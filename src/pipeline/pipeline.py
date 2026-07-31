"""
Assignment 11 — Full Defense-in-Depth Pipeline

Chains all 6 required layers, plus a bonus 7th layer, in order:

    Rate Limiter -> Input Guardrails -> Session Anomaly Detector (bonus)
    -> LLM -> Output Guardrails -> LLM-as-Judge (multi-criteria)
    -> Audit Log -> Monitoring & Alerts

Built as plain Python (the "Pure Python pipeline" option from the assignment
appendix) rather than as ADK plugins, because ADK's PluginManager runs
after_model_callback with early-exit on the first non-None return (see
plugin_manager.py:_run_callbacks) — chaining PII-redaction, the judge, and
audit logging as three separate after_model_callback plugins would mean only
the first one ever executes. Orchestrating them explicitly here keeps every
layer's ordering and audit trail unambiguous.
"""
import re

from core.utils import chat_with_agent
from guardrails.input_guardrails import detect_injection, topic_filter
from guardrails.output_guardrails import content_filter
from pipeline.rate_limiter import RateLimiter
from pipeline.session_anomaly import SessionAnomalyDetector
from pipeline import llm_judge
from pipeline.audit_log import AuditLog
from pipeline.monitoring import MonitoringAlert

# Defense-in-depth against wasting an LLM call on abusive input sizes.
# 2000 chars comfortably covers any real banking question; anything longer
# is either abuse or a copy-paste accident, and gets blocked before the LLM.
MAX_INPUT_CHARS = 2000


class DefensePipeline:
    """End-to-end guarded chat pipeline for the VinBank assistant."""

    def __init__(
        self,
        agent,
        runner,
        rate_limiter: RateLimiter = None,
        session_anomaly_detector: SessionAnomalyDetector = None,
        use_llm_judge: bool = True,
    ):
        self.agent = agent
        self.runner = runner
        self.rate_limiter = rate_limiter or RateLimiter(max_requests=10, window_seconds=60)
        self.session_anomaly_detector = session_anomaly_detector or SessionAnomalyDetector()
        self.use_llm_judge = use_llm_judge
        self.audit_log = AuditLog()
        self.monitor = MonitoringAlert(self.audit_log)

    async def process(self, user_input: str, user_id: str = "default") -> dict:
        """Run one message through every layer.

        Returns:
            dict: {response, blocked_by, blocked_reason, latency_ms, judge}
        """
        start = self.audit_log.start_timer()

        def finish(response, blocked_by=None, blocked_reason=None, judge=None):
            entry = self.audit_log.record(
                user_id, user_input, response, blocked_by, blocked_reason, start
            )
            return {
                "response": response,
                "blocked_by": blocked_by,
                "blocked_reason": blocked_reason,
                "latency_ms": entry.latency_ms,
                "judge": judge,
            }

        # --- Layer 1: Rate Limiter ---
        rl_result = self.rate_limiter.check(user_id)
        if not rl_result["allowed"]:
            return finish(
                f"BLOCKED: Too many requests. Please wait {rl_result['retry_after']:.0f}s.",
                blocked_by="rate_limiter",
                blocked_reason=f"{rl_result['requests_in_window']} requests in window",
            )

        # --- Layer 2: Input Guardrails ---
        if not user_input or not user_input.strip():
            return finish(
                "BLOCKED: Empty input is not a valid request.",
                blocked_by="input_guardrail",
                blocked_reason="empty_input",
            )

        if len(user_input) > MAX_INPUT_CHARS:
            return finish(
                "BLOCKED: Input exceeds the maximum allowed length.",
                blocked_by="input_guardrail",
                blocked_reason=f"input_too_long ({len(user_input)} chars > {MAX_INPUT_CHARS})",
            )

        if detect_injection(user_input):
            return finish(
                "BLOCKED: I can't help with that request. I can only assist with "
                "VinBank banking questions.",
                blocked_by="input_guardrail",
                blocked_reason="injection_pattern_matched",
            )

        if topic_filter(user_input):
            return finish(
                "BLOCKED: I'm a VinBank assistant and can only help with "
                "banking-related questions (accounts, transactions, loans, savings, cards).",
                blocked_by="input_guardrail",
                blocked_reason="off_topic_or_blocked_topic",
            )

        # --- Bonus Layer: Session Anomaly Detector ---
        # Runs even though this single message just passed input guardrails —
        # it's evaluating the user's session history, not this message alone.
        anomaly = self.session_anomaly_detector.check(user_id, user_input)
        if anomaly["flagged"]:
            return finish(
                "BLOCKED: This session has been flagged for unusual activity. "
                "Please contact VinBank support directly for further assistance.",
                blocked_by="session_anomaly_detector",
                blocked_reason=anomaly["reason"],
            )

        # --- LLM call ---
        raw_response, _ = await chat_with_agent(self.agent, self.runner, user_input)

        # --- Layer 3: Output Guardrails (PII/secret redaction) ---
        redaction = content_filter(raw_response)
        response = redaction["redacted"]

        # --- Layer 4: LLM-as-Judge (multi-criteria) ---
        judge_result = None
        if self.use_llm_judge:
            judge_result = await llm_judge.judge_response(response)
            self.monitor.record_judge_result(judge_result["verdict"])
            if judge_result["verdict"] == "FAIL":
                return finish(
                    "I cannot provide that information. Please contact VinBank "
                    "support for further assistance.",
                    blocked_by="llm_judge",
                    blocked_reason=judge_result["reason"],
                    judge=judge_result,
                )

        return finish(response, blocked_by=None, blocked_reason=None, judge=judge_result)
