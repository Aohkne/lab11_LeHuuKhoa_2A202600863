"""
Assignment 11 — Layer 6: Monitoring & Alerts

What it does: reads the AuditLog (and rate-limiter/judge stats) and computes
rolling metrics — overall block rate, rate-limit hit rate, judge fail rate —
then fires an alert whenever a metric crosses a configured threshold.

Why it's needed: every other layer decides "block this one request or not."
None of them can see the aggregate picture. A sudden spike in block rate is
itself a signal (e.g. "someone is running an automated attack sweep right
now") that no single-request layer would ever notice, because from each
layer's point of view every request is independent.
"""
from dataclasses import dataclass


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


class MonitoringAlert:
    """Threshold-based monitor over an AuditLog.

    Usage:
        monitor = MonitoringAlert(audit_log, rate_limit_plugin=..., judge_stats=...)
        alerts = monitor.check_metrics()
        for a in alerts: print(a.message)
    """

    def __init__(
        self,
        audit_log,
        block_rate_threshold: float = 0.20,
        rate_limit_threshold: float = 0.15,
        judge_fail_rate_threshold: float = 0.10,
    ):
        self.audit_log = audit_log
        self.block_rate_threshold = block_rate_threshold
        self.rate_limit_threshold = rate_limit_threshold
        self.judge_fail_rate_threshold = judge_fail_rate_threshold
        self.judge_total = 0
        self.judge_failed = 0

    def record_judge_result(self, verdict: str):
        """Feed each LLM-as-Judge verdict in so judge_fail_rate can be tracked."""
        self.judge_total += 1
        if verdict.upper() == "FAIL":
            self.judge_failed += 1

    def metrics(self) -> dict:
        total = len(self.audit_log.entries)
        by_layer = self.audit_log.blocked_by_layer()
        rate_limit_hits = by_layer.get("rate_limiter", 0)

        return {
            "total_requests": total,
            "block_rate": self.audit_log.block_rate(),
            "blocked_by_layer": by_layer,
            "rate_limit_hit_rate": (rate_limit_hits / total) if total else 0.0,
            "judge_fail_rate": (self.judge_failed / self.judge_total) if self.judge_total else 0.0,
        }

    def check_metrics(self) -> list[Alert]:
        """Compute metrics and return a list of Alerts for thresholds that were exceeded."""
        m = self.metrics()
        alerts = []

        if m["block_rate"] > self.block_rate_threshold:
            alerts.append(Alert(
                metric="block_rate", value=m["block_rate"], threshold=self.block_rate_threshold,
                message=f"ALERT: block_rate={m['block_rate']:.0%} exceeds threshold "
                        f"{self.block_rate_threshold:.0%} — possible attack in progress.",
            ))

        if m["rate_limit_hit_rate"] > self.rate_limit_threshold:
            alerts.append(Alert(
                metric="rate_limit_hit_rate", value=m["rate_limit_hit_rate"], threshold=self.rate_limit_threshold,
                message=f"ALERT: rate_limit_hit_rate={m['rate_limit_hit_rate']:.0%} exceeds threshold "
                        f"{self.rate_limit_threshold:.0%} — possible volumetric abuse.",
            ))

        if m["judge_fail_rate"] > self.judge_fail_rate_threshold:
            alerts.append(Alert(
                metric="judge_fail_rate", value=m["judge_fail_rate"], threshold=self.judge_fail_rate_threshold,
                message=f"ALERT: judge_fail_rate={m['judge_fail_rate']:.0%} exceeds threshold "
                        f"{self.judge_fail_rate_threshold:.0%} — model may be leaking/hallucinating more than usual.",
            ))

        return alerts

    def print_report(self):
        m = self.metrics()
        print("=" * 60)
        print("MONITORING REPORT")
        print("=" * 60)
        print(f"  Total requests:      {m['total_requests']}")
        print(f"  Block rate:          {m['block_rate']:.0%}")
        print(f"  Blocked by layer:    {m['blocked_by_layer']}")
        print(f"  Rate-limit hit rate: {m['rate_limit_hit_rate']:.0%}")
        print(f"  Judge fail rate:     {m['judge_fail_rate']:.0%}")

        alerts = self.check_metrics()
        if alerts:
            print("\n  ALERTS FIRED:")
            for a in alerts:
                print(f"    - {a.message}")
        else:
            print("\n  No alerts — all metrics within threshold.")
        print("=" * 60)


# ============================================================
# Quick tests
# ============================================================

def test_monitoring():
    """Feed a synthetic audit log with a high block rate and confirm alerts fire."""
    from pipeline.audit_log import AuditLog

    audit = AuditLog()
    # 10 requests, 3 blocked -> 30% block rate, above the 20% default threshold.
    scenarios = [
        (None, None), (None, None), (None, None), (None, None), (None, None),
        (None, None), (None, None),
        ("input_guardrail", "injection"),
        ("input_guardrail", "injection"),
        ("rate_limiter", "too many requests"),
    ]
    for blocked_by, reason in scenarios:
        start = audit.start_timer()
        audit.record("user_1", "x", "y", blocked_by, reason, start)

    monitor = MonitoringAlert(audit)
    monitor.record_judge_result("PASS")
    monitor.record_judge_result("FAIL")  # 1/2 = 50% fail rate -> above 10% threshold

    print("Testing MonitoringAlert:")
    monitor.print_report()

    alerts = monitor.check_metrics()
    fired_metrics = {a.metric for a in alerts}
    assert "block_rate" in fired_metrics, "expected block_rate alert to fire at 30%"
    assert "judge_fail_rate" in fired_metrics, "expected judge_fail_rate alert to fire at 50%"
    print("\nPASS: alerts fire correctly when thresholds are exceeded.")


if __name__ == "__main__":
    test_monitoring()
