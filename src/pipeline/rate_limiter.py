"""
Assignment 11 — Layer 1: Rate Limiter

What it does: blocks a user once they exceed `max_requests` calls inside a
sliding `window_seconds` window, using a per-user deque of timestamps.

Why it's needed: it is the only layer that catches *volume* abuse (brute-force
probing, scripted attack sweeps, cost-exhaustion) — regex/topic/LLM layers
downstream only ever look at a single request in isolation and would happily
evaluate request #10,000 exactly like request #1.
"""
import time
from collections import defaultdict, deque


class RateLimiter:
    """Sliding-window, per-user request limiter (pure Python, no framework).

    A deque of timestamps is kept per user. On each call, timestamps older
    than `window_seconds` are dropped from the left, then the remaining
    length is compared against `max_requests`.
    """

    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque] = defaultdict(deque)

    def check(self, user_id: str, now: float = None) -> dict:
        """Check whether `user_id` may send another request right now.

        Args:
            user_id: Identifier for the caller (session id, IP, account id...)
            now: Injectable clock for deterministic testing. Defaults to time.time().

        Returns:
            dict with:
              allowed (bool): True if the request may proceed
              retry_after (float): seconds until the oldest request expires (0 if allowed)
              requests_in_window (int): count *before* this request is recorded
        """
        now = time.time() if now is None else now
        window = self.user_windows[user_id]

        # Drop expired timestamps from the front of the window.
        while window and (now - window[0]) > self.window_seconds:
            window.popleft()

        requests_in_window = len(window)

        if requests_in_window >= self.max_requests:
            retry_after = self.window_seconds - (now - window[0])
            return {
                "allowed": False,
                "retry_after": max(0.0, round(retry_after, 2)),
                "requests_in_window": requests_in_window,
            }

        window.append(now)
        return {
            "allowed": True,
            "retry_after": 0.0,
            "requests_in_window": requests_in_window,
        }

    def reset(self, user_id: str = None):
        """Clear rate-limit history for one user, or everyone if user_id is None."""
        if user_id is None:
            self.user_windows.clear()
        else:
            self.user_windows.pop(user_id, None)


# ============================================================
# ADK plugin wrapper — same logic, exposed through the
# on_user_message_callback hook so it can be dropped into the
# same `plugins=[...]` list as InputGuardrailPlugin / OutputGuardrailPlugin.
# Because ADK plugins run in registration order with early-exit on the
# first non-None return, this plugin MUST be registered first so abusive
# users never even reach the regex/LLM layers.
# ============================================================

try:
    from google.genai import types
    from google.adk.plugins import base_plugin

    class RateLimitPlugin(base_plugin.BasePlugin):
        """ADK plugin form of RateLimiter — blocks before any LLM call is made."""

        def __init__(self, max_requests: int = 10, window_seconds: float = 60.0):
            super().__init__(name="rate_limiter")
            self.limiter = RateLimiter(max_requests, window_seconds)
            self.blocked_count = 0
            self.total_count = 0

        async def on_user_message_callback(self, *, invocation_context, user_message):
            self.total_count += 1
            user_id = getattr(invocation_context, "user_id", None) or "anonymous"
            result = self.limiter.check(user_id)

            if not result["allowed"]:
                self.blocked_count += 1
                return types.Content(
                    role="model",
                    parts=[types.Part.from_text(
                        text=f"BLOCKED: Too many requests. Please wait "
                             f"{result['retry_after']:.0f}s before trying again."
                    )],
                )
            return None

except ImportError:
    # google-adk not installed in this environment — pure-Python
    # RateLimiter above still works standalone for the DefensePipeline.
    RateLimitPlugin = None


# ============================================================
# Quick tests
# ============================================================

def test_rate_limiter():
    """Send 15 rapid requests from the same user: first 10 pass, last 5 blocked."""
    limiter = RateLimiter(max_requests=10, window_seconds=60)
    fixed_now = 1_000_000.0

    print("Testing RateLimiter (15 requests, limit=10/60s):")
    results = []
    for i in range(1, 16):
        # All 15 requests happen "at once" (same fixed_now) to simulate a burst.
        result = limiter.check("user_1", now=fixed_now)
        results.append(result["allowed"])
        status = "PASS" if result["allowed"] else "BLOCKED"
        extra = "" if result["allowed"] else f" (retry_after={result['retry_after']}s)"
        print(f"  Request #{i:2d}: {status}{extra}")

    passed = sum(results)
    blocked = len(results) - passed
    print(f"\nSummary: {passed} passed / {blocked} blocked (expected 10 passed / 5 blocked)")
    assert passed == 10 and blocked == 5, "Rate limiter did not match expected 10/5 split"
    print("PASS: rate limiter matches spec.")


if __name__ == "__main__":
    test_rate_limiter()
