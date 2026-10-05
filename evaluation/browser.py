"""Fail-closed result boundary for operator-owned isolated browser executors."""

import time


BROWSER_MODES = {"page", "page_request", "browser", "browser_request"}
TRANSPORT_COUNTERS = {
    "completed", "refused", "upstream_error", "request_limit", "response_limit",
    "deadline", "client_disconnect", "handler_error",
}


def run_browser_case(executor, attempt, suite, case, target, timeout):
    """The trusted executor owns bounds, guards, both relay hops and cleanup.

    This boundary cannot terminate arbitrary callbacks. Executors must enforce
    the supplied total timeout independently, including resource preparation.
    No raw browser output, exception text or journey return value enters evidence.
    """
    result = {"case_id": case["id"], "verdict": "inconclusive"}
    if executor is None:
        return dict(result, reason="browser_executor_unavailable")
    started = time.monotonic()
    try:
        value = executor(attempt, suite, dict(case), dict(target), timeout_seconds=timeout)
    except Exception:
        return dict(result, reason="browser_executor_error", abort_suite=True)
    if not isinstance(value, dict) or value.get("case_id") != case["id"]:
        return dict(result, reason="browser_result_invalid", abort_suite=True)
    # An executor may not claim observations after losing its containment guard,
    # nor allow following cases when cleanup/restoration is uncertain.
    if value.get("cleanup_verified") is not True or value.get("guard_verified") is not True:
        return dict(result, reason="browser_lifetime_uncertain", abort_suite=True)
    if type(value.get("abort_suite", False)) is not bool:
        return dict(result, reason="browser_result_invalid", abort_suite=True)
    if value.get("abort_suite", False):
        return dict(result, reason="browser_state_uncertain", abort_suite=True)
    if time.monotonic() - started > timeout:
        return dict(result, reason="browser_deadline_exceeded")
    # Both the private Unix->TCP hop and browser loopback->Unix hop must report.
    hops = value.get("transport")
    if not isinstance(hops, dict) or set(hops) != {"browser", "upstream"}:
        return dict(result, reason="browser_transport_unverified")
    for counters in hops.values():
        if (not isinstance(counters, dict) or not set(counters) <= TRANSPORT_COUNTERS
                or any(type(count) is not int or count < 0 for count in counters.values())
                or counters.get("completed", 0) <= 0
                or any(count for name, count in counters.items() if name != "completed")):
            return dict(result, reason="browser_transport_unverified")
    verdict = value.get("verdict")
    if verdict not in ("pass", "fail", "inconclusive", "untested"):
        return dict(result, reason="browser_result_invalid", abort_suite=True)
    return dict(result, verdict=verdict, reason="browser_" + verdict)
