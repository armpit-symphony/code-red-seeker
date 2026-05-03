"""HTTP helpers for baseline and diffing."""

from __future__ import annotations


def response_differs(baseline, resp, min_delta: int = 50) -> bool:
    if not baseline:
        return True
    if baseline.status_code != resp.status_code:
        return True
    try:
        return abs(len(baseline.text) - len(resp.text)) > min_delta
    except Exception:
        return True
