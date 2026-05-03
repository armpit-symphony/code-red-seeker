"""Simple request budgeting and throttling."""

from __future__ import annotations

import os
import threading
import time


class RequestBudget:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._reset()

    def _reset(self) -> None:
        self._window_start = time.time()
        self._count = 0

    def allow(self, n: int = 1) -> bool:
        with self._lock:
            now = time.time()
            if now - self._window_start >= self.window_seconds:
                self._reset()
            if self._count + n > self.max_requests:
                return False
            self._count += n
            return True

    def wait_for_budget(self, n: int = 1, poll_seconds: float = 0.25) -> None:
        while not self.allow(n):
            time.sleep(poll_seconds)


def from_env() -> "RequestBudget":
    max_per_minute = int(os.getenv("BUDGET_MAX_PER_MINUTE", "120"))
    return RequestBudget(max_per_minute, 60)
