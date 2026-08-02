"""Per-key sliding-window rate limiter.

Single-process, in-memory -- matches the design doc's non-goal of no
distributed/multi-tenant policy sync. A `deque` of call timestamps per key
is trimmed to the window on every check, so memory is bounded by
(max_calls_per_key) rather than growing unboundedly.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable


class SlidingWindowRateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._calls: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, max_calls: int, window_seconds: float) -> bool:
        now = self._clock()
        timestamps = self._calls[key]
        while timestamps and now - timestamps[0] > window_seconds:
            timestamps.popleft()

        if len(timestamps) >= max_calls:
            return False

        timestamps.append(now)
        return True
