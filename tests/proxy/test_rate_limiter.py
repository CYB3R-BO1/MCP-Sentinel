from proxy.rate_limiter import SlidingWindowRateLimiter


def test_allows_calls_under_the_limit():
    clock = _FakeClock(start=0.0)
    limiter = SlidingWindowRateLimiter(clock=clock)
    for _ in range(5):
        assert limiter.allow("read_file", max_calls=5, window_seconds=60.0) is True


def test_denies_calls_over_the_limit_within_the_window():
    clock = _FakeClock(start=0.0)
    limiter = SlidingWindowRateLimiter(clock=clock)
    for _ in range(3):
        assert limiter.allow("read_file", max_calls=3, window_seconds=60.0) is True
    assert limiter.allow("read_file", max_calls=3, window_seconds=60.0) is False


def test_old_calls_fall_out_of_the_window():
    clock = _FakeClock(start=0.0)
    limiter = SlidingWindowRateLimiter(clock=clock)
    for _ in range(3):
        assert limiter.allow("read_file", max_calls=3, window_seconds=60.0) is True
    assert limiter.allow("read_file", max_calls=3, window_seconds=60.0) is False

    clock.advance(61.0)
    assert limiter.allow("read_file", max_calls=3, window_seconds=60.0) is True


def test_limits_are_tracked_independently_per_key():
    clock = _FakeClock(start=0.0)
    limiter = SlidingWindowRateLimiter(clock=clock)
    for _ in range(2):
        assert limiter.allow("read_file", max_calls=2, window_seconds=60.0) is True
    assert limiter.allow("read_file", max_calls=2, window_seconds=60.0) is False
    assert limiter.allow("fetch_url", max_calls=2, window_seconds=60.0) is True


class _FakeClock:
    def __init__(self, start: float = 0.0):
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds
