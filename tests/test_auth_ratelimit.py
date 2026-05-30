from augur.auth.ratelimit import RateLimiter


def test_locks_out_after_max_failures():
    rl = RateLimiter(max_failures=3, window_seconds=900, lockout_seconds=900)
    for _ in range(3):
        assert rl.is_locked("alice") is False
        rl.record_failure("alice")
    assert rl.is_locked("alice") is True


def test_success_resets():
    rl = RateLimiter(max_failures=3, window_seconds=900, lockout_seconds=900)
    rl.record_failure("bob"); rl.record_failure("bob")
    rl.reset("bob")
    assert rl.is_locked("bob") is False
