"""TDD: a DB-backed rate limiter so lockout state is shared across worker
processes and survives a restart (the in-memory limiter loses both)."""
from augur.auth.store import connect
from augur.auth.ratelimit import SqliteRateLimiter


def test_lockout_after_max_failures(tmp_path):
    conn = connect(str(tmp_path / "rl.db"))
    rl = SqliteRateLimiter(conn, max_failures=3, window_seconds=900, lockout_seconds=900)
    for _ in range(3):
        assert rl.is_locked("alice") is False
        rl.record_failure("alice")
    assert rl.is_locked("alice") is True


def test_reset_clears_lock(tmp_path):
    conn = connect(str(tmp_path / "rl.db"))
    rl = SqliteRateLimiter(conn, max_failures=2, window_seconds=900, lockout_seconds=900)
    rl.record_failure("bob"); rl.record_failure("bob")
    assert rl.is_locked("bob") is True
    rl.reset("bob")
    assert rl.is_locked("bob") is False


def test_lock_persists_across_instances_same_db(tmp_path):
    # Simulates a second uvicorn worker / a process restart: a fresh limiter on
    # the same DB file must see the lockout the first one recorded.
    db = str(tmp_path / "shared.db")
    rl1 = SqliteRateLimiter(connect(db), max_failures=3, window_seconds=900, lockout_seconds=900)
    for _ in range(3):
        rl1.record_failure("admin")
    assert rl1.is_locked("admin") is True

    rl2 = SqliteRateLimiter(connect(db), max_failures=3, window_seconds=900, lockout_seconds=900)
    assert rl2.is_locked("admin") is True


def test_expired_lock_auto_clears(tmp_path):
    conn = connect(str(tmp_path / "rl.db"))
    # lockout_seconds=0 → the lock is already expired the instant it is set.
    rl = SqliteRateLimiter(conn, max_failures=1, window_seconds=900, lockout_seconds=0)
    rl.record_failure("carol")
    assert rl.is_locked("carol") is False
