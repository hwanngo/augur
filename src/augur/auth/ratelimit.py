import json
import threading
import time


class SqliteRateLimiter:
    """Per-key failure counter with lockout, persisted in sqlite.

    Unlike the in-process ``RateLimiter``, this shares state across worker
    processes (all pointing at the same WAL DB) and survives a restart, so the
    configured budget isn't multiplied by the worker count or reset on redeploy.
    Uses wall-clock ``time.time()`` (monotonic clocks are per-process and can't
    be shared); the rate-limit windows are minutes-scale so wall-clock is fine.
    """

    def __init__(self, conn, max_failures: int = 5, window_seconds: int = 900,
                 lockout_seconds: int = 900, namespace: str = "") -> None:
        self.conn = conn
        self.max = max_failures
        self.window = window_seconds
        self.lockout = lockout_seconds
        # Prefix so per-username and per-IP limiters sharing one table can't
        # collide (e.g. a username equal to an IP string).
        self._ns = f"{namespace}:" if namespace else ""

    def _key(self, key: str) -> str:
        return f"{self._ns}{key}"

    def is_locked(self, key: str) -> bool:
        k = self._key(key)
        now = time.time()
        row = self.conn.execute(
            "SELECT locked_until FROM auth_ratelimit WHERE key=?", (k,)).fetchone()
        if row is None or row["locked_until"] is None:
            return False
        if now >= row["locked_until"]:
            self._delete(k)        # lock expired → clear it
            return False
        return True

    def record_failure(self, key: str) -> None:
        k = self._key(key)
        now = time.time()
        with self.conn:
            row = self.conn.execute(
                "SELECT fails FROM auth_ratelimit WHERE key=?", (k,)).fetchone()
            fails = [t for t in json.loads(row["fails"]) if now - t < self.window] if row else []
            fails.append(now)
            locked_until = now + self.lockout if len(fails) >= self.max else None
            self.conn.execute(
                "INSERT INTO auth_ratelimit(key, fails, locked_until) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET fails=excluded.fails, locked_until=excluded.locked_until",
                (k, json.dumps(fails), locked_until))

    def reset(self, key: str) -> None:
        self._delete(self._key(key))

    def _delete(self, prefixed_key: str) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM auth_ratelimit WHERE key=?", (prefixed_key,))


class RateLimiter:
    """In-process per-key failure counter with lockout. Single-box use only."""
    def __init__(self, max_failures: int = 5, window_seconds: int = 900,
                 lockout_seconds: int = 900) -> None:
        self.max = max_failures
        self.window = window_seconds
        self.lockout = lockout_seconds
        self._fails: dict[str, list[float]] = {}
        self._locked: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_locked(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            until = self._locked.get(key)
            if until is None:
                return False
            if now >= until:
                del self._locked[key]
                self._fails.pop(key, None)
                return False
            return True

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            xs = [t for t in self._fails.get(key, []) if now - t < self.window]
            xs.append(now)
            self._fails[key] = xs
            if len(xs) >= self.max:
                self._locked[key] = now + self.lockout

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)
            self._locked.pop(key, None)
