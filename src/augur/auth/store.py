import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROLES = ("viewer", "analyst", "admin")
_RANK = {"viewer": 0, "analyst": 1, "admin": 2}

# Bump when the schema changes; init_db stamps PRAGMA user_version and refuses to
# open a DB written by a newer schema (prevents a rolled-back binary corrupting it).
SCHEMA_VERSION = 1


def role_rank(role: str) -> int:
    return _RANK[role]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@dataclass
class User:
    id: int
    username: str
    role: str
    disabled: bool
    created_at: str
    updated_at: str
    password_hash: str = ""


@dataclass
class Session:
    id: str
    user_id: int
    csrf_token: str
    created_at: str
    last_seen: str
    expires_at: str


def _new_real_conn(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    init_db(conn)
    return conn


class _ThreadLocalConnection:
    """Proxy presenting a stable object whose DB ops bind to a per-thread sqlite3.Connection on
    the same WAL file. Lets FastAPI's threadpool workers each use their own connection while every
    store keeps `self.conn = <proxy>` unchanged. Fixes concurrent-use-of-one-connection errors."""

    def __init__(self, db_path: str) -> None:
        object.__setattr__(self, "_db_path", db_path)
        object.__setattr__(self, "_local", threading.local())

    def _conn(self) -> sqlite3.Connection:
        local = object.__getattribute__(self, "_local")
        c = getattr(local, "conn", None)
        if c is None:
            c = _new_real_conn(object.__getattribute__(self, "_db_path"))
            local.conn = c
        return c

    def __getattr__(self, name):                 # execute, executescript, executemany, commit,
        return getattr(self._conn(), name)        # cursor, rollback, close, interrupt, ...

    def __setattr__(self, name, value):           # e.g. row_factory = sqlite3.Row
        setattr(self._conn(), name, value)

    def __enter__(self):                          # `with conn:` -> real per-thread txn
        return self._conn().__enter__()

    def __exit__(self, *exc):
        return self._conn().__exit__(*exc)


def connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    proxy = _ThreadLocalConnection(db_path)
    proxy._conn()       # eagerly materialize the main-thread connection (+ schema) before workers start
    return proxy


def init_db(conn: sqlite3.Connection) -> None:
    on_disk = conn.execute("PRAGMA user_version").fetchone()[0]
    if on_disk > SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {on_disk} is newer than this build supports "
            f"({SCHEMA_VERSION}); upgrade Augur or restore a compatible backup."
        )
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
          disabled INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(
          id TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          csrf_token TEXT NOT NULL,
          created_at TEXT NOT NULL,
          last_seen TEXT NOT NULL,
          expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT NOT NULL, username TEXT, event TEXT NOT NULL, ip TEXT, detail TEXT
        );
        CREATE TABLE IF NOT EXISTS auth_ratelimit(
          key TEXT PRIMARY KEY,
          fails TEXT NOT NULL DEFAULT '[]',   -- JSON list of failure epoch seconds
          locked_until REAL                   -- epoch seconds; NULL when not locked
        );
        """
    )
    # Stamp the schema version (a no-op on an already-current DB; future bumps add
    # ordered migration steps here before re-stamping).
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()


def _user(row: sqlite3.Row) -> User:
    return User(id=row["id"], username=row["username"], role=row["role"],
                disabled=bool(row["disabled"]), created_at=row["created_at"],
                updated_at=row["updated_at"], password_hash=row["password_hash"])


class UserStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def is_empty(self) -> bool:
        return self.conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0

    def create_user(self, username: str, password_hash: str, role: str) -> int:
        if role not in ROLES:
            raise ValueError(f"invalid role {role!r}")
        now = _iso(_now())
        cur = self.conn.execute(
            "INSERT INTO users(username,password_hash,role,disabled,created_at,updated_at)"
            " VALUES(?,?,?,0,?,?)", (username, password_hash, role, now, now))
        self.conn.commit()
        return cur.lastrowid

    def get_by_username(self, username: str) -> User | None:
        r = self.conn.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE",
                              (username,)).fetchone()
        return _user(r) if r else None

    def get_by_id(self, uid: int) -> User | None:
        r = self.conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return _user(r) if r else None

    def list_users(self) -> list[User]:
        return [_user(r) for r in self.conn.execute("SELECT * FROM users ORDER BY id").fetchall()]

    def update_user(self, uid: int, *, role: str | None = None, disabled: bool | None = None) -> None:
        sets, args = [], []
        if role is not None:
            if role not in ROLES:
                raise ValueError(f"invalid role {role!r}")
            sets.append("role=?"); args.append(role)
        if disabled is not None:
            sets.append("disabled=?"); args.append(1 if disabled else 0)
        if not sets:
            return
        sets.append("updated_at=?"); args.append(_iso(_now()))
        args.append(uid)
        self.conn.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", args)
        self.conn.commit()

    def set_password(self, uid: int, password_hash: str) -> None:
        self.conn.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
                          (password_hash, _iso(_now()), uid))
        self.conn.commit()

    def delete_user(self, uid: int) -> None:
        self.conn.execute("DELETE FROM users WHERE id=?", (uid,))
        self.conn.commit()

    def count_admins(self) -> int:
        # only ENABLED admins count toward the last-admin guard — a disabled admin
        # cannot authenticate and is not a usable recovery path.
        return self.conn.execute(
            "SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0").fetchone()["c"]


class SessionStore:
    def __init__(self, conn: sqlite3.Connection,
                 idle_seconds: int = 12 * 3600, max_seconds: int = 7 * 24 * 3600) -> None:
        self.conn = conn
        self.idle = idle_seconds
        self.max = max_seconds

    def create_session(self, user_id: int) -> Session:
        now = _now()
        s = Session(id=secrets.token_urlsafe(32), user_id=user_id,
                    csrf_token=secrets.token_urlsafe(32), created_at=_iso(now),
                    last_seen=_iso(now), expires_at=_iso(now + timedelta(seconds=self.idle)))
        self.conn.execute(
            "INSERT INTO sessions(id,user_id,csrf_token,created_at,last_seen,expires_at)"
            " VALUES(?,?,?,?,?,?)",
            (s.id, s.user_id, s.csrf_token, s.created_at, s.last_seen, s.expires_at))
        self.conn.commit()
        return s

    def get(self, sid: str) -> Session | None:
        r = self.conn.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not r:
            return None
        return Session(id=r["id"], user_id=r["user_id"], csrf_token=r["csrf_token"],
                       created_at=r["created_at"], last_seen=r["last_seen"], expires_at=r["expires_at"])

    def is_valid(self, s: Session) -> bool:
        now = _now()
        exp = datetime.fromisoformat(s.expires_at)
        created = datetime.fromisoformat(s.created_at)
        return now <= exp and now <= created + timedelta(seconds=self.max)

    def touch(self, sid: str) -> None:
        now = _now()
        self.conn.execute("UPDATE sessions SET last_seen=?, expires_at=? WHERE id=?",
                          (_iso(now), _iso(now + timedelta(seconds=self.idle)), sid))
        self.conn.commit()

    def delete(self, sid: str) -> None:
        self.conn.execute("DELETE FROM sessions WHERE id=?", (sid,))
        self.conn.commit()

    def delete_user_sessions(self, user_id: int) -> None:
        self.conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        self.conn.commit()

    def list_for_user(self, user_id: int) -> list["Session"]:
        """Return all sessions for a user, newest first (by created_at DESC)."""
        rows = self.conn.execute(
            "SELECT * FROM sessions WHERE user_id=? ORDER BY created_at DESC", (user_id,)
        ).fetchall()
        return [Session(id=r["id"], user_id=r["user_id"], csrf_token=r["csrf_token"],
                        created_at=r["created_at"], last_seen=r["last_seen"],
                        expires_at=r["expires_at"]) for r in rows]

    def prune_expired(self, now_iso: str) -> int:
        """Delete sessions whose expires_at < now_iso. Returns rows deleted."""
        cur = self.conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?", (now_iso,)
        )
        self.conn.commit()
        return cur.rowcount


class AuthEvents:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def log(self, event: str, *, username: str | None = None, ip: str | None = None,
            detail: str | None = None) -> None:
        self.conn.execute("INSERT INTO auth_events(ts,username,event,ip,detail) VALUES(?,?,?,?,?)",
                          (_iso(_now()), username, event, ip, detail))
        self.conn.commit()

    def recent(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM auth_events ORDER BY id DESC LIMIT ?",
                                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def prune(self, before_iso: str) -> int:
        """Delete auth_events with ts < before_iso. Returns rows deleted."""
        cur = self.conn.execute(
            "DELETE FROM auth_events WHERE ts < ?", (before_iso,)
        )
        self.conn.commit()
        return cur.rowcount
