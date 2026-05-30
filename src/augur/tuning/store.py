"""SQLite store for FP-tuning allowlist entries.

Mirrors `HuntStore`/`AlertStore`: shared per-thread connection, `_init_*_db` on construct,
`token_hex(8)` ids, an events table for the audit trail. Empty-string sentinels for nullable
predicate columns (the loader maps ``''`` -> ``None``).

Wall-clock lives ONLY here (created/updated stamping + expiry filtering). The pure matcher in
``apply.py`` never imports this module and never sees ``expires_at``; ``active_entries`` resolves
expiry at the store boundary so the matcher stays a pure function of (detections, active entries).
"""
import secrets
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone

ACTIONS = ("SUPPRESS", "DOWNGRADE")
DOWNGRADE_BANDS = ("WATCH", "HIGH")
EVENTS = ("created", "edited", "enabled", "disabled", "deleted", "proposed")

# Predicate columns that carry an empty-string sentinel meaning "no constraint".
_PREDICATE_COLS = ("scenario_id", "technique", "host", "zone",
                   "process_regex", "command_regex", "image_regex", "ts_from", "ts_to")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AllowlistEntry:
    action: str                       # SUPPRESS | DOWNGRADE
    reason: str
    author: str
    id: str = ""
    downgrade_to: str | None = None   # WATCH | HIGH (required iff action == DOWNGRADE)
    scenario_id: str | None = None
    technique: str | None = None
    host: str | None = None
    zone: str | None = None
    process_regex: str | None = None
    command_regex: str | None = None
    image_regex: str | None = None
    ts_from: str | None = None
    ts_to: str | None = None
    enabled: bool = True
    expires_at: str | None = None
    source: str = "manual"            # manual | proposed
    source_alert_id: str | None = None
    created_at: str = ""
    updated_at: str = ""

    def predicates(self) -> dict:
        """The active (non-None) predicate fields — used by the matcher and the >=1 validation."""
        return {c: getattr(self, c) for c in _PREDICATE_COLS if getattr(self, c)}


@dataclass
class AllowlistEvent:
    entry_id: str
    ts: str
    actor: str
    event: str
    detail: str = ""
    id: int = 0


def _init_tuning_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS allowlist_entries(
          id TEXT PRIMARY KEY,
          action TEXT NOT NULL,
          downgrade_to TEXT NOT NULL DEFAULT '',
          scenario_id TEXT NOT NULL DEFAULT '',
          technique TEXT NOT NULL DEFAULT '',
          host TEXT NOT NULL DEFAULT '',
          zone TEXT NOT NULL DEFAULT '',
          process_regex TEXT NOT NULL DEFAULT '',
          command_regex TEXT NOT NULL DEFAULT '',
          image_regex TEXT NOT NULL DEFAULT '',
          ts_from TEXT NOT NULL DEFAULT '',
          ts_to TEXT NOT NULL DEFAULT '',
          reason TEXT NOT NULL,
          author TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          expires_at TEXT NOT NULL DEFAULT '',
          source TEXT NOT NULL DEFAULT 'manual',
          source_alert_id TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_allow_enabled ON allowlist_entries(enabled);
        CREATE INDEX IF NOT EXISTS idx_allow_scenario ON allowlist_entries(scenario_id);
        CREATE TABLE IF NOT EXISTS allowlist_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          entry_id TEXT NOT NULL,
          ts TEXT NOT NULL,
          actor TEXT NOT NULL,
          event TEXT NOT NULL,
          detail TEXT NOT NULL DEFAULT ''
        );
        """
    )
    conn.commit()


def _s(v: str | None) -> str:
    """Map None -> '' for storage."""
    return v if v else ""


def _n(v: str) -> str | None:
    """Map '' -> None on load."""
    return v or None


def _row_to_entry(row: sqlite3.Row) -> AllowlistEntry:
    return AllowlistEntry(
        id=row["id"], action=row["action"], downgrade_to=_n(row["downgrade_to"]),
        scenario_id=_n(row["scenario_id"]), technique=_n(row["technique"]),
        host=_n(row["host"]), zone=_n(row["zone"]),
        process_regex=_n(row["process_regex"]), command_regex=_n(row["command_regex"]),
        image_regex=_n(row["image_regex"]), ts_from=_n(row["ts_from"]), ts_to=_n(row["ts_to"]),
        reason=row["reason"], author=row["author"], enabled=bool(row["enabled"]),
        expires_at=_n(row["expires_at"]), source=row["source"],
        source_alert_id=_n(row["source_alert_id"]),
        created_at=row["created_at"], updated_at=row["updated_at"],
    )


class AllowlistStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        _init_tuning_db(conn)

    def create(self, e: AllowlistEntry) -> str:
        eid = e.id or secrets.token_hex(8)
        now = _now()
        self.conn.execute(
            "INSERT INTO allowlist_entries(id,action,downgrade_to,scenario_id,technique,host,zone,"
            "process_regex,command_regex,image_regex,ts_from,ts_to,reason,author,enabled,expires_at,"
            "source,source_alert_id,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, e.action, _s(e.downgrade_to), _s(e.scenario_id), _s(e.technique), _s(e.host),
             _s(e.zone), _s(e.process_regex), _s(e.command_regex), _s(e.image_regex),
             _s(e.ts_from), _s(e.ts_to), e.reason, e.author, 1 if e.enabled else 0,
             _s(e.expires_at), e.source, _s(e.source_alert_id), now, now),
        )
        self.conn.commit()
        self.add_event(AllowlistEvent(entry_id=eid, ts=now, actor=e.author,
                                      event="proposed" if e.source == "proposed" else "created"))
        return eid

    def get(self, eid: str) -> AllowlistEntry | None:
        row = self.conn.execute("SELECT * FROM allowlist_entries WHERE id=?", (eid,)).fetchone()
        return _row_to_entry(row) if row else None

    def list(self, *, enabled: bool | None = None) -> list[AllowlistEntry]:
        q = "SELECT * FROM allowlist_entries"
        params: list = []
        if enabled is not None:
            q += " WHERE enabled=?"
            params.append(1 if enabled else 0)
        q += " ORDER BY id"
        return [_row_to_entry(r) for r in self.conn.execute(q, params).fetchall()]

    def active_entries(self, *, now: datetime) -> list[AllowlistEntry]:
        """Enabled, non-expired entries ordered by id (deterministic). Expiry resolved HERE
        (wall-clock at the store boundary), never inside the pure matcher."""
        now_iso = now.isoformat()
        rows = self.conn.execute(
            "SELECT * FROM allowlist_entries WHERE enabled=1 AND (expires_at='' OR expires_at>?) "
            "ORDER BY id", (now_iso,),
        ).fetchall()
        return [_row_to_entry(r) for r in rows]

    def has_active(self, *, now: datetime) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM allowlist_entries WHERE enabled=1 AND (expires_at='' OR expires_at>?) LIMIT 1",
            (now.isoformat(),),
        ).fetchone()
        return row is not None

    def update(self, e: AllowlistEntry, *, actor: str) -> None:
        self.conn.execute(
            "UPDATE allowlist_entries SET action=?,downgrade_to=?,scenario_id=?,technique=?,host=?,"
            "zone=?,process_regex=?,command_regex=?,image_regex=?,ts_from=?,ts_to=?,reason=?,"
            "expires_at=?,updated_at=? WHERE id=?",
            (e.action, _s(e.downgrade_to), _s(e.scenario_id), _s(e.technique), _s(e.host),
             _s(e.zone), _s(e.process_regex), _s(e.command_regex), _s(e.image_regex),
             _s(e.ts_from), _s(e.ts_to), e.reason, _s(e.expires_at), _now(), e.id),
        )
        self.conn.commit()
        self.add_event(AllowlistEvent(entry_id=e.id, ts=_now(), actor=actor, event="edited"))

    def set_enabled(self, eid: str, enabled: bool, *, actor: str) -> None:
        self.conn.execute("UPDATE allowlist_entries SET enabled=?,updated_at=? WHERE id=?",
                          (1 if enabled else 0, _now(), eid))
        self.conn.commit()
        self.add_event(AllowlistEvent(entry_id=eid, ts=_now(), actor=actor,
                                      event="enabled" if enabled else "disabled"))

    def delete(self, eid: str, *, actor: str) -> None:
        self.conn.execute("DELETE FROM allowlist_entries WHERE id=?", (eid,))
        self.conn.commit()
        # Keep the audit trail: log the deletion event AFTER the row is gone (events are not FK-bound).
        self.add_event(AllowlistEvent(entry_id=eid, ts=_now(), actor=actor, event="deleted"))

    def add_event(self, e: AllowlistEvent) -> None:
        self.conn.execute("INSERT INTO allowlist_events(entry_id,ts,actor,event,detail) VALUES(?,?,?,?,?)",
                          (e.entry_id, e.ts, e.actor, e.event, e.detail))
        self.conn.commit()

    def list_events(self, eid: str) -> list[AllowlistEvent]:
        rows = self.conn.execute("SELECT * FROM allowlist_events WHERE entry_id=? ORDER BY id", (eid,)).fetchall()
        return [AllowlistEvent(id=r["id"], entry_id=r["entry_id"], ts=r["ts"], actor=r["actor"],
                               event=r["event"], detail=r["detail"]) for r in rows]
