import json
import secrets
import sqlite3
from dataclasses import dataclass, field


@dataclass
class Alert:
    dedup_key: str
    scenario_id: str
    scenario_name: str
    severity: str
    affected_hosts: list[str]
    proximity: float
    band: str
    state: str = "open"
    first_seen: str = ""
    last_seen: str = ""
    count: int = 1
    absent_cycles: int = 0
    notified_band: str = ""
    detection_json: str = "{}"
    id: str = ""
    created_at: str = ""
    updated_at: str = ""
    assignee: str = ""
    status: str = "open"
    resolution_note: str = ""
    assigned_at: str = ""
    resolved_at: str = ""


@dataclass
class AlertEvent:
    alert_id: str
    ts: str
    actor: str
    event: str
    detail: str = ""
    id: int = 0


def _init_alerts_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS alerts(
          id TEXT PRIMARY KEY,
          dedup_key TEXT NOT NULL UNIQUE,
          scenario_id TEXT NOT NULL,
          scenario_name TEXT NOT NULL,
          severity TEXT NOT NULL,
          affected_hosts TEXT NOT NULL,
          proximity REAL NOT NULL,
          band TEXT NOT NULL,
          state TEXT NOT NULL DEFAULT 'open',
          first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL,
          count INTEGER NOT NULL DEFAULT 1,
          absent_cycles INTEGER NOT NULL DEFAULT 0,
          notified_band TEXT NOT NULL DEFAULT '',
          detection_json TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          assignee TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'open',
          resolution_note TEXT NOT NULL DEFAULT '',
          assigned_at TEXT NOT NULL DEFAULT '',
          resolved_at TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state);
        -- Deliberately NO `REFERENCES alerts(id) ON DELETE CASCADE` FK (the spec shows one).
        -- connect() enables `PRAGMA foreign_keys=ON`; dropping the FK keeps event insertion
        -- order-independent and avoids FK-violation surprises. apply_evaluation inserts the
        -- alert before its events anyway, so referential integrity holds in practice.
        CREATE TABLE IF NOT EXISTS alert_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          alert_id TEXT NOT NULL,
          ts TEXT NOT NULL,
          actor TEXT NOT NULL,
          event TEXT NOT NULL,
          detail TEXT NOT NULL DEFAULT ''
        );
        """
    )
    conn.commit()
    _migrate_alerts_columns(conn)


_ALERT_NEW_COLUMNS = (
    ("assignee", "TEXT NOT NULL DEFAULT ''"),
    ("status", "TEXT NOT NULL DEFAULT 'open'"),
    ("resolution_note", "TEXT NOT NULL DEFAULT ''"),
    ("assigned_at", "TEXT NOT NULL DEFAULT ''"),
    ("resolved_at", "TEXT NOT NULL DEFAULT ''"),
)

_WORKFLOW_STATUSES = ("open", "acknowledged", "in_progress", "resolved", "closed")


def _migrate_alerts_columns(conn: sqlite3.Connection) -> None:
    """Additive, idempotent migration for the triage columns (safe on a populated DB).

    PRAGMA-guarded so re-running init is a no-op. sqlite `ADD COLUMN` with a constant
    default is O(1) metadata-only.
    """
    existing = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    for name, decl in _ALERT_NEW_COLUMNS:
        if name not in existing:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {decl}")
    # status defaults to 'open' for legacy rows; backfill terminal status from legacy state
    # so a pre-existing 'resolved' alert reads as resolved in the new workflow too.
    conn.execute(
        "UPDATE alerts SET status='resolved', resolved_at=updated_at "
        "WHERE status='open' AND state='resolved' AND resolved_at=''"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_assignee ON alerts(assignee)")
    conn.commit()


_ALERT_COLS = ("id", "dedup_key", "scenario_id", "scenario_name", "severity", "affected_hosts",
               "proximity", "band", "state", "first_seen", "last_seen", "count", "absent_cycles",
               "notified_band", "detection_json", "created_at", "updated_at",
               "assignee", "status", "resolution_note", "assigned_at", "resolved_at")


def _row_to_alert(row: sqlite3.Row) -> Alert:
    return Alert(
        id=row["id"], dedup_key=row["dedup_key"], scenario_id=row["scenario_id"],
        scenario_name=row["scenario_name"], severity=row["severity"],
        affected_hosts=json.loads(row["affected_hosts"]), proximity=row["proximity"],
        band=row["band"], state=row["state"], first_seen=row["first_seen"], last_seen=row["last_seen"],
        count=row["count"], absent_cycles=row["absent_cycles"], notified_band=row["notified_band"],
        detection_json=row["detection_json"], created_at=row["created_at"], updated_at=row["updated_at"],
        assignee=row["assignee"], status=row["status"], resolution_note=row["resolution_note"],
        assigned_at=row["assigned_at"], resolved_at=row["resolved_at"],
    )


class AlertStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        _init_alerts_db(conn)

    def create(self, a: Alert) -> str:
        aid = a.id or secrets.token_hex(8)
        self.conn.execute(
            "INSERT INTO alerts(id,dedup_key,scenario_id,scenario_name,severity,affected_hosts,proximity,"
            "band,state,first_seen,last_seen,count,absent_cycles,notified_band,detection_json,created_at,"
            "updated_at,assignee,status,resolution_note,assigned_at,resolved_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, a.dedup_key, a.scenario_id, a.scenario_name, a.severity, json.dumps(a.affected_hosts),
             a.proximity, a.band, a.state, a.first_seen, a.last_seen, a.count, a.absent_cycles,
             a.notified_band, a.detection_json, a.created_at, a.updated_at,
             a.assignee, a.status, a.resolution_note, a.assigned_at, a.resolved_at),
        )
        self.conn.commit()
        return aid

    def get(self, aid: str) -> Alert | None:
        r = self.conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        return _row_to_alert(r) if r else None

    def get_by_dedup_key(self, key: str) -> Alert | None:
        r = self.conn.execute("SELECT * FROM alerts WHERE dedup_key=?", (key,)).fetchone()
        return _row_to_alert(r) if r else None

    def list(self, state: str | None = None, severity: str | None = None, *,
             status: str | None = None, assignee: str | None = None,
             seen_from: str | None = None, seen_to: str | None = None,
             dedup_key: str | None = None) -> list[Alert]:
        q, params = "SELECT * FROM alerts", []
        clauses = []
        if state:
            clauses.append("state=?"); params.append(state)
        if severity:
            clauses.append("severity=?"); params.append(severity)
        if status:
            clauses.append("status=?"); params.append(status)
        if assignee is not None:
            clauses.append("assignee=?"); params.append(assignee)
        if seen_from:
            clauses.append("last_seen>=?"); params.append(seen_from)
        if seen_to:
            clauses.append("last_seen<=?"); params.append(seen_to)
        if dedup_key:
            clauses.append("dedup_key=?"); params.append(dedup_key)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY created_at DESC, id DESC"
        return [_row_to_alert(r) for r in self.conn.execute(q, params).fetchall()]

    def update(self, a: Alert) -> None:
        self.conn.execute(
            "UPDATE alerts SET scenario_name=?,severity=?,affected_hosts=?,proximity=?,band=?,state=?,"
            "last_seen=?,count=?,absent_cycles=?,notified_band=?,detection_json=?,updated_at=?,"
            "assignee=?,status=?,resolution_note=?,assigned_at=?,resolved_at=? WHERE id=?",
            (a.scenario_name, a.severity, json.dumps(a.affected_hosts), a.proximity, a.band, a.state,
             a.last_seen, a.count, a.absent_cycles, a.notified_band, a.detection_json, a.updated_at,
             a.assignee, a.status, a.resolution_note, a.assigned_at, a.resolved_at, a.id),
        )
        self.conn.commit()

    def set_state(self, aid: str, state: str, *, actor: str, detail: str = "") -> None:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute("UPDATE alerts SET state=?, updated_at=? WHERE id=?", (state, now, aid))
        event = {"acknowledged": "ack", "resolved": "resolved", "open": "reopened"}.get(state, state)
        self.add_event(AlertEvent(alert_id=aid, ts=now, actor=actor, event=event, detail=detail))

    def assign(self, aid: str, assignee: str, *, actor: str) -> None:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "UPDATE alerts SET assignee=?, assigned_at=?, updated_at=? WHERE id=?",
            (assignee, now, now, aid),
        )
        self.add_event(AlertEvent(alert_id=aid, ts=now, actor=actor, event="assigned", detail=assignee))

    def set_status(self, aid: str, status: str, *, actor: str, note: str = "") -> None:
        if status not in _WORKFLOW_STATUSES:
            raise ValueError(f"invalid status: {status!r}")
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        terminal = status in ("resolved", "closed")
        resolved_at = now if terminal else ""
        self.conn.execute(
            "UPDATE alerts SET status=?, resolution_note=?, resolved_at=?, updated_at=? WHERE id=?",
            (status, note, resolved_at, now, aid),
        )
        # Mirror to the legacy engine `state` for the two overlapping values so the open-queue
        # summary and auto-resolve stay coherent. in_progress/open leave `state` as the engine set it.
        if status == "acknowledged":
            self.conn.execute("UPDATE alerts SET state=? WHERE id=?", ("acknowledged", aid))
        elif terminal:
            self.conn.execute("UPDATE alerts SET state=? WHERE id=?", ("resolved", aid))
        detail = f"{status} — {note}" if note else status
        self.add_event(AlertEvent(alert_id=aid, ts=now, actor=actor, event="status", detail=detail))

    def add_comment(self, aid: str, *, actor: str, text: str) -> None:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        self.add_event(AlertEvent(alert_id=aid, ts=now, actor=actor, event="comment", detail=text))

    def add_event(self, e: AlertEvent) -> None:
        self.conn.execute(
            "INSERT INTO alert_events(alert_id,ts,actor,event,detail) VALUES(?,?,?,?,?)",
            (e.alert_id, e.ts, e.actor, e.event, e.detail),
        )
        self.conn.commit()

    def list_events(self, aid: str) -> list[AlertEvent]:
        rows = self.conn.execute(
            "SELECT * FROM alert_events WHERE alert_id=? ORDER BY id", (aid,)).fetchall()
        return [AlertEvent(id=r["id"], alert_id=r["alert_id"], ts=r["ts"], actor=r["actor"],
                           event=r["event"], detail=r["detail"]) for r in rows]

    def summary(self) -> dict:
        rows = self.conn.execute("SELECT state, COUNT(*) c FROM alerts GROUP BY state").fetchall()
        by_state = {r["state"]: r["c"] for r in rows}
        status_rows = self.conn.execute(
            "SELECT status, COUNT(*) c FROM alerts GROUP BY status").fetchall()
        by_status_raw = {r["status"]: r["c"] for r in status_rows}
        by_status = {st: by_status_raw.get(st, 0) for st in _WORKFLOW_STATUSES}
        unassigned = self.conn.execute(
            "SELECT COUNT(*) c FROM alerts WHERE assignee=''").fetchone()["c"]
        max_row = self.conn.execute("SELECT MAX(rowid) m FROM alerts").fetchone()
        latest = self.conn.execute("SELECT MAX(created_at) m FROM alerts").fetchone()
        return {
            "open_count": by_state.get("open", 0),
            "acknowledged_count": by_state.get("acknowledged", 0),
            "resolved_count": by_state.get("resolved", 0),
            "in_progress_count": by_status["in_progress"],
            "closed_count": by_status["closed"],
            "unassigned_count": unassigned,
            "by_status": by_status,
            "max_alert_id": max_row["m"] or 0,
            "latest_created_at": latest["m"] or "",
        }

    def activity_span(self) -> tuple[str | None, str | None]:
        """(min, max) ISO timestamp across all non-empty lifecycle stamps (created_at, assigned_at,
        resolved_at) over all alerts, or (None, None) if the store has none. Read-only; one aggregate
        SELECT; no schema change. Feeds the triage-handover default wall-clock window (analogous to
        corpus_time_span for the board diff)."""
        row = self.conn.execute(
            "SELECT MIN(ts) lo, MAX(ts) hi FROM ("
            "  SELECT created_at ts FROM alerts WHERE created_at <> '' "
            "  UNION ALL SELECT assigned_at FROM alerts WHERE assigned_at <> '' "
            "  UNION ALL SELECT resolved_at FROM alerts WHERE resolved_at <> '' "
            ")"
        ).fetchone()
        return (row["lo"], row["hi"])

    def prune(self, before_iso: str, *, states: tuple[str, ...] = ("resolved",)) -> int:
        """Delete alerts where state IN states AND updated_at < before_iso.

        Deletes alert_events rows for the deleted alerts first (no FK cascade).
        Returns count of alerts deleted.
        """
        placeholders = ",".join("?" * len(states))
        # Find the ids to delete first so we can clean up alert_events
        rows = self.conn.execute(
            f"SELECT id FROM alerts WHERE state IN ({placeholders}) AND updated_at < ?",
            (*states, before_iso),
        ).fetchall()
        if not rows:
            return 0
        ids = [r["id"] for r in rows]
        id_placeholders = ",".join("?" * len(ids))
        # Delete child events first
        self.conn.execute(
            f"DELETE FROM alert_events WHERE alert_id IN ({id_placeholders})", ids
        )
        # Delete the alerts
        cur = self.conn.execute(
            f"DELETE FROM alerts WHERE id IN ({id_placeholders})", ids
        )
        self.conn.commit()
        return cur.rowcount


def apply_evaluation(store: "AlertStore", result) -> dict:
    """Persist an EvaluationResult; resolve random ids for new alerts before logging events."""
    # New alerts: mint id, insert, then stamp any 'created' events with that id.
    for a in result.created:
        if not a.id:
            a.id = secrets.token_hex(8)
        store.create(a)
    for a in result.escalated + result.updated + result.resolved:
        store.update(a)
    # Only 'created' events carry an empty alert_id (the evaluator can't mint random ids). Reopened/
    # escalated events already reference a real id from `existing`. Back-fill the created events by
    # creation order — the evaluator emits exactly one empty-id event per created alert, in order.
    pending = [e for e in result.events if not e.alert_id]
    assert len(pending) == len(result.created), "exactly one empty-id (created) event per created alert"
    for e, a in zip(pending, result.created):
        e.alert_id = a.id
    for e in result.events:
        if e.alert_id:
            store.add_event(e)
    return {"created": len(result.created), "escalated": len(result.escalated),
            "updated": len(result.updated), "resolved": len(result.resolved)}
