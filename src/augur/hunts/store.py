import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

_HUNT_STATUSES = ("open", "investigating", "confirmed", "refuted", "abandoned")
_TERMINAL = ("confirmed", "refuted")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Hunt:
    owner: str
    hypothesis: str
    scope_json: str = "{}"
    id: str = ""
    status: str = "open"
    verdict_note: str = ""
    notes: str = ""
    verdict_evidence_json: str = ""
    verdict_evidence_at: str = ""
    created_at: str = ""
    updated_at: str = ""


@dataclass
class HuntEvent:
    hunt_id: str
    ts: str
    actor: str
    event: str
    detail: str = ""
    id: int = 0


def _init_hunts_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS hunts(
          id TEXT PRIMARY KEY,
          owner TEXT NOT NULL,
          hypothesis TEXT NOT NULL,
          scope_json TEXT NOT NULL DEFAULT '{}',
          status TEXT NOT NULL DEFAULT 'open',
          verdict_note TEXT NOT NULL DEFAULT '',
          notes TEXT NOT NULL DEFAULT '',
          verdict_evidence_json TEXT NOT NULL DEFAULT '',
          verdict_evidence_at TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_hunts_status ON hunts(status);
        CREATE INDEX IF NOT EXISTS idx_hunts_owner ON hunts(owner);
        CREATE TABLE IF NOT EXISTS hunt_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          hunt_id TEXT NOT NULL,
          ts TEXT NOT NULL,
          actor TEXT NOT NULL,
          event TEXT NOT NULL,
          detail TEXT NOT NULL DEFAULT ''
        );
        """
    )
    conn.commit()


def _row_to_hunt(row: sqlite3.Row) -> Hunt:
    return Hunt(id=row["id"], owner=row["owner"], hypothesis=row["hypothesis"],
               scope_json=row["scope_json"], status=row["status"], verdict_note=row["verdict_note"],
               notes=row["notes"], verdict_evidence_json=row["verdict_evidence_json"],
               verdict_evidence_at=row["verdict_evidence_at"],
               created_at=row["created_at"], updated_at=row["updated_at"])


class HuntStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        _init_hunts_db(conn)

    def create(self, h: Hunt) -> str:
        hid = h.id or secrets.token_hex(8)
        now = _now()
        self.conn.execute(
            "INSERT INTO hunts(id,owner,hypothesis,scope_json,status,verdict_note,notes,"
            "verdict_evidence_json,verdict_evidence_at,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (hid, h.owner, h.hypothesis, h.scope_json, h.status, h.verdict_note, h.notes,
             h.verdict_evidence_json, h.verdict_evidence_at, now, now),
        )
        self.conn.commit()
        self.add_event(HuntEvent(hunt_id=hid, ts=now, actor=h.owner, event="created", detail=""))
        return hid

    def get(self, hid: str) -> Hunt | None:
        row = self.conn.execute("SELECT * FROM hunts WHERE id=?", (hid,)).fetchone()
        return _row_to_hunt(row) if row else None

    def list(self, *, status: str | None = None, owner: str | None = None) -> list[Hunt]:
        clauses, params = [], []
        if status:
            clauses.append("status=?"); params.append(status)
        if owner:
            clauses.append("owner=?"); params.append(owner)
        q = "SELECT * FROM hunts"
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY created_at DESC, id DESC"
        return [_row_to_hunt(r) for r in self.conn.execute(q, params).fetchall()]

    def update(self, h: Hunt) -> None:
        self.conn.execute(
            "UPDATE hunts SET hypothesis=?,scope_json=?,notes=?,updated_at=? WHERE id=?",
            (h.hypothesis, h.scope_json, h.notes, _now(), h.id),
        )
        self.conn.commit()

    def set_status(self, hid: str, status: str, *, actor: str, note: str = "",
                   evidence_json: str = "", evidence_at: str = "") -> None:
        if status not in _HUNT_STATUSES:
            raise ValueError(f"invalid status: {status!r}")
        now = _now()
        if status in _TERMINAL:
            self.conn.execute(
                "UPDATE hunts SET status=?,verdict_note=?,verdict_evidence_json=?,"
                "verdict_evidence_at=?,updated_at=? WHERE id=?",
                (status, note, evidence_json, evidence_at, now, hid),
            )
        else:
            self.conn.execute("UPDATE hunts SET status=?,updated_at=? WHERE id=?", (status, now, hid))
        self.conn.commit()
        self.add_event(HuntEvent(hunt_id=hid, ts=now, actor=actor, event="status", detail=status))

    def add_comment(self, hid: str, *, actor: str, text: str) -> None:
        self.add_event(HuntEvent(hunt_id=hid, ts=_now(), actor=actor, event="comment", detail=text))

    def add_event(self, e: HuntEvent) -> None:
        self.conn.execute("INSERT INTO hunt_events(hunt_id,ts,actor,event,detail) VALUES(?,?,?,?,?)",
                          (e.hunt_id, e.ts, e.actor, e.event, e.detail))
        self.conn.commit()

    def list_events(self, hid: str) -> list[HuntEvent]:
        rows = self.conn.execute("SELECT * FROM hunt_events WHERE hunt_id=? ORDER BY id", (hid,)).fetchall()
        return [HuntEvent(id=r["id"], hunt_id=r["hunt_id"], ts=r["ts"], actor=r["actor"],
                          event=r["event"], detail=r["detail"]) for r in rows]

    def delete(self, hid: str) -> None:
        self.conn.execute("DELETE FROM hunt_events WHERE hunt_id=?", (hid,))
        self.conn.execute("DELETE FROM hunts WHERE id=?", (hid,))
        self.conn.commit()
