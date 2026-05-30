import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Candidate:
    scenario_id: str
    category: str
    yaml: str
    seed_id: str
    mutation_axes: str
    plausibility: float
    gauntlet_report: str
    created_by: str
    id: str = ""
    status: str = "pending"
    created_at: str = ""
    reviewed_by: str = ""
    reviewed_at: str = ""


def _init_candidates_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS candidates(
          id TEXT PRIMARY KEY,
          scenario_id TEXT NOT NULL,
          category TEXT NOT NULL,
          yaml TEXT NOT NULL,
          seed_id TEXT NOT NULL,
          mutation_axes TEXT NOT NULL,
          plausibility REAL NOT NULL,
          gauntlet_report TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          created_by TEXT NOT NULL,
          created_at TEXT NOT NULL,
          reviewed_by TEXT NOT NULL DEFAULT '',
          reviewed_at TEXT NOT NULL DEFAULT ''
        );
        """
    )
    conn.commit()


def _row_to_candidate(row: sqlite3.Row) -> Candidate:
    return Candidate(
        id=row["id"],
        scenario_id=row["scenario_id"],
        category=row["category"],
        yaml=row["yaml"],
        seed_id=row["seed_id"],
        mutation_axes=row["mutation_axes"],
        plausibility=row["plausibility"],
        gauntlet_report=row["gauntlet_report"],
        status=row["status"],
        created_by=row["created_by"],
        created_at=row["created_at"],
        reviewed_by=row["reviewed_by"],
        reviewed_at=row["reviewed_at"],
    )


class CandidateStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        _init_candidates_db(conn)

    def create(self, candidate: Candidate) -> str:
        cid = secrets.token_hex(8)
        now = _now()
        self.conn.execute(
            "INSERT INTO candidates(id,scenario_id,category,yaml,seed_id,mutation_axes,"
            "plausibility,gauntlet_report,status,created_by,created_at,reviewed_by,reviewed_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (cid, candidate.scenario_id, candidate.category, candidate.yaml,
             candidate.seed_id, candidate.mutation_axes, candidate.plausibility,
             candidate.gauntlet_report, candidate.status or "pending",
             candidate.created_by, now, "", "")
        )
        self.conn.commit()
        return cid

    def get(self, cid: str) -> Candidate | None:
        r = self.conn.execute("SELECT * FROM candidates WHERE id=?", (cid,)).fetchone()
        return _row_to_candidate(r) if r else None

    def list(self, status: str | None = None) -> list[Candidate]:
        if status is not None:
            rows = self.conn.execute(
                "SELECT * FROM candidates WHERE status=? ORDER BY created_at", (status,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM candidates ORDER BY created_at"
            ).fetchall()
        return [_row_to_candidate(r) for r in rows]

    def set_status(self, cid: str, status: str, *, reviewed_by: str = "") -> None:
        now = _now()
        self.conn.execute(
            "UPDATE candidates SET status=?, reviewed_by=?, reviewed_at=? WHERE id=?",
            (status, reviewed_by, now, cid)
        )
        self.conn.commit()

    def prune(self, before_iso: str, *, statuses: tuple[str, ...] = ("approved", "rejected")) -> int:
        """Delete candidates where status IN statuses AND created_at < before_iso.

        Returns count of rows deleted.
        """
        placeholders = ",".join("?" * len(statuses))
        cur = self.conn.execute(
            f"DELETE FROM candidates WHERE status IN ({placeholders}) AND created_at < ?",
            (*statuses, before_iso),
        )
        self.conn.commit()
        return cur.rowcount
