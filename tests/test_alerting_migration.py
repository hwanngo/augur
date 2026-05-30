"""Migration tests: additive assignee/status columns on a pre-existing (old-schema) alerts DB."""
import sqlite3

from augur.alerting.store import AlertStore


def _old_schema_conn(db_path: str) -> sqlite3.Connection:
    """Create an alerts table with the *legacy* schema (no new triage columns)."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE alerts(
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
          updated_at TEXT NOT NULL
        );
        CREATE TABLE alert_events(
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
    return conn


_NEW_COLS = ("assignee", "status", "resolution_note", "assigned_at", "resolved_at")


def test_migration_adds_columns_and_backfills_resolved(tmp_path):
    conn = _old_schema_conn(str(tmp_path / "old.db"))
    # Insert a legacy row already resolved by the engine `state`.
    conn.execute(
        "INSERT INTO alerts(id,dedup_key,scenario_id,scenario_name,severity,affected_hosts,proximity,"
        "band,state,first_seen,last_seen,count,absent_cycles,notified_band,detection_json,created_at,"
        "updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("a1", "SCEN-1|hostA", "SCEN-1", "Cred Theft", "CRITICAL", '["hostA"]', 0.6, "WATCH",
         "resolved", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00", 1, 0, "WATCH", "{}",
         "2026-01-01T00:00:00+00:00", "2026-01-02T03:04:05+00:00"),
    )
    conn.commit()

    AlertStore(conn)  # opening the store runs the additive migration

    cols = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    for c in _NEW_COLS:
        assert c in cols, f"missing migrated column {c}"

    row = conn.execute("SELECT status, resolved_at, assignee FROM alerts WHERE id='a1'").fetchone()
    assert row["status"] == "resolved"          # backfilled from legacy state='resolved'
    assert row["resolved_at"] == "2026-01-02T03:04:05+00:00"  # from updated_at
    assert row["assignee"] == ""                # default unassigned


def test_init_twice_is_idempotent(tmp_path):
    conn = _old_schema_conn(str(tmp_path / "twice.db"))
    AlertStore(conn)
    # Re-opening must not error and must not duplicate columns.
    AlertStore(conn)
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()]
    for c in _NEW_COLS:
        assert cols.count(c) == 1
