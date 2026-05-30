# tests/test_retention.py
import pytest
from augur.auth.store import connect, UserStore, SessionStore, AuthEvents


def _conn(tmp_path, name="r.db"):
    return connect(str(tmp_path / name))


# ── SessionStore.prune_expired ──────────────────────────────────────────────

def test_prune_expired_removes_old_and_keeps_fresh(tmp_path):
    conn = _conn(tmp_path)
    us = UserStore(conn)
    ss = SessionStore(conn)
    uid = us.create_user("alice", "h", "viewer")

    # Insert two sessions manually with explicit expires_at
    conn.execute(
        "INSERT INTO sessions(id,user_id,csrf_token,created_at,last_seen,expires_at) VALUES(?,?,?,?,?,?)",
        ("old-sid", uid, "csrf1", "2026-01-01T00:00:00+00:00",
         "2026-01-01T00:00:00+00:00", "2026-01-01T01:00:00+00:00"),
    )
    conn.execute(
        "INSERT INTO sessions(id,user_id,csrf_token,created_at,last_seen,expires_at) VALUES(?,?,?,?,?,?)",
        ("fresh-sid", uid, "csrf2", "2026-06-01T00:00:00+00:00",
         "2026-06-01T00:00:00+00:00", "2099-12-31T23:59:59+00:00"),
    )
    conn.commit()

    deleted = ss.prune_expired("2026-05-01T00:00:00+00:00")
    assert deleted == 1
    assert ss.get("old-sid") is None
    assert ss.get("fresh-sid") is not None


def test_prune_expired_returns_zero_when_nothing_to_delete(tmp_path):
    conn = _conn(tmp_path)
    us = UserStore(conn)
    ss = SessionStore(conn)
    uid = us.create_user("bob", "h", "viewer")
    conn.execute(
        "INSERT INTO sessions(id,user_id,csrf_token,created_at,last_seen,expires_at) VALUES(?,?,?,?,?,?)",
        ("fresh2", uid, "csrf3", "2026-06-01T00:00:00+00:00",
         "2026-06-01T00:00:00+00:00", "2099-12-31T23:59:59+00:00"),
    )
    conn.commit()
    assert ss.prune_expired("2026-01-01T00:00:00+00:00") == 0


# ── AuthEvents.prune ────────────────────────────────────────────────────────

def test_prune_auth_events_removes_old_keeps_recent(tmp_path):
    conn = _conn(tmp_path)
    ev = AuthEvents(conn)
    conn.execute(
        "INSERT INTO auth_events(ts,username,event,ip,detail) VALUES(?,?,?,?,?)",
        ("2025-01-01T00:00:00+00:00", "alice", "login_ok", "1.2.3.4", ""),
    )
    conn.execute(
        "INSERT INTO auth_events(ts,username,event,ip,detail) VALUES(?,?,?,?,?)",
        ("2026-06-01T00:00:00+00:00", "alice", "login_ok", "1.2.3.4", ""),
    )
    conn.commit()

    deleted = ev.prune("2026-05-01T00:00:00+00:00")
    assert deleted == 1
    rows = ev.recent(100)
    assert len(rows) == 1
    assert rows[0]["ts"] == "2026-06-01T00:00:00+00:00"


def test_prune_auth_events_zero_on_empty(tmp_path):
    conn = _conn(tmp_path)
    ev = AuthEvents(conn)
    assert ev.prune("2026-01-01T00:00:00+00:00") == 0


# ── AlertStore.prune ────────────────────────────────────────────────────────

from augur.alerting.store import AlertStore, Alert


def _alert(dedup_key, state, updated_at, scenario_id="SCEN-1"):
    return Alert(
        dedup_key=dedup_key,
        scenario_id=scenario_id,
        scenario_name="Test",
        severity="HIGH",
        affected_hosts=["hostA"],
        proximity=0.8,
        band="HIGH",
        state=state,
        first_seen="2026-01-01T00:00:00+00:00",
        last_seen="2026-01-01T00:00:00+00:00",
        count=1,
        absent_cycles=0,
        notified_band="",
        detection_json="{}",
        created_at="2026-01-01T00:00:00+00:00",
        updated_at=updated_at,
    )


def test_alert_prune_removes_resolved_old_alerts(tmp_path):
    conn = _conn(tmp_path)
    s = AlertStore(conn)

    # old resolved → should be pruned
    old_resolved_id = s.create(_alert("k1", "resolved", "2025-06-01T00:00:00+00:00"))
    # recent resolved → should stay (updated_at is after cutoff)
    recent_resolved_id = s.create(_alert("k2", "resolved", "2026-06-01T00:00:00+00:00", "SCEN-2"))
    # old open → should stay (state not in default states)
    old_open_id = s.create(_alert("k3", "open", "2025-06-01T00:00:00+00:00", "SCEN-3"))

    deleted = s.prune("2026-01-01T00:00:00+00:00")
    assert deleted == 1
    assert s.get(old_resolved_id) is None
    assert s.get(recent_resolved_id) is not None
    assert s.get(old_open_id) is not None


def test_alert_prune_also_deletes_alert_events(tmp_path):
    from augur.alerting.store import AlertEvent
    conn = _conn(tmp_path)
    s = AlertStore(conn)
    aid = s.create(_alert("k1", "resolved", "2025-01-01T00:00:00+00:00"))
    s.add_event(AlertEvent(alert_id=aid, ts="2025-01-01T00:00:00+00:00",
                           actor="system", event="resolved", detail=""))
    # Events exist before prune
    assert len(s.list_events(aid)) == 1

    deleted = s.prune("2026-01-01T00:00:00+00:00")
    assert deleted == 1
    # Events are gone too
    assert s.list_events(aid) == []


def test_alert_prune_custom_states(tmp_path):
    conn = _conn(tmp_path)
    s = AlertStore(conn)
    # acknowledged + old → should be pruned if we pass states=("acknowledged",)
    ack_old_id = s.create(_alert("k1", "acknowledged", "2025-01-01T00:00:00+00:00"))
    # resolved + old → stays (not in the custom states tuple)
    res_old_id = s.create(_alert("k2", "resolved", "2025-01-01T00:00:00+00:00", "SCEN-2"))

    deleted = s.prune("2026-01-01T00:00:00+00:00", states=("acknowledged",))
    assert deleted == 1
    assert s.get(ack_old_id) is None
    assert s.get(res_old_id) is not None


def test_alert_prune_zero_when_no_eligible(tmp_path):
    conn = _conn(tmp_path)
    s = AlertStore(conn)
    s.create(_alert("k1", "open", "2025-01-01T00:00:00+00:00"))
    assert s.prune("2026-01-01T00:00:00+00:00") == 0


# ── CandidateStore.prune ────────────────────────────────────────────────────

from augur.generative.candidates import CandidateStore, Candidate


def _candidate(status, created_at):
    return Candidate(
        scenario_id="SCEN-GEN-0001",
        category="credential_access",
        yaml="id: SCEN-GEN-0001",
        seed_id="SCEN-WIN-001",
        mutation_axes="lolbin",
        plausibility=0.9,
        gauntlet_report="{}",
        created_by="admin",
        status=status,
    )


def _insert_candidate_at(conn, status, created_at):
    """Helper: insert a candidate with an explicit created_at (bypassing _now())."""
    import secrets
    cid = secrets.token_hex(8)
    conn.execute(
        "INSERT INTO candidates(id,scenario_id,category,yaml,seed_id,mutation_axes,"
        "plausibility,gauntlet_report,status,created_by,created_at,reviewed_by,reviewed_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (cid, "SCEN-GEN-0001", "credential_access", "yaml: here",
         "SCEN-WIN-001", "lolbin", 0.9, "{}", status, "admin", created_at, "", ""),
    )
    conn.commit()
    return cid


def test_candidate_prune_removes_approved_old(tmp_path):
    conn = _conn(tmp_path)
    cs = CandidateStore(conn)

    old_approved = _insert_candidate_at(conn, "approved", "2025-01-01T00:00:00+00:00")
    recent_approved = _insert_candidate_at(conn, "approved", "2026-06-01T00:00:00+00:00")
    old_pending = _insert_candidate_at(conn, "pending", "2025-01-01T00:00:00+00:00")

    deleted = cs.prune("2026-01-01T00:00:00+00:00")
    assert deleted == 1
    assert cs.get(old_approved) is None
    assert cs.get(recent_approved) is not None
    assert cs.get(old_pending) is not None


def test_candidate_prune_rejected_old(tmp_path):
    conn = _conn(tmp_path)
    cs = CandidateStore(conn)
    old_rejected = _insert_candidate_at(conn, "rejected", "2025-01-01T00:00:00+00:00")
    deleted = cs.prune("2026-01-01T00:00:00+00:00")
    assert deleted == 1
    assert cs.get(old_rejected) is None


def test_candidate_prune_custom_statuses(tmp_path):
    conn = _conn(tmp_path)
    cs = CandidateStore(conn)
    old_approved = _insert_candidate_at(conn, "approved", "2025-01-01T00:00:00+00:00")
    old_rejected = _insert_candidate_at(conn, "rejected", "2025-01-01T00:00:00+00:00")
    # Only prune approved; rejected should stay
    deleted = cs.prune("2026-01-01T00:00:00+00:00", statuses=("approved",))
    assert deleted == 1
    assert cs.get(old_approved) is None
    assert cs.get(old_rejected) is not None


def test_candidate_prune_zero_when_nothing_eligible(tmp_path):
    conn = _conn(tmp_path)
    cs = CandidateStore(conn)
    _insert_candidate_at(conn, "pending", "2025-01-01T00:00:00+00:00")
    assert cs.prune("2026-01-01T00:00:00+00:00") == 0


# ── maintenance CLI smoke test ───────────────────────────────────────────────

import subprocess
import sys


def test_maintenance_prune_smoke(tmp_path):
    """maintenance.main(['prune','--days','30','--db', path]) prints a pruned: line."""
    db_path = str(tmp_path / "maint.db")
    result = subprocess.run(
        [sys.executable, "-m", "augur.maintenance", "prune", "--days", "30", "--db", db_path],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "pruned:" in result.stdout
