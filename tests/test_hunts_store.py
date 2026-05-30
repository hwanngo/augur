"""TDD: HuntStore — human-authored hunt state (sqlite, mirrors AlertStore)."""
from augur.auth.store import connect
from augur.hunts.store import HuntStore, Hunt, HuntEvent, _HUNT_STATUSES


def _store(tmp_path):
    return HuntStore(connect(str(tmp_path / "h.db")))


def _hunt(**kw):
    base = dict(owner="alice", hypothesis="cred theft advancing in DMZ", scope_json='{"zone":"DMZ"}')
    base.update(kw)
    return Hunt(**base)


def test_create_get_list(tmp_path):
    s = _store(tmp_path)
    hid = s.create(_hunt())
    got = s.get(hid)
    assert got.hypothesis == "cred theft advancing in DMZ" and got.owner == "alice" and got.status == "open"
    assert got.created_at and got.updated_at
    assert [h.id for h in s.list()] == [hid]
    assert s.list(owner="bob") == []
    assert [h.id for h in s.list(owner="alice")] == [hid]


def test_set_status_validates_and_stamps(tmp_path):
    s = _store(tmp_path)
    hid = s.create(_hunt())
    s.set_status(hid, "investigating", actor="alice")
    assert s.get(hid).status == "investigating"
    import pytest
    with pytest.raises(ValueError):
        s.set_status(hid, "bogus", actor="alice")


def test_terminal_status_captures_verdict_snapshot(tmp_path):
    s = _store(tmp_path)
    hid = s.create(_hunt())
    s.set_status(hid, "confirmed", actor="alice", note="found it",
                 evidence_json='[{"scenario_id":"SCEN-WIN-001","proximity":1.0}]',
                 evidence_at="2026-06-01T10:00:00+00:00")
    h = s.get(hid)
    assert h.status == "confirmed" and h.verdict_note == "found it"
    assert "SCEN-WIN-001" in h.verdict_evidence_json and h.verdict_evidence_at == "2026-06-01T10:00:00+00:00"


def test_comment_and_events(tmp_path):
    s = _store(tmp_path)
    hid = s.create(_hunt())
    s.add_comment(hid, actor="alice", text="checking lsass")
    s.set_status(hid, "investigating", actor="alice")
    evs = s.list_events(hid)
    assert any(e.event == "comment" and e.detail == "checking lsass" for e in evs)
    assert any(e.event == "status" for e in evs)
    assert evs == sorted(evs, key=lambda e: e.id)


def test_delete_removes_hunt_and_events(tmp_path):
    s = _store(tmp_path)
    hid = s.create(_hunt())
    s.add_comment(hid, actor="alice", text="x")
    s.delete(hid)
    assert s.get(hid) is None
    assert s.list_events(hid) == []


def test_hunts_table_has_no_engine_result_column(tmp_path):
    s = _store(tmp_path)
    cols = {r[1] for r in s.conn.execute("PRAGMA table_info(hunts)").fetchall()}
    assert "proximity" not in cols and "detection_json" not in cols and "evidence_json" not in cols
    assert "verdict_evidence_json" in cols and "verdict_evidence_at" in cols
