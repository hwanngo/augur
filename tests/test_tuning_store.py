"""TDD: AllowlistStore — FP-tuning allowlist persistence (sqlite, mirrors HuntStore)."""
from datetime import datetime, timezone

from augur.auth.store import connect
from augur.tuning.store import AllowlistStore, AllowlistEntry


def _store(tmp_path):
    return AllowlistStore(connect(str(tmp_path / "t.db")))


def _entry(**kw):
    base = dict(action="SUPPRESS", reason="backup agent reads lsass nightly", author="alice",
                scenario_id="SCEN-WIN-001")
    base.update(kw)
    return AllowlistEntry(**base)


def test_create_and_get_roundtrip(tmp_path):
    s = _store(tmp_path)
    eid = s.create(_entry(host="BACKUP-01"))
    got = s.get(eid)
    assert got is not None
    assert got.action == "SUPPRESS"
    assert got.scenario_id == "SCEN-WIN-001"
    assert got.host == "BACKUP-01"
    # empty-string sentinels load back as None
    assert got.technique is None
    assert got.process_regex is None
    assert got.enabled is True


def test_predicates_excludes_empty(tmp_path):
    e = _entry(host="BACKUP-01", technique=None)
    assert e.predicates() == {"scenario_id": "SCEN-WIN-001", "host": "BACKUP-01"}


def test_list_orders_by_id_and_filters_enabled(tmp_path):
    s = _store(tmp_path)
    a = s.create(AllowlistEntry(id="aaaa", action="SUPPRESS", reason="r", author="x", scenario_id="S1"))
    b = s.create(AllowlistEntry(id="bbbb", action="SUPPRESS", reason="r", author="x", scenario_id="S2"))
    s.set_enabled(b, False, actor="x")
    ids = [e.id for e in s.list()]
    assert ids == ["aaaa", "bbbb"]  # ordered by id
    assert [e.id for e in s.list(enabled=True)] == ["aaaa"]
    assert [e.id for e in s.list(enabled=False)] == ["bbbb"]


def test_active_entries_excludes_disabled_and_expired(tmp_path):
    s = _store(tmp_path)
    now = datetime(2026, 6, 3, tzinfo=timezone.utc)
    past = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat()
    future = datetime(2027, 1, 1, tzinfo=timezone.utc).isoformat()
    live = s.create(_entry(id="live", expires_at=future))
    s.create(_entry(id="expired", expires_at=past))
    disabled = s.create(_entry(id="disabled"))
    s.set_enabled(disabled, False, actor="x")
    active = s.active_entries(now=now)
    assert [e.id for e in active] == ["live"]
    assert s.has_active(now=now) is True


def test_has_active_false_when_empty(tmp_path):
    s = _store(tmp_path)
    assert s.has_active(now=datetime(2026, 6, 3, tzinfo=timezone.utc)) is False


def test_update_changes_fields_and_logs_event(tmp_path):
    s = _store(tmp_path)
    eid = s.create(_entry())
    e = s.get(eid)
    e.reason = "updated reason"
    e.host = "WS-1"
    s.update(e, actor="bob")
    got = s.get(eid)
    assert got.reason == "updated reason"
    assert got.host == "WS-1"
    assert "edited" in [ev.event for ev in s.list_events(eid)]


def test_set_enabled_toggle_and_events(tmp_path):
    s = _store(tmp_path)
    eid = s.create(_entry())
    s.set_enabled(eid, False, actor="bob")
    assert s.get(eid).enabled is False
    s.set_enabled(eid, True, actor="bob")
    assert s.get(eid).enabled is True
    events = [ev.event for ev in s.list_events(eid)]
    assert events == ["created", "disabled", "enabled"]


def test_delete_removes_row_keeps_event_trail(tmp_path):
    s = _store(tmp_path)
    eid = s.create(_entry())
    s.delete(eid, actor="bob")
    assert s.get(eid) is None
    assert "deleted" in [ev.event for ev in s.list_events(eid)]


def test_proposed_source_logs_proposed_event(tmp_path):
    s = _store(tmp_path)
    eid = s.create(_entry(source="proposed", source_alert_id="alert-9"))
    assert s.get(eid).source == "proposed"
    assert s.get(eid).source_alert_id == "alert-9"
    assert s.list_events(eid)[0].event == "proposed"
