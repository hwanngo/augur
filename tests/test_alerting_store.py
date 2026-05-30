import json
from augur.auth.store import connect
from augur.alerting.store import AlertStore, Alert, AlertEvent


def _alert(**kw):
    base = dict(dedup_key="SCEN-1|hostA", scenario_id="SCEN-1", scenario_name="Cred Theft",
                severity="CRITICAL", affected_hosts=["hostA"], proximity=0.6, band="WATCH",
                state="open", first_seen="2026-01-01T00:00:00+00:00", last_seen="2026-01-01T00:00:00+00:00",
                count=1, absent_cycles=0, notified_band="WATCH", detection_json="{}",
                created_at="2026-01-01T00:00:00+00:00", updated_at="2026-01-01T00:00:00+00:00")
    base.update(kw)
    return Alert(**base)


def test_create_get_by_key_and_id(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert())
    assert s.get(aid).dedup_key == "SCEN-1|hostA"
    assert s.get_by_dedup_key("SCEN-1|hostA").id == aid
    assert s.get_by_dedup_key("nope") is None


def test_list_and_summary(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    s.create(_alert(dedup_key="SCEN-1|hostA"))
    s.create(_alert(dedup_key="SCEN-2|hostB", scenario_id="SCEN-2", state="acknowledged"))
    assert {a.dedup_key for a in s.list()} == {"SCEN-1|hostA", "SCEN-2|hostB"}
    assert [a.dedup_key for a in s.list(state="open")] == ["SCEN-1|hostA"]
    summ = s.summary()
    assert summ["open_count"] == 1 and summ["acknowledged_count"] == 1
    assert summ["max_alert_id"] >= 1


def test_update_and_set_state_and_events(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert())
    a = s.get(aid)
    a.proximity = 0.85; a.band = "HIGH"; a.count = 2; a.notified_band = "HIGH"
    s.update(a)
    assert s.get(aid).band == "HIGH" and s.get(aid).count == 2
    s.set_state(aid, "acknowledged", actor="alice")
    assert s.get(aid).state == "acknowledged"
    s.add_event(AlertEvent(alert_id=aid, ts="2026-01-01T00:00:01+00:00", actor="system",
                           event="created", detail="WATCH"))
    evs = s.list_events(aid)
    assert any(e.event == "created" for e in evs) and any(e.event == "ack" for e in evs)


def test_summary_max_alert_id_is_monotonic_rowid(tmp_path):
    """max_alert_id must be a true monotonic rowid (not COUNT), so it never decreases on delete."""
    s = AlertStore(connect(str(tmp_path / "a.db")))
    s.create(_alert(dedup_key="SCEN-1|hostA"))
    s.create(_alert(dedup_key="SCEN-2|hostB", scenario_id="SCEN-2"))
    assert s.summary()["max_alert_id"] == 2
    s.create(_alert(dedup_key="SCEN-3|hostC", scenario_id="SCEN-3"))
    assert s.summary()["max_alert_id"] == 3   # strictly increases


def test_affected_hosts_round_trips_as_json(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert(affected_hosts=["h1", "h2"], detection_json=json.dumps({"matched_steps": []})))
    got = s.get(aid)
    assert got.affected_hosts == ["h1", "h2"]
    assert json.loads(got.detection_json) == {"matched_steps": []}


def test_new_triage_columns_round_trip(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert(assignee="alice", status="in_progress", resolution_note="looking",
                          assigned_at="2026-01-01T01:00:00+00:00", resolved_at=""))
    got = s.get(aid)
    assert got.assignee == "alice"
    assert got.status == "in_progress"
    assert got.resolution_note == "looking"
    assert got.assigned_at == "2026-01-01T01:00:00+00:00"
    assert got.resolved_at == ""
    # update round-trips them too
    got.status = "resolved"; got.resolved_at = "2026-01-02T00:00:00+00:00"
    s.update(got)
    again = s.get(aid)
    assert again.status == "resolved" and again.resolved_at == "2026-01-02T00:00:00+00:00"


def test_fresh_install_has_default_triage_values(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert())
    got = s.get(aid)
    assert got.assignee == "" and got.status == "open"
    assert got.resolution_note == "" and got.assigned_at == "" and got.resolved_at == ""


def test_assign_sets_assignee_and_logs_event(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert())
    s.assign(aid, "alice", actor="bob")
    got = s.get(aid)
    assert got.assignee == "alice"
    assert got.assigned_at != ""
    assert got.assigned_at.endswith("+00:00")
    evs = s.list_events(aid)
    assigned = [e for e in evs if e.event == "assigned"]
    assert assigned and assigned[0].detail == "alice" and assigned[0].actor == "bob"


def test_assign_can_clear(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert(assignee="alice"))
    s.assign(aid, "", actor="bob")
    assert s.get(aid).assignee == ""


def test_set_status_invalid_raises_value_error(tmp_path):
    import pytest
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert())
    with pytest.raises(ValueError):
        s.set_status(aid, "bogus", actor="bob")


def test_set_status_each_valid_status(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert())
    for st in ("open", "acknowledged", "in_progress", "resolved", "closed"):
        s.set_status(aid, st, actor="bob", note="n" if st in ("resolved", "closed") else "")
        assert s.get(aid).status == st


def test_set_status_terminal_stamps_resolved_at_and_note(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert())
    s.set_status(aid, "resolved", actor="bob", note="benign")
    got = s.get(aid)
    assert got.resolved_at != "" and got.resolved_at.endswith("+00:00")
    assert got.resolution_note == "benign"
    evs = s.list_events(aid)
    assert any(e.event == "status" for e in evs)


def test_set_status_reopen_clears_resolved_at(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert())
    s.set_status(aid, "resolved", actor="bob", note="done")
    assert s.get(aid).resolved_at != ""
    s.set_status(aid, "in_progress", actor="bob")
    assert s.get(aid).resolved_at == ""


def test_set_status_mirrors_legacy_state(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert())
    s.set_status(aid, "acknowledged", actor="bob")
    assert s.get(aid).state == "acknowledged"
    s.set_status(aid, "resolved", actor="bob", note="done")
    assert s.get(aid).state == "resolved"
    s.set_status(aid, "closed", actor="bob", note="closing")
    assert s.get(aid).state == "resolved"


def test_add_comment_logs_event_without_mutating_row(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    aid = s.create(_alert())
    before = s.get(aid)
    s.add_comment(aid, actor="bob", text="investigating")
    after = s.get(aid)
    assert after.status == before.status and after.updated_at == before.updated_at
    evs = s.list_events(aid)
    comments = [e for e in evs if e.event == "comment"]
    assert comments and comments[0].detail == "investigating" and comments[0].actor == "bob"


def test_list_filters_by_status_and_assignee(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    s.create(_alert(dedup_key="d1", status="open", assignee="alice"))
    s.create(_alert(dedup_key="d2", scenario_id="S2", status="in_progress", assignee="alice"))
    s.create(_alert(dedup_key="d3", scenario_id="S3", status="in_progress", assignee="bob"))
    assert {a.dedup_key for a in s.list(status="in_progress")} == {"d2", "d3"}
    assert {a.dedup_key for a in s.list(assignee="alice")} == {"d1", "d2"}
    # combined filters AND together
    assert {a.dedup_key for a in s.list(status="in_progress", assignee="alice")} == {"d2"}


def test_list_filters_by_seen_window(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    s.create(_alert(dedup_key="d1", last_seen="2026-01-01T00:00:00+00:00"))
    s.create(_alert(dedup_key="d2", scenario_id="S2", last_seen="2026-02-01T00:00:00+00:00"))
    s.create(_alert(dedup_key="d3", scenario_id="S3", last_seen="2026-03-01T00:00:00+00:00"))
    got = {a.dedup_key for a in s.list(seen_from="2026-01-15T00:00:00+00:00",
                                       seen_to="2026-02-15T00:00:00+00:00")}
    assert got == {"d2"}
    assert {a.dedup_key for a in s.list(seen_from="2026-02-01T00:00:00+00:00")} == {"d2", "d3"}
    assert {a.dedup_key for a in s.list(seen_to="2026-02-01T00:00:00+00:00")} == {"d1", "d2"}


def test_list_filter_by_dedup_key(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    s.create(_alert(dedup_key="SCEN-1|hostA"))
    s.create(_alert(dedup_key="SCEN-2|hostB", scenario_id="SCEN-2"))
    assert [a.dedup_key for a in s.list(dedup_key="SCEN-1|hostA")] == ["SCEN-1|hostA"]
    assert s.list(dedup_key="nope") == []


def test_list_dedup_key_composes_with_status(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    s.create(_alert(dedup_key="SCEN-1|hostA", status="open"))
    s.create(_alert(dedup_key="SCEN-2|hostB", scenario_id="SCEN-2", status="in_progress"))
    # AND together: the dedup_key matches but the status does not -> empty
    assert s.list(dedup_key="SCEN-1|hostA", status="in_progress") == []
    assert [a.dedup_key for a in s.list(dedup_key="SCEN-1|hostA", status="open")] == ["SCEN-1|hostA"]


def test_list_existing_filters_still_work(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    s.create(_alert(dedup_key="d1", state="open", severity="CRITICAL"))
    s.create(_alert(dedup_key="d2", scenario_id="S2", state="acknowledged", severity="HIGH"))
    assert [a.dedup_key for a in s.list(state="open")] == ["d1"]
    assert [a.dedup_key for a in s.list(severity="HIGH")] == ["d2"]


def test_summary_extended_by_status(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    s.create(_alert(dedup_key="d1", status="open", assignee=""))
    s.create(_alert(dedup_key="d2", scenario_id="S2", status="in_progress", assignee="alice"))
    s.create(_alert(dedup_key="d3", scenario_id="S3", status="closed", assignee=""))
    summ = s.summary()
    # existing keys preserved
    assert "open_count" in summ and "max_alert_id" in summ
    assert summ["in_progress_count"] == 1
    assert summ["closed_count"] == 1
    assert summ["unassigned_count"] == 2
    assert summ["by_status"] == {"open": 1, "acknowledged": 0, "in_progress": 1,
                                 "resolved": 0, "closed": 1}


def test_activity_span_min_max_over_lifecycle_stamps(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    s.create(_alert(dedup_key="d1", created_at="2026-06-01T08:00:00+00:00",
                    assigned_at="2026-06-01T09:30:00+00:00", resolved_at=""))
    s.create(_alert(dedup_key="d2", scenario_id="SCEN-2",
                    created_at="2026-06-01T10:00:00+00:00",
                    assigned_at="", resolved_at="2026-06-01T12:15:00+00:00"))
    lo, hi = s.activity_span()
    assert lo == "2026-06-01T08:00:00+00:00"
    assert hi == "2026-06-01T12:15:00+00:00"


def test_activity_span_ignores_empty_strings(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    s.create(_alert(dedup_key="d1", created_at="2026-06-01T08:00:00+00:00",
                    assigned_at="", resolved_at=""))
    lo, hi = s.activity_span()
    assert lo == "2026-06-01T08:00:00+00:00" and hi == "2026-06-01T08:00:00+00:00"


def test_activity_span_empty_store_is_none(tmp_path):
    s = AlertStore(connect(str(tmp_path / "a.db")))
    assert s.activity_span() == (None, None)
