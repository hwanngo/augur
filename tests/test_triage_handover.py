"""TDD: triage-handover diff pure helpers (infra-free, deterministic, read-only)."""
from augur.alerting.store import Alert, AlertEvent
from augur.api.triage_handover import diff_triage


def _alert(**kw):
    base = dict(dedup_key="SCEN-1|h", scenario_id="SCEN-1", scenario_name="Cred Theft",
                severity="CRITICAL", affected_hosts=["h"], proximity=0.6, band="WATCH",
                created_at="2026-06-01T08:00:00+00:00", updated_at="2026-06-01T08:00:00+00:00",
                id="a1", assignee="", status="open", assigned_at="", resolved_at="")
    base.update(kw)
    return Alert(**base)


def test_diff_triage_buckets_by_lifecycle_timestamp():
    win = dict(frm="2026-06-01T09:00:00+00:00", to="2026-06-01T18:00:00+00:00")
    alerts = [
        _alert(id="new", dedup_key="d-new", created_at="2026-06-01T10:00:00+00:00"),
        _alert(id="old", dedup_key="d-old", created_at="2026-06-01T07:00:00+00:00"),
        _alert(id="asg", dedup_key="d-asg", created_at="2026-06-01T07:00:00+00:00",
               assigned_at="2026-06-01T11:00:00+00:00", assignee="alice", status="in_progress"),
        _alert(id="res", dedup_key="d-res", created_at="2026-06-01T07:00:00+00:00",
               resolved_at="2026-06-01T12:00:00+00:00", status="resolved"),
    ]
    out = diff_triage(alerts, {}, **win)
    assert [r["alert_id"] for r in out["new_alerts"]] == ["new"]
    assert [r["alert_id"] for r in out["assigned"]] == ["asg"]
    assert out["assigned"][0]["assignee"] == "alice" and out["assigned"][0]["ts_field"] == "assigned_at"
    assert [r["alert_id"] for r in out["resolved"]] == ["res"]
    assert out["reopened"] == []


def test_diff_triage_window_is_inclusive_and_skips_empty_stamps():
    win = dict(frm="2026-06-01T09:00:00+00:00", to="2026-06-01T18:00:00+00:00")
    alerts = [
        _alert(id="edge", dedup_key="d-edge", created_at="2026-06-01T09:00:00+00:00"),
        _alert(id="noasg", dedup_key="d-noasg", created_at="2026-06-01T10:00:00+00:00", assigned_at=""),
    ]
    out = diff_triage(alerts, {}, **win)
    assert {r["alert_id"] for r in out["new_alerts"]} == {"edge", "noasg"}
    assert out["assigned"] == []


def test_diff_triage_assigned_and_resolved_same_window_appears_in_both():
    win = dict(frm="2026-06-01T09:00:00+00:00", to="2026-06-01T18:00:00+00:00")
    a = _alert(id="x", dedup_key="d-x", created_at="2026-06-01T07:00:00+00:00",
               assigned_at="2026-06-01T10:00:00+00:00", resolved_at="2026-06-01T11:00:00+00:00",
               status="resolved", assignee="bob")
    out = diff_triage([a], {}, **win)
    assert [r["alert_id"] for r in out["assigned"]] == ["x"]
    assert [r["alert_id"] for r in out["resolved"]] == ["x"]


def test_diff_triage_reopened_from_status_and_legacy_events():
    win = dict(frm="2026-06-01T09:00:00+00:00", to="2026-06-01T18:00:00+00:00")
    a = _alert(id="r", dedup_key="d-r", status="in_progress")
    events = {"r": [
        AlertEvent(alert_id="r", ts="2026-06-01T09:30:00+00:00", actor="x", event="status", detail="resolved", id=1),
        AlertEvent(alert_id="r", ts="2026-06-01T11:00:00+00:00", actor="x", event="status", detail="in_progress — reworking", id=2),
    ]}
    out = diff_triage([a], events, **win)
    assert [r["alert_id"] for r in out["reopened"]] == ["r"]
    assert out["reopened"][0]["ts"] == "2026-06-01T11:00:00+00:00"
    assert out["reopened"][0]["ts_field"] == "reopened"


def test_diff_triage_reopened_from_engine_auto_resolved():
    # Engine path: evaluator emits event="auto_resolved" (terminal, sets state=resolved), then the
    # threat reappears -> event="reopened". The terminal->non-terminal transition must surface.
    win = dict(frm="2026-06-01T09:00:00+00:00", to="2026-06-01T18:00:00+00:00")
    a = _alert(id="e", dedup_key="d-e", status="open")
    events = {"e": [
        AlertEvent(alert_id="e", ts="2026-06-01T09:30:00+00:00", actor="system", event="auto_resolved", detail="", id=1),
        AlertEvent(alert_id="e", ts="2026-06-01T11:00:00+00:00", actor="system", event="reopened", detail="", id=2),
    ]}
    out = diff_triage([a], events, **win)
    assert [r["alert_id"] for r in out["reopened"]] == ["e"]
    assert out["reopened"][0]["ts"] == "2026-06-01T11:00:00+00:00"


def test_diff_triage_no_reopen_when_never_terminal():
    win = dict(frm="2026-06-01T09:00:00+00:00", to="2026-06-01T18:00:00+00:00")
    a = _alert(id="n", dedup_key="d-n")
    events = {"n": [
        AlertEvent(alert_id="n", ts="2026-06-01T10:00:00+00:00", actor="x", event="status", detail="in_progress", id=1),
    ]}
    assert diff_triage([a], events, **win)["reopened"] == []


def test_diff_triage_ordering_by_ts_then_alert_id():
    win = dict(frm="2026-06-01T00:00:00+00:00", to="2026-06-01T23:00:00+00:00")
    alerts = [
        _alert(id="b", dedup_key="d-b", created_at="2026-06-01T10:00:00+00:00"),
        _alert(id="a", dedup_key="d-a", created_at="2026-06-01T10:00:00+00:00"),
        _alert(id="c", dedup_key="d-c", created_at="2026-06-01T08:00:00+00:00"),
    ]
    out = diff_triage(alerts, {}, **win)
    assert [r["alert_id"] for r in out["new_alerts"]] == ["c", "a", "b"]


def test_diff_triage_deterministic():
    win = dict(frm="2026-06-01T00:00:00+00:00", to="2026-06-01T23:00:00+00:00")
    alerts = [_alert(id="a", dedup_key="d", created_at="2026-06-01T10:00:00+00:00")]
    assert diff_triage(alerts, {}, **win) == diff_triage(alerts, {}, **win)


from augur.api.triage_handover import build_triage_handover


def test_build_triage_handover_envelope():
    a = _alert(id="new", dedup_key="d-new", created_at="2026-06-01T10:00:00+00:00")
    out = build_triage_handover([a], {}, from_iso="2026-06-01T09:00:00+00:00",
                                to_iso="2026-06-01T18:00:00+00:00")
    assert set(out) == {"window", "meta", "triage", "summary"}
    assert out["window"] == {"from": "2026-06-01T09:00:00+00:00", "to": "2026-06-01T18:00:00+00:00"}
    assert out["meta"] == {"basis": "alert-lifecycle-wallclock", "deterministic": True}
    assert set(out["triage"]) == {"new_alerts", "assigned", "resolved", "reopened"}
    assert out["summary"]["counts"]["new_alerts"] == 1


def test_build_triage_handover_empty_window_is_structural():
    out = build_triage_handover([], {}, from_iso=None, to_iso=None)
    assert out["window"] == {"from": None, "to": None}
    assert out["triage"] == {"new_alerts": [], "assigned": [], "resolved": [], "reopened": []}
    assert out["summary"]["counts"] == {"new_alerts": 0, "assigned": 0, "resolved": 0, "reopened": 0}
