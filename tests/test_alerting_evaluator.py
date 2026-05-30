from datetime import datetime, timezone
from dataclasses import replace
from augur.alerting.evaluator import evaluate, EvaluationResult
from augur.alerting.config import AlertConfig
from augur.engine.scoring import Detection

CFG = AlertConfig(min_proximity=0.6, auto_resolve_cycles=0)
T0 = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 1, 1, 9, 1, 0, tzinfo=timezone.utc)


def _det(p, hosts=("hostA",), sid="SCEN-1"):
    return Detection(scenario_id=sid, name="Cred Theft", severity="CRITICAL", proximity=p,
                     matched_steps=[{"step_id": 1}], missing_steps=[], affected_hosts=list(hosts),
                     affected_zones=["User_Endpoint"], hunting_queries=[{"engine": "KQL", "query": "x"}])


def test_new_detection_creates_open_alert():
    r = evaluate([_det(0.6)], {}, CFG, T0)
    assert len(r.created) == 1 and not r.escalated and not r.updated
    a = r.created[0]
    assert a.dedup_key == "SCEN-1|hostA" and a.state == "open" and a.band == "WATCH"
    assert a.notified_band == "WATCH" and a.count == 1 and a.first_seen == T0.isoformat()
    assert any(e.event == "created" for e in r.events)


def test_below_threshold_no_alert():
    assert evaluate([_det(0.45)], {}, CFG, T0).created == []


def test_same_band_updates_no_renotify():
    a = evaluate([_det(0.6)], {}, CFG, T0).created[0]
    a = replace(a, id="x1")
    r = evaluate([_det(0.7)], {a.dedup_key: a}, CFG, T1)   # still WATCH
    assert not r.created and not r.escalated and len(r.updated) == 1
    u = r.updated[0]
    assert u.count == 2 and u.proximity == 0.7 and u.band == "WATCH" and u.notified_band == "WATCH"
    assert u.last_seen == T1.isoformat()


def test_upward_band_cross_escalates_and_renotifies():
    a = replace(evaluate([_det(0.6)], {}, CFG, T0).created[0], id="x1")
    r = evaluate([_det(0.9)], {a.dedup_key: a}, CFG, T1)
    assert len(r.escalated) == 1 and not r.updated
    e = r.escalated[0]
    assert e.band == "HIGH" and e.notified_band == "HIGH"
    assert any(ev.event == "escalated" for ev in r.events)


def test_drop_does_not_lower_notified_band_or_renotify():
    a = replace(evaluate([_det(0.9)], {}, CFG, T0).created[0], id="x1")   # notified_band HIGH
    r = evaluate([_det(0.6)], {a.dedup_key: a}, CFG, T1)
    assert not r.escalated and len(r.updated) == 1
    u = r.updated[0]
    assert u.band == "WATCH" and u.notified_band == "HIGH"   # high-water mark preserved


def test_changed_host_set_is_a_new_alert():
    a = replace(evaluate([_det(0.6, hosts=("hostA",))], {}, CFG, T0).created[0], id="x1")
    r = evaluate([_det(0.6, hosts=("hostA", "hostB"))], {a.dedup_key: a}, CFG, T1)
    assert len(r.created) == 1 and r.created[0].dedup_key == "SCEN-1|hostA,hostB"


def test_auto_resolve_off_keeps_absent_alert_open():
    a = replace(evaluate([_det(0.6)], {}, CFG, T0).created[0], id="x1")
    r = evaluate([], {a.dedup_key: a}, CFG, T1)             # detection gone, auto_resolve off
    assert not r.resolved and len(r.updated) == 1 and r.updated[0].absent_cycles == 1
    assert r.updated[0].state == "open"


def test_auto_resolve_on_resolves_after_n_absent_cycles():
    cfg = AlertConfig(min_proximity=0.6, auto_resolve_cycles=2)
    a = replace(evaluate([_det(0.6)], {}, cfg, T0).created[0], id="x1")
    r1 = evaluate([], {a.dedup_key: a}, cfg, T1)            # absent_cycles -> 1, still open
    assert not r1.resolved and r1.updated[0].absent_cycles == 1
    a2 = replace(r1.updated[0])
    r2 = evaluate([], {a2.dedup_key: a2}, cfg, T1)          # absent_cycles -> 2 >= 2 -> resolved
    assert len(r2.resolved) == 1 and r2.resolved[0].state == "resolved"
    assert any(ev.event == "auto_resolved" for ev in r2.events)


def test_acknowledged_alert_auto_resolves_when_absent():
    """An 'acknowledged' alert (not just 'open') must auto-resolve after N absent cycles.
    The prior ack event remains in alert_events for audit; this is intentional by design."""
    cfg = AlertConfig(min_proximity=0.6, auto_resolve_cycles=1)
    # Build an alert in 'acknowledged' state
    r1 = evaluate([_det(0.6)], {}, cfg, T0)
    a = replace(r1.created[0], id="x1", state="acknowledged")
    # cycle 2: detection gone -> should auto-resolve even though state is 'acknowledged'
    r2 = evaluate([], {a.dedup_key: a}, cfg, T1)
    assert len(r2.resolved) == 1, f"expected auto-resolve, got resolved={r2.resolved}, updated={r2.updated}"
    assert r2.resolved[0].state == "resolved"
    assert any(e.event == "auto_resolved" for e in r2.events)


def test_reopen_produces_exactly_one_notification(tmp_path):
    """Reopen of a resolved alert must emit ONE reopened event and ONE escalated entry, zero 'escalated' events."""
    cfg = AlertConfig(min_proximity=0.6, auto_resolve_cycles=1)
    # cycle 1: create
    r1 = evaluate([_det(0.6)], {}, cfg, T0)
    a = replace(r1.created[0], id="x1")
    # cycle 2: no detection -> auto-resolves
    r2 = evaluate([], {a.dedup_key: a}, cfg, T1)
    assert len(r2.resolved) == 1
    resolved_alert = replace(r2.resolved[0])
    # cycle 3: detection reappears -> reopen
    r3 = evaluate([_det(0.6)], {resolved_alert.dedup_key: resolved_alert}, cfg, T1)
    assert len(r3.escalated) == 1,  f"expected 1 escalated (reopen), got {len(r3.escalated)}"
    assert len(r3.updated) == 0,    f"expected 0 updated, got {len(r3.updated)}"
    assert r3.escalated[0].state == "open"
    event_types = [e.event for e in r3.events]
    assert event_types.count("reopened") == 1, f"expected exactly 1 'reopened' event, got {event_types}"
    assert "escalated" not in event_types, f"expected no 'escalated' event on reopen, got {event_types}"


def test_purity_same_inputs_same_outputs():
    r1 = evaluate([_det(0.6)], {}, CFG, T0)
    r2 = evaluate([_det(0.6)], {}, CFG, T0)
    assert r1.created[0] == r2.created[0]   # dataclass equality; no wall-clock/random

    # Prove now is the ONLY time source: a run with a different injected clock must track it.
    r_t1 = evaluate([_det(0.6)], {}, CFG, T1)
    a_t0 = r1.created[0]
    a_t1 = r_t1.created[0]
    assert a_t1.first_seen == T1.isoformat(), "first_seen must track injected now (T1)"
    assert a_t1.last_seen  == T1.isoformat(), "last_seen must track injected now (T1)"
    assert a_t1.created_at == T1.isoformat(), "created_at must track injected now (T1)"
    assert a_t0.first_seen == T0.isoformat(), "first_seen must track injected now (T0)"
