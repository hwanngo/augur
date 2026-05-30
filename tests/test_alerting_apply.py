from datetime import datetime, timezone
from dataclasses import replace
from augur.auth.store import connect
from augur.alerting.store import AlertStore, apply_evaluation
from augur.alerting.evaluator import evaluate
from augur.alerting.config import AlertConfig
from augur.engine.scoring import Detection

CFG = AlertConfig(min_proximity=0.6, auto_resolve_cycles=0)
T0 = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 1, 1, 9, 1, tzinfo=timezone.utc)


def _det(p, hosts=("hostA",)):
    return Detection(scenario_id="SCEN-1", name="Cred Theft", severity="CRITICAL", proximity=p,
                     matched_steps=[], missing_steps=[], affected_hosts=list(hosts),
                     affected_zones=[], hunting_queries=[])


def _load_existing(store):
    return {a.dedup_key: a for a in store.list()}


def test_apply_creates_then_escalates_one_alert(tmp_path):
    store = AlertStore(connect(str(tmp_path / "a.db")))
    # cycle 1: create
    counts = apply_evaluation(store, evaluate([_det(0.6)], _load_existing(store), CFG, T0))
    assert counts == {"created": 1, "escalated": 0, "updated": 0, "resolved": 0}
    a = store.get_by_dedup_key("SCEN-1|hostA")
    assert a.band == "WATCH" and a.count == 1
    assert [e.event for e in store.list_events(a.id)] == ["created"]
    # cycle 2: escalate (same alert)
    counts = apply_evaluation(store, evaluate([_det(0.9)], _load_existing(store), CFG, T1))
    assert counts == {"created": 0, "escalated": 1, "updated": 0, "resolved": 0}
    a2 = store.get_by_dedup_key("SCEN-1|hostA")
    assert a2.id == a.id and a2.band == "HIGH" and a2.count == 2 and a2.notified_band == "HIGH"
    assert "escalated" in [e.event for e in store.list_events(a.id)]
    assert len(store.list()) == 1   # not a duplicate row


def test_apply_auto_resolve(tmp_path):
    cfg = AlertConfig(min_proximity=0.6, auto_resolve_cycles=1)
    store = AlertStore(connect(str(tmp_path / "a.db")))
    apply_evaluation(store, evaluate([_det(0.6)], _load_existing(store), cfg, T0))
    counts = apply_evaluation(store, evaluate([], _load_existing(store), cfg, T1))
    assert counts["resolved"] == 1
    assert store.get_by_dedup_key("SCEN-1|hostA").state == "resolved"
