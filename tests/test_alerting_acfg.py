import json
from augur.auth.store import connect
from augur.alerting.acfg import AlertConfigStore, build_sink_factory


def test_config_store_seeds_defaults_and_updates(tmp_path, monkeypatch):
    monkeypatch.delenv("AUGUR_ALERT_MIN_PROXIMITY", raising=False)
    s = AlertConfigStore(connect(str(tmp_path / "c.db")))
    cfg = s.get()
    assert cfg["min_proximity"] == 0.6 and cfg["auto_resolve_cycles"] == 0
    assert cfg["rules"] == [] and cfg["sinks"] == {}
    s.put({"min_proximity": 0.8, "auto_resolve_cycles": 2,
           "rules": [{"min_severity": "CRITICAL", "min_proximity": None, "sinks": ["log"]}],
           "sinks": {"log": {"type": "jsonl", "path": str(tmp_path / "alerts.jsonl")}}})
    cfg2 = s.get()
    assert cfg2["min_proximity"] == 0.8 and cfg2["rules"][0]["sinks"] == ["log"]


def test_build_sink_factory_constructs_known_sinks(tmp_path):
    sinks_cfg = {"log": {"type": "jsonl", "path": str(tmp_path / "a.jsonl")}}
    factory = build_sink_factory(sinks_cfg)
    sink = factory("log")
    assert sink is not None and hasattr(sink, "emit")
    assert factory("missing") is None
