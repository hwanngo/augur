from datetime import datetime, timezone
from augur.auth.store import connect
from augur.alerting.store import AlertStore
from augur.alerting.config import AlertConfig
from augur.alerting.scan import run_scan
from augur.ingest.jsonl import read_jsonl

NOW = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


class _ListSource:
    def __init__(self, raws): self._raws = raws
    def read(self): return self._raws


def _tp_source():
    # the acceptance true-positive fixture fires SCEN-WIN-001 at proximity 1.0
    return _ListSource(list(read_jsonl("sample_data/acceptance/full_detection.jsonl")))


def test_scan_creates_alert_from_detections(tmp_path):
    store = AlertStore(connect(str(tmp_path / "a.db")))
    cfg = AlertConfig(min_proximity=0.9, auto_resolve_cycles=0)   # 0.9 isolates SCEN-WIN-001 at 1.0
    counts = run_scan(store, _tp_source(), cfg, rules=[], sink_factory=dict().get, now=NOW)
    assert counts["created"] == 1 and counts["notified"] == 0     # no sinks configured
    a = store.list()[0]
    assert a.scenario_id == "SCEN-WIN-001" and a.proximity == 1.0 and a.band == "CONFIRMED"


def test_scan_notifies_via_sink(tmp_path):
    store = AlertStore(connect(str(tmp_path / "a.db")))
    cfg = AlertConfig(min_proximity=0.9, auto_resolve_cycles=0)   # 0.9 isolates SCEN-WIN-001 at 1.0
    emitted = []

    class FakeSink:
        def emit(self, d): emitted.append(d)

    rules = [{"min_severity": None, "min_proximity": None, "sinks": ["fake"]}]
    counts = run_scan(store, _tp_source(), cfg, rules=rules,
                      sink_factory={"fake": FakeSink()}.get, now=NOW)
    assert counts["created"] == 1 and counts["notified"] == 1 and len(emitted) == 1


def test_scan_empty_source_no_alert(tmp_path):
    store = AlertStore(connect(str(tmp_path / "a.db")))
    cfg = AlertConfig(min_proximity=0.6, auto_resolve_cycles=0)
    counts = run_scan(store, _ListSource([]), cfg, rules=[], sink_factory=dict().get, now=NOW)
    assert counts == {"created": 0, "escalated": 0, "updated": 0, "resolved": 0, "notified": 0}
