"""F2 seam (DEFERRED): ``record_proximity`` is a documented no-op called per-detection in run_scan.

These tests pin two invariants: the seam exists and is a true no-op (returns None, no error), and
``run_scan`` invokes it once per detection without otherwise changing behaviour.
"""
from datetime import datetime, timezone

from augur.auth.store import connect
from augur.alerting.store import AlertStore
from augur.alerting.config import AlertConfig
from augur.alerting import scan as scan_mod
from augur.alerting.scan import run_scan
from augur.ingest.jsonl import read_jsonl

NOW = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


class _ListSource:
    def __init__(self, raws):
        self._raws = raws

    def read(self):
        return self._raws


def _tp_source():
    return _ListSource(list(read_jsonl("sample_data/acceptance/full_detection.jsonl")))


def test_record_proximity_is_callable_noop():
    # the seam exists and is a no-op returning None (no storage, no side effect, no error)
    assert scan_mod.record_proximity("SCEN-WIN-001", 0.6667, "2026-01-01T00:00:00+00:00") is None


def test_run_scan_invokes_record_proximity_per_detection(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(scan_mod, "record_proximity",
                        lambda sid, prox, ts: seen.append((sid, prox, ts)))
    store = AlertStore(connect(str(tmp_path / "a.db")))
    cfg = AlertConfig(min_proximity=0.9, auto_resolve_cycles=0)
    counts = run_scan(store, _tp_source(), cfg, rules=[], sink_factory=dict().get, now=NOW)
    # run_scan behaviour unchanged: the TP fixture still creates exactly one alert
    assert counts["created"] == 1
    # the seam was called at least once (per detection), with the scenario id + a float proximity
    assert seen != []
    sids = {s for s, _, _ in seen}
    assert "SCEN-WIN-001" in sids
    assert all(isinstance(p, float) for _, p, _ in seen)


def test_run_scan_unchanged_when_seam_is_noop(tmp_path):
    # with the real no-op seam, run_scan produces the exact same counts as the existing scan test
    store = AlertStore(connect(str(tmp_path / "a.db")))
    cfg = AlertConfig(min_proximity=0.9, auto_resolve_cycles=0)
    counts = run_scan(store, _tp_source(), cfg, rules=[], sink_factory=dict().get, now=NOW)
    assert counts["created"] == 1 and counts["notified"] == 0
