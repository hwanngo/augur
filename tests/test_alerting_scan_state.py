from datetime import datetime, timezone
from fastapi import FastAPI
from augur.auth.store import connect
from augur.auth.router import attach_auth
from augur.alerting.router import attach_alerting, scan_state

NOW = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


class _ListSource:
    def __init__(self, raws): self._raws = raws
    def read(self): return self._raws


def _astate(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    app = FastAPI()
    state = attach_auth(app)
    return attach_alerting(app, state, scan_source_path="sample_data/acceptance/full_detection.jsonl")


def test_scan_state_uses_configured_source(tmp_path, monkeypatch):
    astate = _astate(tmp_path, monkeypatch)
    counts = scan_state(astate, now=NOW)            # default source = scan_source_path
    assert counts["created"] >= 1
    assert any(a.scenario_id == "SCEN-WIN-001" for a in astate.alerts.list())


def test_scan_state_accepts_injected_source(tmp_path, monkeypatch):
    astate = _astate(tmp_path, monkeypatch)
    counts = scan_state(astate, now=NOW, source=_ListSource([]))   # empty override
    assert counts == {"created": 0, "escalated": 0, "updated": 0, "resolved": 0, "notified": 0}
