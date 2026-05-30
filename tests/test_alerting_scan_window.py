"""
TDD: trailing-time-window option for run_scan / scan_state.

Events in full_detection.jsonl are timestamped 2026-01-01T09:00:xx+00:00.
"""
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI

from augur.alerting.config import AlertConfig
from augur.alerting.router import attach_alerting, scan_state
from augur.alerting.scan import run_scan
from augur.alerting.store import AlertStore
from augur.auth.router import attach_auth
from augur.auth.store import connect
from augur.ingest.jsonl import read_jsonl

# events end at ~2026-01-01T09:00:10
_EVENT_END = datetime(2026, 1, 1, 9, 3, 0, tzinfo=timezone.utc)
# far future: events are clearly "old"
_FAR_FUTURE = datetime(2026, 5, 5, 0, 0, 0, tzinfo=timezone.utc)


class _ListSource:
    def __init__(self, raws):
        self._raws = raws

    def read(self):
        return self._raws


def _tp_source():
    return _ListSource(list(read_jsonl("sample_data/acceptance/full_detection.jsonl")))


def _store(tmp_path):
    return AlertStore(connect(str(tmp_path / "a.db")))


def _cfg():
    return AlertConfig(min_proximity=0.6, auto_resolve_cycles=0)


# ---------------------------------------------------------------------------
# run_scan window_seconds tests
# ---------------------------------------------------------------------------


def test_window_generous_events_inside(tmp_path):
    """now = just after events, window = 3600 s → events are within window → at least 1 alert created."""
    store = _store(tmp_path)
    counts = run_scan(
        store,
        _tp_source(),
        _cfg(),
        rules=[],
        sink_factory=dict().get,
        now=_EVENT_END,
        window_seconds=3600,
    )
    assert counts["created"] >= 1, f"expected >= 1 created (events in window), got {counts}"
    assert any(a.scenario_id == "SCEN-WIN-001" for a in store.list()), "SCEN-WIN-001 must be created"


def test_window_short_events_outside(tmp_path):
    """now = far future, window = 60 s → all events are old → nothing in graph → 0 created."""
    store = _store(tmp_path)
    counts = run_scan(
        store,
        _tp_source(),
        _cfg(),
        rules=[],
        sink_factory=dict().get,
        now=_FAR_FUTURE,
        window_seconds=60,
    )
    assert counts["created"] == 0, f"expected 0 created (events outside window), got {counts}"


def test_window_none_default_off(tmp_path):
    """window_seconds=None (default) + far-future now → no filtering → alert created.
    Proves the opt-in / default-off guarantee."""
    store = _store(tmp_path)
    # window_seconds omitted — uses default
    counts = run_scan(
        store,
        _tp_source(),
        _cfg(),
        rules=[],
        sink_factory=dict().get,
        now=_FAR_FUTURE,
    )
    assert counts["created"] >= 1, f"expected >= 1 created (no window), got {counts}"
    assert any(a.scenario_id == "SCEN-WIN-001" for a in store.list()), "SCEN-WIN-001 must be created"


def test_window_zero_is_default_off(tmp_path):
    """window_seconds=0 behaves identically to None (disabled)."""
    store = _store(tmp_path)
    counts = run_scan(
        store,
        _tp_source(),
        _cfg(),
        rules=[],
        sink_factory=dict().get,
        now=_FAR_FUTURE,
        window_seconds=0,
    )
    assert counts["created"] >= 1, f"expected >= 1 created (window=0 → disabled), got {counts}"
    assert any(a.scenario_id == "SCEN-WIN-001" for a in store.list()), "SCEN-WIN-001 must be created"


# ---------------------------------------------------------------------------
# scan_state env-var tests
# ---------------------------------------------------------------------------


def _astate(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    app = FastAPI()
    state = attach_auth(app)
    return attach_alerting(app, state, scan_source_path="sample_data/acceptance/full_detection.jsonl")


def test_scan_state_env_window_60_filters_old_events(tmp_path, monkeypatch):
    """AUGUR_SCAN_WINDOW_SECONDS=60 with far-future now → events filtered → created 0."""
    monkeypatch.setenv("AUGUR_SCAN_WINDOW_SECONDS", "60")
    astate = _astate(tmp_path, monkeypatch)
    counts = scan_state(astate, now=_FAR_FUTURE)
    assert counts["created"] == 0, (
        f"window=60 + far-future now should filter all old events, got {counts}"
    )


def test_scan_state_env_window_unset_no_filtering(tmp_path, monkeypatch):
    """AUGUR_SCAN_WINDOW_SECONDS unset (or 0) → no filtering → alert created."""
    monkeypatch.delenv("AUGUR_SCAN_WINDOW_SECONDS", raising=False)
    astate = _astate(tmp_path, monkeypatch)
    # Use a now just after the events so the scan runs normally
    counts = scan_state(astate, now=_EVENT_END)
    assert counts["created"] >= 1, f"no window → should create alert, got {counts}"


def test_scan_state_env_window_zero_no_filtering(tmp_path, monkeypatch):
    """AUGUR_SCAN_WINDOW_SECONDS=0 → disabled → alert created even with far-future now."""
    monkeypatch.setenv("AUGUR_SCAN_WINDOW_SECONDS", "0")
    astate = _astate(tmp_path, monkeypatch)
    counts = scan_state(astate, now=_FAR_FUTURE)
    assert counts["created"] >= 1, f"window=0 → disabled → should create alert, got {counts}"
