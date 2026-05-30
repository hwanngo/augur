"""
TDD: per-window detections helper (mirrors test_alerting_scan_window.py).

Events in full_detection.jsonl are timestamped 2026-01-01T09:00:xx+00:00.
"""
from datetime import datetime, timezone

from augur.api.detections import windowed_detections
from augur.pipeline import default_scenarios, default_topology

_LOGS = ["sample_data/acceptance/full_detection.jsonl"]

# events span 2026-01-01T09:00:00 .. 09:00:10
_FROM_GENEROUS = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
_TO_GENEROUS = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

# window entirely before the events
_FROM_BEFORE = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_TO_BEFORE = datetime(2025, 1, 1, 1, 0, 0, tzinfo=timezone.utc)


def _topo():
    return default_topology()


def _scen():
    return default_scenarios()


def test_generous_window_fires_scen_win_001():
    """A generous [from,to] includes all events and fires SCEN-WIN-001 at proximity 1.0."""
    dets = windowed_detections(_LOGS, _topo(), _scen(), frm=_FROM_GENEROUS, to=_TO_GENEROUS)
    ids = [d["scenario_id"] for d in dets]
    assert "SCEN-WIN-001" in ids, f"SCEN-WIN-001 must fire, got {ids}"
    win = next(d for d in dets if d["scenario_id"] == "SCEN-WIN-001")
    assert win["proximity"] == 1.0, f"expected full detection, got {win['proximity']}"
    # _public strips private keys
    assert not any(k.startswith("_") for d in dets for k in d), "private keys must be stripped"


def test_window_before_events_is_empty():
    """A window entirely before the events returns no detections."""
    dets = windowed_detections(_LOGS, _topo(), _scen(), frm=_FROM_BEFORE, to=_TO_BEFORE)
    assert dets == [], f"expected empty, got {[d['scenario_id'] for d in dets]}"


def test_determinism_identical_bounds_identical_order():
    """Two calls with identical bounds produce identical scenario_id ordering (no wall-clock leak)."""
    a = windowed_detections(_LOGS, _topo(), _scen(), frm=_FROM_GENEROUS, to=_TO_GENEROUS)
    b = windowed_detections(_LOGS, _topo(), _scen(), frm=_FROM_GENEROUS, to=_TO_GENEROUS)
    assert [d["scenario_id"] for d in a] == [d["scenario_id"] for d in b]


# --- F3 (D1): stall enrichment folded into the once-per-window builder ---------------

_PARTIAL_LOGS = ["sample_data/acceptance/no_detection_temporal_gap.jsonl"]
_FROM_WIDE = datetime(2025, 1, 1, tzinfo=timezone.utc)
_TO_WIDE = datetime(2027, 1, 1, tzinfo=timezone.utc)


def test_partial_detection_carries_stall():
    dets = windowed_detections(_PARTIAL_LOGS, _topo(), _scen(), frm=_FROM_WIDE, to=_TO_WIDE)
    win = next(d for d in dets if d["scenario_id"] == "SCEN-WIN-001")
    assert 0 < win["proximity"] < 1.0
    assert "stall" in win and win["stall"] is not None
    assert win["stall"]["step_id"] == len(win["matched_steps"]) + 1
    assert win["stall"]["kind"] == "temporal"


def test_full_detection_has_no_stall():
    dets = windowed_detections(_LOGS, _topo(), _scen(), frm=_FROM_GENEROUS, to=_TO_GENEROUS)
    win = next(d for d in dets if d["scenario_id"] == "SCEN-WIN-001")
    assert win["proximity"] == 1.0
    assert "stall" not in win                      # absent for 100% (per spec)


def test_stall_enrichment_preserves_ranking_order():
    """[auditor binding] adding `stall` must not reorder the list run_engine already ranked."""
    dets = windowed_detections(_PARTIAL_LOGS, _topo(), _scen(), frm=_FROM_WIDE, to=_TO_WIDE)
    enriched_order = [d["scenario_id"] for d in dets]
    # the ranking is exactly run_engine's ranking — recompute it the raw way and compare.
    from augur.engine.runner import run_engine
    from augur.graph.builder import build_graph
    from augur.graph.networkx_backend import NetworkXBackend
    from augur.normalize.ecs import normalize_events
    from augur.ingest.jsonl import read_jsonl
    raws = []
    for p in _PARTIAL_LOGS:
        raws.extend(read_jsonl(p))
    events = sorted(normalize_events(raws), key=lambda e: e.timestamp)
    events = [e for e in events if _FROM_WIDE <= e.timestamp <= _TO_WIDE]
    b = NetworkXBackend()
    build_graph(events, _topo(), b)
    raw_order = [d.scenario_id for d in run_engine(b, _scen(), min_proximity=0.0)]
    assert enriched_order == raw_order
