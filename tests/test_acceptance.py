import pytest
from augur.engine.runner import run_engine
from augur.pipeline import build_backend, default_topology, default_scenarios

SCN = default_scenarios()
TOPO = default_topology()
ANCHOR = "SCEN-WIN-001"  # Windows LSASS chain, fires 1.0 on HR_User_PC (User_Endpoint)


def _detections(path, min_proximity=0.30):
    backend = build_backend([path], TOPO)
    return {d.scenario_id: d for d in run_engine(backend, SCN, min_proximity=min_proximity)}


def test_true_positive_full_scenario():
    dets = _detections("sample_data/acceptance/full_detection.jsonl")
    assert ANCHOR in dets
    assert dets[ANCHOR].proximity == 1.0
    assert dets[ANCHOR].affected_hosts == ["HR_User_PC"]


def test_partial_scenario_proximity():
    dets = _detections("sample_data/acceptance/partial_detection.jsonl")
    assert dets[ANCHOR].proximity == 0.6667


def test_benign_does_not_fire():
    dets = _detections("sample_data/acceptance/no_detection_benign.jsonl")
    assert dets == {}  # nothing >= 0.30


def test_temporal_window_violation_is_partial_not_full():
    dets = _detections("sample_data/acceptance/no_detection_temporal_gap.jsonl")
    assert dets[ANCHOR].proximity == 0.6667  # a step suppressed by the window


def test_spatial_constraint_suppresses_detection():
    dets = _detections("sample_data/acceptance/no_detection_wrong_zone.jsonl")
    assert ANCHOR not in dets  # out-of-zone host cannot anchor


def test_demo_feed_has_multiple_ranked_detections():
    dets = _detections("sample_data/acceptance/demo_multi_os.jsonl")
    assert dets[ANCHOR].proximity == 1.0
    assert dets["SCEN-LNX-001"].proximity == 1.0
