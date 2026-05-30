"""Quality gate: every per-scenario true-positive fixture must match its scenario at 100%.

Convention: a fixture named ``sample_data/<category>/<SCENARIO_ID>_tp.jsonl`` is a
complete, realistic trace that should drive its scenario to proximity == 1.0. This keeps
the generated scenario library and its sample data provably consistent.
"""
import pathlib
import pytest

from augur.pipeline import build_backend, default_topology, default_scenarios
from augur.engine.runner import run_engine

TP_FILES = sorted(pathlib.Path("sample_data").rglob("*_tp.jsonl"))
_SCN = {s.scenario_id: s for s in default_scenarios()}
_TOPO = default_topology()


@pytest.mark.parametrize("tp", TP_FILES, ids=[f.stem for f in TP_FILES])
def test_tp_fixture_matches_its_scenario_fully(tp: pathlib.Path):
    scenario_id = tp.name[: -len("_tp.jsonl")]
    assert scenario_id in _SCN, f"{tp}: no scenario with id {scenario_id}"
    backend = build_backend([str(tp)], _TOPO)
    dets = {d.scenario_id: d for d in run_engine(backend, [_SCN[scenario_id]], min_proximity=0.0)}
    assert scenario_id in dets, f"{tp}: scenario {scenario_id} did not match at all"
    assert dets[scenario_id].proximity == 1.0, (
        f"{tp}: expected proximity 1.0 for {scenario_id}, got {dets[scenario_id].proximity}"
    )
