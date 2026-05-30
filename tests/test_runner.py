from datetime import datetime, timedelta
from augur.engine.runner import run_engine
from augur.pipeline import build_backend, default_topology, default_scenarios
from tests.test_matcher import _full_lsass_chain  # reuse helper


def test_run_engine_detects_full_scenario(tmp_path):
    import json
    f = tmp_path / "tp.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in _full_lsass_chain()))
    backend = build_backend([str(f)], default_topology())
    detections = run_engine(backend, default_scenarios(), min_proximity=0.30)
    top = detections[0]
    assert top.scenario_id == "SCEN-WIN-001"
    assert top.proximity == 1.0
