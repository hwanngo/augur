import json
from pathlib import Path
from augur.scenarios.loader import load_scenarios
from augur.pipeline import default_topology
from augur.normalize.registry import normalize_events
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.engine.runner import run_engine
import scripts.regen_sample_data as regen

SCNS = load_scenarios("scenarios")
TOPO = default_topology()
ANCHOR = "SCEN-WIN-001"


def _run(path):
    raws = [json.loads(l) for l in Path(path).read_text().strip().splitlines()]
    raws = [{k: v for k, v in r.items() if k != "_scenario_id"} for r in raws]
    b = NetworkXBackend()
    build_graph(sorted(normalize_events(raws), key=lambda e: e.timestamp), TOPO, b)
    return {d.scenario_id: d.proximity for d in run_engine(b, SCNS, min_proximity=0.0)}


def test_acceptance_fixtures_behave_per_name(tmp_path):
    out = tmp_path / "acceptance"
    regen.regen_acceptance("scenarios", str(out))
    tp = _run(out / "full_detection.jsonl")
    assert tp.get(ANCHOR) == 1.0
    partial = _run(out / "partial_detection.jsonl")
    assert 0 < partial.get(ANCHOR, 0) < 1.0
    benign = _run(out / "no_detection_benign.jsonl")
    assert all(p < 0.30 for p in benign.values()), f"benign fired: {benign}"
    temporal = _run(out / "no_detection_temporal_gap.jsonl")
    assert 0 < temporal.get(ANCHOR, 0) < 1.0           # one step suppressed by the window
    spatial = _run(out / "no_detection_wrong_zone.jsonl")
    assert ANCHOR not in spatial                        # out-of-zone host -> no match
    demo = _run(out / "demo_multi_os.jsonl")
    assert demo.get(ANCHOR) == 1.0 and len([k for k, v in demo.items() if v == 1.0]) >= 2
