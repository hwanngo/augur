import json
from pathlib import Path
from augur.scenarios.loader import load_scenarios
from augur.pipeline import default_topology
from augur.normalize.registry import normalize_events
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.engine.runner import run_engine
import scripts.regen_sample_data as regen


def test_regen_writes_native_tp_fixtures_that_fire(tmp_path):
    scns = load_scenarios("scenarios")
    out = tmp_path / "sample_data_v2"
    written = regen.regen_tp_fixtures("scenarios", str(out))
    assert len(written) == len(scns)
    topo = default_topology()
    by_id = {s.scenario_id: s for s in scns}
    for path in written:
        raws = [json.loads(l) for l in Path(path).read_text().strip().splitlines()]
        assert raws, f"empty fixture {path}"
        sid = raws[0].get("_scenario_id") or Path(path).name.replace("_tp.jsonl", "")
        # the fixture, normalized + run, fires its scenario at 1.0
        b = NetworkXBackend()
        build_graph(sorted(normalize_events([{k: v for k, v in r.items() if k != '_scenario_id'} for r in raws]),
                           key=lambda e: e.timestamp), topo, b)
        # find the scenario whose id is embedded in the filename
        scn = next(s for s in scns if path.endswith(f"{s.scenario_id}_tp.jsonl"))
        dets = {d.scenario_id: d for d in run_engine(b, [scn], min_proximity=0.0)}
        assert dets[scn.scenario_id].proximity == 1.0
