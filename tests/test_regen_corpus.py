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


def test_corpus_surfaces_its_manifest_and_nothing_benign(tmp_path):
    out = tmp_path / "corpus"
    manifest = regen.regen_corpus("scenarios", str(out))
    raws = [json.loads(l) for l in (out / "enterprise_day.jsonl").read_text().strip().splitlines()]
    raws = [{k: v for k, v in r.items() if k != "_scenario_id"} for r in raws]
    assert len(raws) > len(manifest["injections"])     # benign noise + injected attacks
    b = NetworkXBackend()
    build_graph(sorted(normalize_events(raws), key=lambda e: e.timestamp), TOPO, b)
    fired = {d.scenario_id for d in run_engine(b, SCNS, min_proximity=0.30)}
    planted = {inj["scenario_id"] for inj in manifest["injections"]}
    assert planted <= fired, f"planted attacks not all detected: {planted - fired}"
    # the written manifest.json matches
    saved = json.loads((out / "manifest.json").read_text())
    assert {i["scenario_id"] for i in saved["injections"]} == planted
