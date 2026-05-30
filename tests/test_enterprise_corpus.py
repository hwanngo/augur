"""The big 'enterprise day' corpus must surface every planted attack at 100%,
ranked above the partial/benign noise. Guards against regressions in realistic,
high-volume conditions (sample_data/corpus/enterprise_day.jsonl)."""
import json
from pathlib import Path
from augur.pipeline import build_backend, default_topology, default_scenarios
from augur.engine.runner import run_engine

CORPUS = "sample_data/corpus/enterprise_day.jsonl"
MANIFEST = "sample_data/corpus/manifest.json"
PLANTED = {
    inj["scenario_id"]
    for inj in json.loads(Path(MANIFEST).read_text())["injections"]
}


def test_corpus_surfaces_every_planted_attack_at_full_confidence():
    backend = build_backend([CORPUS], default_topology())
    ranked = run_engine(backend, default_scenarios(), min_proximity=0.30)
    dets = {d.scenario_id: d for d in ranked}
    for sid in PLANTED:
        assert sid in dets, f"{sid} not detected in enterprise corpus"
        assert dets[sid].proximity == 1.0, f"{sid} at {dets[sid].proximity}, expected 1.0"
    # the ranking puts a full-confidence detection first
    assert ranked[0].proximity == 1.0
