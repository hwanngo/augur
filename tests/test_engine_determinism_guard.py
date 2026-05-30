"""Determinism guard [AUDIT #5] — the engine-intelligence work (F1/F3 enrichment, F2 seam) is
additive and read-only, so ``run_engine``'s proximity / matched_len / ranking must be byte-identical
to a recorded expectation. This pins the scoring path against accidental drift.
"""
from augur.engine.runner import run_engine
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.normalize.ecs import normalize_events
from augur.ingest.jsonl import read_jsonl
from augur.pipeline import default_scenarios, default_topology


def _run(path):
    raws = read_jsonl(path)
    events = sorted(normalize_events(raws), key=lambda e: e.timestamp)
    b = NetworkXBackend()
    build_graph(events, default_topology(), b)
    return run_engine(b, default_scenarios(), min_proximity=0.0)


def test_full_detection_scoring_is_byte_identical_to_recorded_expectation():
    # Recorded expectation over sample_data/acceptance/full_detection.jsonl (the engine-intel work
    # must not have shifted scoring): a single SCEN-WIN-001 detection, 3/3 matched, proximity 1.0.
    dets = _run("sample_data/acceptance/full_detection.jsonl")
    recorded = [(d.scenario_id, round(d.proximity, 4), len(d.matched_steps), len(d.missing_steps))
                for d in dets]
    assert recorded == [("SCEN-WIN-001", 1.0, 3, 0)]


def test_proximity_matched_len_and_ranking_are_stable():
    a = _run("sample_data/acceptance/full_detection.jsonl")
    b = _run("sample_data/acceptance/full_detection.jsonl")
    sig_a = [(d.scenario_id, d.proximity, len(d.matched_steps)) for d in a]
    sig_b = [(d.scenario_id, d.proximity, len(d.matched_steps)) for d in b]
    assert sig_a == sig_b
    # ranking order is identical run-to-run and independent of any F1/F3 enrichment
    assert [d.scenario_id for d in a] == [d.scenario_id for d in b]


def test_enterprise_corpus_scoring_is_deterministic():
    a = _run("sample_data/corpus/enterprise_day.jsonl")
    b = _run("sample_data/corpus/enterprise_day.jsonl")
    assert [(d.scenario_id, d.proximity, len(d.matched_steps)) for d in a] \
        == [(d.scenario_id, d.proximity, len(d.matched_steps)) for d in b]
    assert [d.scenario_id for d in a] == [d.scenario_id for d in b]
