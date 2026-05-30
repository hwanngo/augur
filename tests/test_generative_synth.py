import yaml
from augur.generative.synth import synthesize_trace
from augur.generative.fake import SAMPLE_VALID_YAML
from augur.scenarios.schema import Scenario
from augur.scenarios.loader import load_scenarios
from augur.pipeline import default_topology
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.normalize.ecs import normalize_events
from augur.engine.runner import run_engine


def _scores_full(scenario, events):
    b = NetworkXBackend()
    build_graph(sorted(normalize_events(events), key=lambda e: e.timestamp), default_topology(), b)
    dets = {d.scenario_id: d for d in run_engine(b, [scenario], min_proximity=0.0)}
    return dets.get(scenario.scenario_id)


def test_synthesizes_full_trace_for_fake_candidate():
    s = Scenario(**yaml.safe_load(SAMPLE_VALID_YAML))
    events = synthesize_trace(s, default_topology())
    assert events is not None
    det = _scores_full(s, events)
    assert det is not None and det.proximity == 1.0


def test_synthesizes_for_a_real_library_scenario():
    s = {x.scenario_id: x for x in load_scenarios("scenarios")}["SCEN-WIN-014"]
    events = synthesize_trace(s, default_topology())
    if events is not None:                        # if synthesizable, it must fire fully
        assert _scores_full(s, events).proximity == 1.0
