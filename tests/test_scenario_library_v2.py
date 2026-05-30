import re
from augur.scenarios.loader import load_scenarios
from augur.generative.synth import synthesize_trace
from augur.normalize.registry import normalize_events
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.engine.runner import run_engine
from augur.pipeline import default_topology

V2_DIR = "scenarios"
_ID = re.compile(r"^SCEN-(WIN|LNX|MAC|CLD)-\d{3}$")
TOPO = default_topology()


def _scns():
    return load_scenarios(V2_DIR)


def test_every_v2_scenario_well_formed():
    scns = _scns()
    assert len(scns) >= 4
    ids = [s.scenario_id for s in scns]
    assert len(ids) == len(set(ids)), "duplicate IDs"
    for s in scns:
        assert _ID.match(s.scenario_id), f"bad id {s.scenario_id}"
        assert s.os_family in ("windows", "linux", "macos"), s.scenario_id
        assert s.step_count >= 3 and len(s.scenario_metadata.mitre_mappings) >= 1


def test_v2_covers_all_14_tactics():
    from augur.metrics.coverage import TACTIC_NAMES
    tactics = set()
    for s in _scns():
        for m in s.scenario_metadata.mitre_mappings:
            tactics.add(m.tactic)
    missing = set(TACTIC_NAMES) - tactics
    assert not missing, f"v2 library must cover all 14 tactics; missing {sorted(missing)}"


def test_every_v2_scenario_synthesizes_and_fires_at_1():
    failures = []
    for s in _scns():
        tr = synthesize_trace(s, TOPO)
        if tr is None:
            failures.append((s.scenario_id, "unsynthesizable"))
            continue
        b = NetworkXBackend()
        build_graph(sorted(normalize_events(tr), key=lambda e: e.timestamp), TOPO, b)
        dets = {d.scenario_id: d for d in run_engine(b, [s], min_proximity=0.0)}
        p = dets[s.scenario_id].proximity if s.scenario_id in dets else 0.0
        if p != 1.0:
            failures.append((s.scenario_id, f"fires at {p}"))
    assert not failures, f"v2 scenarios must synthesize + fire at 1.0: {failures}"
