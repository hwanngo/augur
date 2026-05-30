from augur.scenarios.loader import load_scenarios
from augur.pipeline import default_topology
from augur.generative.synth import synthesize_trace
from augur.normalize.registry import normalize_events
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.engine.runner import run_engine

SCN = {s.scenario_id: s for s in load_scenarios("scenarios")}


def test_native_scenarios_loaded_with_os_family():
    lx = SCN["SCEN-LNX-001"]
    mac = SCN["SCEN-MAC-001"]
    assert lx.os_family == "linux" and mac.os_family == "macos"
    assert lx.step_count >= 3 and mac.step_count >= 3


def test_macos_host_in_topology():
    zone, _ = default_topology().enrich("DESIGN-MBP-07")
    assert zone.value == "User_Endpoint"


def test_native_scenarios_self_fire():
    topo = default_topology()
    for sid in ("SCEN-LNX-001", "SCEN-MAC-001"):
        s = SCN[sid]
        tr = synthesize_trace(s, topo)
        assert tr is not None
        b = NetworkXBackend()
        build_graph(sorted(normalize_events(tr), key=lambda e: e.timestamp), topo, b)
        dets = {d.scenario_id: d for d in run_engine(b, [s], min_proximity=0.0)}
        assert dets[sid].proximity == 1.0
