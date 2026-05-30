from datetime import datetime, timezone, timedelta
from augur.engine.matcher import match_scenario, Candidate
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.normalize.ecs import normalize_events
from augur.topology.network import load_topology
from augur.scenarios.loader import load_scenario, load_scenarios

TOPO = load_topology("src/augur/topology/standard_topology.yaml")
SCN = {s.scenario_id: s for s in load_scenarios("scenarios")}


def _build(events):
    b = NetworkXBackend()
    evs = sorted(normalize_events(events), key=lambda e: e.timestamp)
    build_graph(evs, TOPO, b)
    return b


def _full_lsass_chain(host="HR_User_PC", t0="2026-05-01T10:00:00+00:00"):
    """SCEN-WIN-001 (3 steps): rundll32+comsvcs -> rundll32+MiniDump (<=60s) ->
    lsass access 0x1410 (<=120s), all same-host."""
    base = datetime.fromisoformat(t0)
    def iso(sec):
        return (base + timedelta(seconds=sec)).isoformat()
    return [
        {"timestamp": iso(0), "event_id": 1, "host": host, "process_guid": "p1",
         "process_name": "rundll32.exe", "process_path": "C:\\Windows\\System32\\rundll32.exe",
         "command_line": "rundll32 comsvcs.dll Minidump", "parent_process_name": "explorer.exe"},
        {"timestamp": iso(10), "event_id": 1, "host": host, "process_guid": "p2",
         "process_name": "rundll32.exe", "process_path": "C:\\Windows\\System32\\rundll32.exe",
         "command_line": "rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump 624 lsass.dmp full",
         "parent_process_guid": "p1", "parent_process_name": "rundll32.exe"},
        {"timestamp": iso(60), "event_id": "edr", "host": host, "process_guid": "p2",
         "behavior": "lsass_access", "target": "lsass.exe", "granted_access": "0x1410"},
    ]


def test_full_chain_matches_all_steps():
    b = _build(_full_lsass_chain())
    n, chain = match_scenario(SCN["SCEN-WIN-001"], b)
    assert n == 3
    assert len(chain) == 3


def test_partial_chain_returns_prefix_length():
    b = _build(_full_lsass_chain()[:2])   # steps 1-2 present only
    n, _ = match_scenario(SCN["SCEN-WIN-001"], b)
    assert n == 2


def test_temporal_window_violation_breaks_chain():
    evs = _full_lsass_chain()
    # push the step-3 lsass access far beyond the 120s window after step 2 (t=10s)
    evs[2]["timestamp"] = "2026-05-01T10:30:00+00:00"
    b = _build(evs)
    n, _ = match_scenario(SCN["SCEN-WIN-001"], b)
    assert n == 2


def test_spatial_constraint_suppresses_anchor():
    # DMZ host (Web_Server_01) is not in applicable_zones -> no anchor
    b = _build(_full_lsass_chain(host="Web_Server_01"))
    n, _ = match_scenario(SCN["SCEN-WIN-001"], b)
    assert n == 0


def test_unknown_host_cannot_anchor():
    b = _build(_full_lsass_chain(host="GHOST_HOST"))
    n, _ = match_scenario(SCN["SCEN-WIN-001"], b)
    assert n == 0
