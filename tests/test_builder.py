from datetime import datetime, timezone
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.normalize.ecs import normalize_events
from augur.topology.network import load_topology
from augur.enums import Zone, Criticality

TOPO = load_topology("src/augur/topology/standard_topology.yaml")


def _events():
    return normalize_events([
        {"timestamp": "2026-05-01T10:00:00+00:00", "event_id": 1, "host": "HR_User_PC", "user": "a",
         "process_guid": "p1", "process_name": "rundll32.exe", "process_path": "C:\\Windows\\rundll32.exe",
         "command_line": "rundll32 x", "parent_process_guid": "p0", "parent_process_name": "evil.exe"},
        {"timestamp": "2026-05-01T10:00:05+00:00", "event_id": 7, "host": "HR_User_PC",
         "process_guid": "p1", "image_loaded": "C:\\x\\evil.dll", "signed": False, "is_injected": True},
        {"timestamp": "2026-05-01T10:00:10+00:00", "event_id": "edr", "host": "HR_User_PC",
         "process_guid": "p1", "behavior": "lsass_access", "target": "lsass.exe", "granted_access": "0x1410"},
        {"timestamp": "2026-05-01T10:00:00+00:00", "event_id": 1, "host": "UNKNOWN_BOX", "user": "x",
         "process_guid": "pX", "process_name": "a.exe", "process_path": "C:\\a.exe", "command_line": "a"},
    ])


def test_builds_nodes_and_edges_with_enrichment():
    b = NetworkXBackend()
    build_graph(_events(), TOPO, b)
    host = b.host_of("p1")
    assert host.zone == Zone.User_Endpoint and host.criticality == Criticality.MEDIUM
    procs = b.find_nodes("Process", lambda n: n.id == "p1")
    assert procs[0].timestamp == datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc)
    files = b.find_nodes("File", lambda n: True)
    assert files[0].is_injected is True and files[0].extension == ".dll"
    exhibited = b.edges_from("p1", "EXHIBITED")
    assert exhibited[0].attrs["target"] == "lsass.exe"


def test_unknown_host_gets_unknown_zone():
    b = NetworkXBackend()
    build_graph(_events(), TOPO, b)
    host = b.host_of("pX")
    assert host.zone == Zone.Unknown and host.criticality == Criticality.UNKNOWN
