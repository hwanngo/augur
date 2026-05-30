"""End-to-end real-Sysmon T1003.001 LSASS-dump detection.

read fixture (genuine real-OTRF shape, UNTAGGED) -> normalize via the committed explicit
`normalize_real_sysmon_events` entry (NOT the source_type registry, which would route untagged events
to legacy) -> build_graph (upsert live) -> run_engine over scenarios_real/. The malicious
powershell->lsass 0x1010 access fires at proximity 1.0 CRITICAL on WORKSTATION5.theshire.local; the
benign svchost 0x1000/0x2000 accesses produce 0 false positives. Topology is the committed
OTRF-capture topology — the same path the real 6026-event run uses, only smaller.
"""
from augur.ingest.jsonl import read_jsonl
from augur.normalize.windows_sysmon_real import normalize_real_sysmon_events
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.scenarios.loader import load_scenarios
from augur.engine.runner import run_engine
from augur.enums import Severity
from augur.topology.network import load_topology

FIXTURE = "tests/fixtures/real/lsass_dump_min.jsonl"
TOPOLOGY = "datasets/real/topology_otrf_theshire.yaml"


def _detections():
    events = sorted(normalize_real_sysmon_events(read_jsonl(FIXTURE)), key=lambda e: e.timestamp)
    backend = NetworkXBackend()
    build_graph(events, load_topology(TOPOLOGY), backend)
    scenarios = load_scenarios("scenarios_real")
    return run_engine(backend, scenarios)


def test_fires_at_proximity_1_0_critical():
    dets = _detections()
    t1003 = [d for d in dets if d.scenario_id == "SCEN-REAL-WIN-T1003-001"]
    assert len(t1003) == 1, f"expected exactly one T1003 detection, got {dets}"
    d = t1003[0]
    assert d.proximity == 1.0
    assert d.severity == Severity.CRITICAL


def test_zero_false_positives_on_benign_svchost():
    # the T1003 scenario produces exactly one FULL detection — the malicious LSASS access; the two
    # benign svchost 0x1000/0x2000 accesses do not match it. (Other scenarios_real/ rules may produce
    # low-proximity partials over an unrelated fixture — e.g. the fodhelper 2-step's deliberately-broad
    # powershell step-1 — so this gate is scoped to the T1003 scenario + to fully-matched detections.)
    dets = _detections()
    full = [d for d in dets if d.proximity == 1.0]
    assert len(full) == 1
    assert full[0].scenario_id == "SCEN-REAL-WIN-T1003-001"


def test_detection_is_on_the_malicious_host():
    dets = _detections()
    d = [x for x in dets if x.scenario_id == "SCEN-REAL-WIN-T1003-001"][0]
    hosts = {h.lower() for h in d.affected_hosts}
    assert "workstation5.theshire.local" in hosts
