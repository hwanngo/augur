from datetime import datetime, timezone
from augur.simulator.config import SimConfig, Injection
from augur.simulator.run import generate_feed
from augur.simulator.profiles import MachineProfile
from augur.pipeline import default_scenarios, default_topology
from augur.normalize.registry import normalize_events
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.engine.runner import run_engine

BASE = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
PROFS = [MachineProfile(host="CORP-JENKINS01", os_family="linux", users=["jenkins"]),
         MachineProfile(host="DESIGN-MBP-07", os_family="macos", users=["jsmith"]),
         MachineProfile(host="HR_User_PC", os_family="windows", users=["alice"])]


def test_multi_os_feed_fires_native_linux_and_macos_and_windows():
    cfg = SimConfig(seed=7, duration_seconds=3600, rate_per_minute=20, injections=[
        Injection(scenario_id="SCEN-LNX-001", host="CORP-JENKINS01", start_offset_seconds=300),
        Injection(scenario_id="SCEN-MAC-001", host="DESIGN-MBP-07", start_offset_seconds=600),
        Injection(scenario_id="SCEN-WIN-001", host="HR_User_PC", start_offset_seconds=900),
    ])
    raws = generate_feed(cfg, PROFS, default_scenarios(), default_topology(), BASE)
    # the three injections are in three different native formats
    assert {"linux_auditd", "macos_esf", "windows_sysmon"} <= {r.get("source_type") for r in raws}
    backend = NetworkXBackend()
    build_graph(sorted(normalize_events(raws), key=lambda e: e.timestamp), default_topology(), backend)
    fired = {d.scenario_id for d in run_engine(backend, default_scenarios(), min_proximity=0.30)}
    assert {"SCEN-LNX-001", "SCEN-MAC-001", "SCEN-WIN-001"} <= fired   # detection on all 3 OSes
