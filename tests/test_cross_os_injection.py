import pytest
from datetime import datetime, timezone
from augur.simulator.config import Injection
from augur.simulator.inject import validate_injection, render_injection
from augur.simulator.profiles import MachineProfile
from augur.pipeline import default_scenarios, default_topology
from augur.normalize.registry import normalize_events
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.engine.runner import run_engine

BASE = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
SCEN = default_scenarios()
TOPO = default_topology()
# profiles incl. a linux + macos + windows host that exist in the topology
PROFS = [MachineProfile(host="CORP-JENKINS01", os_family="linux", users=["jenkins"]),
         MachineProfile(host="DESIGN-MBP-07", os_family="macos", users=["jsmith"]),
         MachineProfile(host="HR_User_PC", os_family="windows", users=["alice"])]


def _fires(events, sid):
    b = NetworkXBackend()
    build_graph(sorted(normalize_events(events), key=lambda e: e.timestamp), TOPO, b)
    dets = {d.scenario_id: d for d in run_engine(b, SCEN, min_proximity=0.0)}
    return dets.get(sid)


def test_linux_scenario_fires_when_rendered_native_on_linux_host():
    inj = Injection(scenario_id="SCEN-LNX-001", host="CORP-JENKINS01", start_offset_seconds=60)
    validate_injection(inj, PROFS, SCEN, TOPO)            # ok
    events = render_injection(inj, SCEN, TOPO, BASE, os_family="linux")
    assert all(e["source_type"] == "linux_auditd" for e in events)   # NATIVE format
    det = _fires(events, "SCEN-LNX-001")
    assert det is not None and det.proximity == 1.0       # cross-OS DETECTION through the Linux normalizer


def test_macos_scenario_fires_when_rendered_native_on_macos_host():
    inj = Injection(scenario_id="SCEN-MAC-001", host="DESIGN-MBP-07", start_offset_seconds=60)
    validate_injection(inj, PROFS, SCEN, TOPO)
    events = render_injection(inj, SCEN, TOPO, BASE, os_family="macos")
    assert all(e["source_type"] == "macos_esf" for e in events)
    det = _fires(events, "SCEN-MAC-001")
    assert det is not None and det.proximity == 1.0


def test_os_mismatch_is_rejected():
    with pytest.raises(ValueError, match="os|cannot be injected"):
        validate_injection(Injection(scenario_id="SCEN-LNX-001", host="HR_User_PC"), PROFS, SCEN, TOPO)
    with pytest.raises(ValueError, match="os|cannot be injected"):
        validate_injection(Injection(scenario_id="SCEN-WIN-001", host="CORP-JENKINS01"), PROFS, SCEN, TOPO)


def test_windows_injection_still_works_default_os():
    # regression: the existing Windows path (default os_family) still fires at 1.0
    inj = Injection(scenario_id="SCEN-WIN-001", host="HR_User_PC", start_offset_seconds=60)
    validate_injection(inj, PROFS, SCEN, TOPO)
    events = render_injection(inj, SCEN, TOPO, BASE)       # default os_family="windows"
    assert all(e["source_type"] == "windows_sysmon" for e in events)
    assert _fires(events, "SCEN-WIN-001").proximity == 1.0
