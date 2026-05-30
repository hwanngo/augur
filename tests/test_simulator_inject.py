import pytest
from datetime import datetime, timezone
from augur.simulator.config import Injection
from augur.simulator.inject import validate_injection, render_injection
from augur.simulator.profiles import default_profiles
from augur.pipeline import default_scenarios, default_topology

BASE = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
SCEN = default_scenarios()
TOPO = default_topology()
PROFS = default_profiles()


def test_validate_rejects_unknown_scenario():
    with pytest.raises(ValueError, match="unknown scenario"):
        validate_injection(Injection(scenario_id="SCEN-NOPE", host="HR_User_PC"), PROFS, SCEN, TOPO)


def test_validate_rejects_unknown_host():
    with pytest.raises(ValueError, match="unknown host"):
        validate_injection(Injection(scenario_id="SCEN-WIN-001", host="NOPE"), PROFS, SCEN, TOPO)


def test_validate_rejects_non_windows_host():
    # CORP-JENKINS01 is a linux profile; v1 scenarios are Windows-only -> fail loud
    with pytest.raises(ValueError, match="Windows-only|os_family|linux"):
        validate_injection(Injection(scenario_id="SCEN-WIN-001", host="CORP-JENKINS01"), PROFS, SCEN, TOPO)


def test_render_injection_targets_host_and_offset():
    inj = Injection(scenario_id="SCEN-WIN-001", host="HR_User_PC", start_offset_seconds=1800)
    events = render_injection(inj, SCEN, TOPO, BASE)
    assert len(events) > 0
    assert all(e["host"] == "HR_User_PC" for e in events)
    assert all(e["source_type"] == "windows_sysmon" for e in events)
    first = min(datetime.fromisoformat(e["timestamp"]) for e in events)
    assert first == BASE.replace(minute=30)        # base + 1800s = 09:30


def test_injected_chain_fires_the_scenario():
    inj = Injection(scenario_id="SCEN-WIN-001", host="HR_User_PC", start_offset_seconds=60)
    events = render_injection(inj, SCEN, TOPO, BASE)
    from augur.normalize.registry import normalize_events
    from augur.graph.networkx_backend import NetworkXBackend
    from augur.graph.builder import build_graph
    from augur.engine.runner import run_engine
    backend = NetworkXBackend()
    build_graph(sorted(normalize_events(events), key=lambda e: e.timestamp), TOPO, backend)
    dets = {d.scenario_id: d for d in run_engine(backend, SCEN, min_proximity=0.0)}
    assert "SCEN-WIN-001" in dets and dets["SCEN-WIN-001"].proximity == 1.0
