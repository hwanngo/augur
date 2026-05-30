from datetime import datetime, timezone
from augur.simulator.config import SimConfig, Injection
from augur.simulator.run import generate_feed
from augur.simulator.profiles import default_profiles
from augur.pipeline import default_scenarios, default_topology
from augur.normalize.registry import normalize_events
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.engine.runner import run_engine

BASE = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


def test_feed_with_injection_fires_only_that_scenario():
    cfg = SimConfig(seed=5, duration_seconds=3600, rate_per_minute=20,
                    injections=[Injection(scenario_id="SCEN-WIN-001", host="HR_User_PC",
                                          start_offset_seconds=600)])
    raws = generate_feed(cfg, default_profiles(), default_scenarios(), default_topology(), BASE)
    backend = NetworkXBackend()
    build_graph(sorted(normalize_events(raws), key=lambda e: e.timestamp), default_topology(), backend)
    dets = {d.scenario_id: d for d in run_engine(backend, default_scenarios(), min_proximity=0.30)}
    assert "SCEN-WIN-001" in dets and dets["SCEN-WIN-001"].proximity == 1.0


def test_invalid_injection_raises_before_generating():
    import pytest
    cfg = SimConfig(seed=5, duration_seconds=600, rate_per_minute=5,
                    injections=[Injection(scenario_id="SCEN-WIN-001", host="CORP-JENKINS01")])
    with pytest.raises(ValueError):
        generate_feed(cfg, default_profiles(), default_scenarios(), default_topology(), BASE)
