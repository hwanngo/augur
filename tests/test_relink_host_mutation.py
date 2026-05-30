import pytest

from augur.enums import Criticality
from augur.generative.synth import synthesize_trace
from augur.metrics.mutations import relink_host
from augur.pipeline import default_scenarios, default_topology


def _scenario(scenario_id: str):
    for s in default_scenarios():
        if s.scenario_id == scenario_id:
            return s
    raise AssertionError(f"scenario {scenario_id} not found")


def _eligible_hosts(scenario, topology):
    """Topology-order eligible hostnames, deduped — mirrors the synth's own
    `_pick_hosts` (`ok[:2]`) so `eligible[0]` is the synth's base host h0."""
    sc = scenario.spatial_constraints
    out: list[str] = []
    for a in topology.assets:
        if (a.zone.value in sc.applicable_zones
                and (not sc.critical_assets_only or a.criticality == Criticality.CRITICAL)
                and a.hostname not in out):
            out.append(a.hostname)
    return out


def test_relink_host_moves_step_k_to_end_onto_h1():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    trace = synthesize_trace(sc, topo)
    assert trace is not None
    n = sc.step_count
    k = n  # last step

    eligible = _eligible_hosts(sc, topo)
    assert len(eligible) >= 2, "SCEN-WIN-001 must have a distinct second eligible host"

    mutated, h1 = relink_host(trace, sc, topo, k)
    assert h1 is not None
    assert h1 != eligible[0]  # h1 is the SECOND eligible host, distinct from h0

    moved_guids = {f"syn-p{sid}" for sid in range(k, n + 1)}
    # every step k..end event now lives on h1
    for e in mutated:
        if e.get("process_guid") in moved_guids:
            assert e["host"] == h1
        else:
            # earlier steps stay on h0 (the first eligible host)
            assert e["host"] == eligible[0]


def test_relink_host_is_pure_input_untouched():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    trace = synthesize_trace(sc, topo)
    n = sc.step_count
    before = [dict(e) for e in trace]

    mutated, h1 = relink_host(trace, sc, topo, n)
    assert h1 is not None
    # original list is byte-identical after mutation (deepcopy semantics)
    assert trace == before
    # mutated is a different object graph
    assert mutated is not trace


def test_relink_host_rejects_step_below_2():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    trace = synthesize_trace(sc, topo)
    with pytest.raises(ValueError):
        relink_host(trace, sc, topo, 1)
    with pytest.raises(ValueError):
        relink_host(trace, sc, topo, 0)


def test_relink_host_rejects_out_of_range():
    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    trace = synthesize_trace(sc, topo)
    with pytest.raises(ValueError):
        relink_host(trace, sc, topo, sc.step_count + 1)


def test_relink_host_single_eligible_host_returns_none():
    """When the topology offers only ONE eligible host, h0 == h1: no distinct
    second host, so the mutator returns (copy, None) — mirrors relocate_zone's
    no_offzone_host fallback."""
    from augur.topology.network import Topology

    topo = default_topology()
    sc = _scenario("SCEN-WIN-001")
    trace = synthesize_trace(sc, topo)

    # Build a single-asset topology in the scenario's applicable zone so exactly
    # one host is eligible.
    sc_zones = sc.spatial_constraints.applicable_zones
    one_asset = next(a for a in topo.assets if a.zone.value in sc_zones
                     and (not sc.spatial_constraints.critical_assets_only
                          or a.criticality == Criticality.CRITICAL))
    solo_topo = Topology(zones=topo.zones, assets=[one_asset])

    mutated, h1 = relink_host(trace, sc, solo_topo, sc.step_count)
    assert h1 is None
    # returns a copy, not the original object
    assert mutated is not trace
    assert mutated == trace
