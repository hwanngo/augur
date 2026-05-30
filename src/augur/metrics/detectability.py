"""Per-scenario detectability: can the engine detect its own synthesized traces?"""
from __future__ import annotations

from augur.generative.synth import synthesize_trace
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.normalize.registry import normalize_events
from augur.engine.runner import run_engine
from augur.scenarios.schema import Scenario
from augur.topology.network import Topology


def detectability(scenarios: list[Scenario], topology: Topology) -> dict:
    """For each scenario: synthesize a trace, run the engine, check proximity == 1.0.

    Returns:
        total: number of scenarios tested
        detectable: count that fired at proximity 1.0
        unsynthesizable: list[str] of scenario_ids synth returned None for
        partial: list[str] of scenario_ids that synthesized but fired < 1.0 (should be [])
        detectability_rate: detectable / total
    """
    detectable = 0
    unsynthesizable: list[str] = []
    partial: list[str] = []

    for scenario in scenarios:
        trace = synthesize_trace(scenario, topology)
        if trace is None:
            unsynthesizable.append(scenario.scenario_id)
            continue

        events = sorted(normalize_events(trace), key=lambda e: e.timestamp)
        backend = NetworkXBackend()
        build_graph(events, topology, backend)
        dets = {d.scenario_id: d for d in run_engine(backend, [scenario], min_proximity=0.0)}
        det = dets.get(scenario.scenario_id)

        if det is not None and det.proximity == 1.0:
            detectable += 1
        else:
            partial.append(scenario.scenario_id)

    total = len(scenarios)
    rate = round(detectable / total, 4) if total > 0 else 0.0

    return {
        "total": total,
        "detectable": detectable,
        "unsynthesizable": unsynthesizable,
        "partial": partial,
        "detectability_rate": rate,
    }
