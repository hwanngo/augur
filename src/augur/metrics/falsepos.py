"""False-positive rate measurement against a benign corpus."""
from __future__ import annotations

from datetime import datetime, timezone

from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.normalize.registry import normalize_events
from augur.engine.runner import run_engine
from augur.scenarios.schema import Scenario
from augur.topology.network import Topology
from augur.simulator.baseline import generate_baseline
from augur.simulator.config import SimConfig
from augur.simulator.profiles import default_profiles

_BASE_TIME = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


def generate_benign_corpus(
    seed: int = 1234,
    duration_seconds: int = 14400,
    rate_per_minute: int = 60,
) -> list[dict]:
    """Deterministic multi-OS benign log feed via the simulator baseline.

    Uses a fixed base_time so repeated calls with the same seed are identical.
    """
    config = SimConfig(seed=seed, duration_seconds=duration_seconds, rate_per_minute=rate_per_minute)
    return generate_baseline(default_profiles(), config, _BASE_TIME)


def false_positive_rate(
    scenarios: list[Scenario],
    benign_raws: list[dict],
    topology: Topology,
    threshold: float = 0.30,
) -> dict:
    """Measure false-positive rate: how many detections fire on a purely benign corpus.

    Args:
        scenarios: Scenario objects to test against.
        benign_raws: Raw log dicts (pre-normalize).
        topology: Topology for graph enrichment.
        threshold: minimum proximity to count as a false positive.

    Returns dict with keys: benign_events, false_positives, fp_rate, fired_scenarios.
    """
    benign_count = len(benign_raws)
    if benign_count == 0:
        return {
            "benign_events": 0,
            "false_positives": 0,
            "fp_rate": 0.0,
            "fired_scenarios": [],
        }

    events = sorted(normalize_events(benign_raws), key=lambda e: e.timestamp)
    backend = NetworkXBackend()
    build_graph(events, topology, backend)

    # Run with min_proximity=0.0 so we catch everything, then filter by threshold
    all_detections = run_engine(backend, scenarios, min_proximity=0.0)
    fp_detections = [d for d in all_detections if d.proximity >= threshold]

    return {
        "benign_events": benign_count,
        "false_positives": len(fp_detections),
        "fp_rate": len(fp_detections) / benign_count,
        "fired_scenarios": sorted(d.scenario_id for d in fp_detections),
    }
