"""Purple-Team Drill helper.

Synthesizes a one-host MachineProfile from a topology asset, mirrors the simulator's
``generate_feed`` body (so it owns the baseline/injected counts), then runs the standard
read-only detection pipeline (``alerting.scan._detections_for``). Pure, deterministic,
no wall-clock, no persistence. The scoring path is imported and called unchanged.
"""
from dataclasses import asdict
from datetime import datetime, timezone

from augur.api.detections import _public
from augur.engine.runner import run_engine
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.metrics.coverage import _os_to_family
from augur.normalize.registry import normalize_events
from augur.simulator.baseline import generate_baseline
from augur.simulator.config import Injection, SimConfig
from augur.simulator.inject import render_injection, validate_injection
from augur.simulator.profiles import MachineProfile
from augur.simulator.timeline import merge

# Fixed simulator base-time — never wall-clock (Invariant 2). Mirrors simulator/run.py demos.
_BASE = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


def run_drill(scenario_id: str, host: str, scenarios, topology) -> dict:
    asset = topology.lookup(host)
    if asset is None:
        raise ValueError(f"unknown host: {host}")
    os_family = _os_to_family(asset.os)
    if os_family is None:  # [AUDIT #3] never pass None into the profile
        raise ValueError(f"host {host} OS not expressible: {asset.os!r}")
    # [AUDIT #4] all three fields required; users non-empty (baseline only uses it for benign users).
    profile = MachineProfile(host=host, os_family=os_family, users=["analyst"])
    injection = Injection(scenario_id=scenario_id, host=host, start_offset_seconds=0)
    config = SimConfig(injections=[injection], seed=1337, duration_seconds=3600, rate_per_minute=12)

    # [AUDIT #2] mirror generate_feed's body (call the PIECES) so we own both counts.
    # validate_injection raises ValueError on unknown scenario/host, OS mismatch, or wrong zone.
    validate_injection(injection, [profile], scenarios, topology)
    baseline = generate_baseline([profile], config, _BASE)
    injected = render_injection(injection, scenarios, topology, _BASE, os_family=os_family)
    raws = merge(baseline, injected)

    # Standard read-only pipeline (mirrors alerting.scan._detections_for).
    events = sorted(normalize_events(raws), key=lambda e: e.timestamp)
    backend = NetworkXBackend()
    build_graph(events, topology, backend)
    detections = [_public(asdict(d)) for d in run_engine(backend, scenarios, min_proximity=0.0)]

    detection = next((d for d in detections if d["scenario_id"] == scenario_id), None)
    return {
        "detection": detection,
        "feed_summary": {
            "total_events": len(raws),
            "baseline_events": len(baseline),
            "injected_events": len(injected),
        },
        "scenario_id": scenario_id,
        "host": host,
    }


def replay_detection(scenario_id: str, scenario_name: str, all_detections: list[dict]) -> dict:
    """Replay (not inject): return the real detection for ``scenario_id`` from the already-computed
    dashboard detection list over the loaded real corpus. The engine is NOT re-run here — this is the
    exact detection the Dashboard shows (``all_detections`` in the app closure).

    Honest: matched against real loaded telemetry, not a constructed proof. ``host`` is None (the
    capture decided where it fired, not a user); ``replay_hosts`` is the detection's affected_hosts;
    ``feed_summary`` is None (nothing was synthesized — honest absence, not faked zeros). If the
    scenario isn't present in the loaded capture, ``detection`` is None with an honest note (no 422)."""
    det = next((d for d in all_detections if d["scenario_id"] == scenario_id), None)
    replay_hosts = det["affected_hosts"] if det else []
    note = (
        "Replayed against loaded real telemetry (not synthesized) — this scenario "
        "matched the real capture at the proximity/host shown."
        if det else
        "Replayed against loaded real telemetry — this scenario is not present in the "
        "loaded capture."
    )
    return {
        "scenario_id": scenario_id,
        "host": None,
        "replay_hosts": replay_hosts,
        "detection": det,
        "feed_summary": None,
        "mode": "replay",
        "note": note,
    }
