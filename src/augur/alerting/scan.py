from datetime import datetime, timedelta

from dataclasses import asdict

from augur.alerting.config import AlertConfig
from augur.alerting.evaluator import _dedup_key, evaluate
from augur.alerting.notify import route_notifications
from augur.alerting.store import AlertStore, apply_evaluation
from augur.engine.runner import run_engine
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.normalize.ecs import normalize_events
from augur.pipeline import default_scenarios, default_topology
from augur.tuning.apply import apply_allowlist, dedup_key


def record_proximity(scenario_id: str, proximity: float, ts: str) -> None:
    """F2 seam (DEFERRED): future per-scan proximity sampling for momentum (rising/flat/falling).

    Intentionally a no-op today — no storage, no env, no behaviour change. The future implementation
    will persist ``(scenario_id, proximity, ts)`` to a ``proximity_samples`` table so the UI can show
    a trend arrow; wiring it up is this one function, not a refactor of ``run_scan``.
    """
    return None


def _detections_for(source, scenarios, topology, *, now: datetime, window_seconds: float | None):
    """Returns (detections, backend). The backend is surfaced so FP-tuning regex predicates can read
    ProcessNode attributes without a second graph build."""
    raws = list(source.read())
    events = sorted(normalize_events(raws), key=lambda e: e.timestamp)
    if window_seconds:  # truthy and > 0
        cutoff = now - timedelta(seconds=window_seconds)
        events = [e for e in events if e.timestamp >= cutoff]
    backend = NetworkXBackend()
    build_graph(events, topology, backend)
    return run_engine(backend, scenarios, min_proximity=0.0), backend  # evaluator gates at alert threshold


def _public_detection(d) -> dict:
    return {k: v for k, v in asdict(d).items() if not k.startswith("_")}


def run_scan(store: AlertStore, source, config: AlertConfig, *, rules, sink_factory,
             now: datetime, scenarios=None, topology=None,
             window_seconds: float | None = None,
             tuning_store=None, technique_index=None) -> dict:
    scenarios = scenarios if scenarios is not None else default_scenarios()
    topology = topology if topology is not None else default_topology()
    detections, backend = _detections_for(source, scenarios, topology, now=now, window_seconds=window_seconds)

    # FP-tuning seam: when active allowlist entries exist, drop SUPPRESSED detections before they can
    # alert and pass DOWNGRADE band overrides into evaluate. With no tuning_store this is byte-identical.
    band_overrides: dict[str, str] = {}
    if tuning_store is not None and tuning_store.has_active(now=now):
        active = tuning_store.active_entries(now=now)
        res = apply_allowlist([_public_detection(d) for d in detections], active,
                              backend=backend, technique_index=technique_index or {})
        kept_keys = {dedup_key(k) for k in res.kept}
        detections = [d for d in detections if _dedup_key(d) in kept_keys]
        band_overrides = res.band_overrides

    for d in detections:  # F2 seam (deferred): record proximity momentum — no-op today
        record_proximity(d.scenario_id, d.proximity, now.isoformat())
    existing = {a.dedup_key: a for a in store.list()}
    result = evaluate(detections, existing, config, now, band_overrides=band_overrides)
    counts = apply_evaluation(store, result)
    det_by_key = {_dedup_key(d): d for d in detections}
    pairs = [(a, det_by_key[a.dedup_key]) for a in (result.created + result.escalated)
             if a.dedup_key in det_by_key]
    counts["notified"] = route_notifications(pairs, rules, sink_factory)
    return counts
