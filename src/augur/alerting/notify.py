import json
import logging

from augur.engine.scoring import Detection
from augur.enums import SEVERITY_RANK, Severity

_log = logging.getLogger("augur.alerting")


def rule_matches(alert, rule: dict) -> bool:
    min_sev = rule.get("min_severity")
    min_prox = rule.get("min_proximity")
    if min_sev is not None:
        try:
            alert_rank = SEVERITY_RANK.get(Severity(alert.severity), 0)
            rule_rank = SEVERITY_RANK.get(Severity(min_sev), 0)
        except ValueError:
            return False  # fail-closed: unknown severity → don't notify
        if alert_rank < rule_rank:
            return False
    if min_prox is not None and alert.proximity < min_prox:
        return False
    return True


def _sinks_for(alert, rules: list[dict]) -> list[str]:
    names: list[str] = []
    for rule in rules:
        if rule_matches(alert, rule):
            for name in rule.get("sinks", []):
                if name not in names:
                    names.append(name)
    return names


_SENTINEL = object()  # distinguishes "cached as None" from "not yet looked up"


def _detection_from_alert(alert) -> Detection:
    """Reconstruct a Detection from an Alert + its `detection_json` subset.

    `detection_json` only persists a subset (matched/missing steps, hunting queries,
    affected_zones); the remaining Detection fields are sourced from the Alert row.
    Used by notify-on-assign so the existing Sink.emit(detection) contract is satisfied
    without storing a full Detection. Best-effort — callers swallow failures.
    """
    sub = json.loads(alert.detection_json) if alert.detection_json else {}
    return Detection(
        scenario_id=alert.scenario_id,
        name=alert.scenario_name,
        severity=alert.severity,
        proximity=alert.proximity,
        matched_steps=sub.get("matched_steps", []),
        missing_steps=sub.get("missing_steps", []),
        affected_hosts=list(alert.affected_hosts),
        affected_zones=sub.get("affected_zones", []),
        hunting_queries=sub.get("hunting_queries", []),
    )


def notify_assignment(alert, rules: list[dict], sink_factory) -> int:
    """Best-effort notify-on-assign: route the alert's reconstructed Detection through sinks.

    Never raises. No-op (returns 0) when no rules/sinks are configured, keeping the default
    suite infra-free.
    """
    try:
        detection = _detection_from_alert(alert)
    except Exception as exc:  # reconstruction must never block the assign endpoint
        _log.warning("notify_assignment: detection reconstruction failed: %s", exc)
        return 0
    return route_notifications([(alert, detection)], rules, sink_factory)


def route_notifications(pairs, rules: list[dict], sink_factory) -> int:
    """pairs: list[(Alert, Detection)] to notify (created+escalated). Returns # delivered to >=1 sink.

    sink_factory(name) -> a Sink instance (or None). Per-sink failures are logged, never raised.
    Sinks that expose a close() method are closed in a finally block after the loop.
    """
    if not pairs or not rules:
        return 0
    cache: dict[str, object] = {}  # name -> sink instance, or _SENTINEL for unresolvable names
    notified = 0
    try:
        for alert, detection in pairs:
            delivered = False
            for name in _sinks_for(alert, rules):
                cached = cache.get(name, _SENTINEL)
                if cached is _SENTINEL:
                    sink = sink_factory(name)
                    cache[name] = sink  # may be None — avoids re-resolving on every alert
                    if sink is None:
                        continue
                else:
                    sink = cached
                    if sink is None:
                        continue
                try:
                    sink.emit(detection)
                    delivered = True
                except Exception as exc:           # one sink must never block the others
                    _log.warning("alert sink %r failed: %s", name, exc)
            if delivered:
                notified += 1
    finally:
        for s in cache.values():
            close = getattr(s, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
    return notified
