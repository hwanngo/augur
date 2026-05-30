import json
from dataclasses import dataclass, field, replace
from datetime import datetime

from augur.alerting.bands import band_for, band_rank
from augur.alerting.config import AlertConfig
from augur.alerting.store import Alert, AlertEvent
from augur.engine.scoring import Detection


@dataclass
class EvaluationResult:
    created: list[Alert] = field(default_factory=list)
    escalated: list[Alert] = field(default_factory=list)
    updated: list[Alert] = field(default_factory=list)
    resolved: list[Alert] = field(default_factory=list)
    events: list[AlertEvent] = field(default_factory=list)


def _dedup_key(d: Detection) -> str:
    return d.scenario_id + "|" + ",".join(sorted(d.affected_hosts))


def _detection_json(d: Detection) -> str:
    return json.dumps({"matched_steps": d.matched_steps, "missing_steps": d.missing_steps,
                       "hunting_queries": d.hunting_queries, "affected_zones": d.affected_zones})


def evaluate(detections: list[Detection], existing: dict[str, Alert],
             config: AlertConfig, now: datetime,
             band_overrides: dict[str, str] | None = None) -> EvaluationResult:
    """Pure: detections + prior alert state + config + injected clock -> desired deltas.

    ``band_overrides`` (dedup_key -> band) is the FP-tuning DOWNGRADE seam: a per-detection band
    floor applied instead of ``band_for(proximity)``. Empty/None (the default) is byte-identical to
    the pre-tuning behavior — proximity itself is never mutated."""
    band_overrides = band_overrides or {}
    now_iso = now.isoformat()
    res = EvaluationResult()
    seen: set[str] = set()

    # Deterministic order: by (scenario_id, sorted hosts).
    for d in sorted(detections, key=lambda x: (x.scenario_id, tuple(sorted(x.affected_hosts)))):
        if d.proximity < config.min_proximity:
            continue
        key = _dedup_key(d)
        if key in seen:
            continue
        seen.add(key)
        band = band_overrides.get(key) or band_for(d.proximity)
        det_json = _detection_json(d)
        prior = existing.get(key)

        if prior is None:
            a = Alert(dedup_key=key, scenario_id=d.scenario_id, scenario_name=d.name, severity=d.severity,
                      affected_hosts=sorted(d.affected_hosts), proximity=d.proximity, band=band,
                      state="open", first_seen=now_iso, last_seen=now_iso, count=1, absent_cycles=0,
                      notified_band=band, detection_json=det_json, created_at=now_iso, updated_at=now_iso)
            res.created.append(a)
            res.events.append(AlertEvent(alert_id=a.id, ts=now_iso, actor="system", event="created",
                                         detail=f"{band} p={d.proximity}"))
            continue

        a = replace(prior, scenario_name=d.name, severity=d.severity,
                    affected_hosts=sorted(d.affected_hosts), proximity=d.proximity, band=band,
                    last_seen=now_iso, count=prior.count + 1, absent_cycles=0,
                    detection_json=det_json, updated_at=now_iso)
        if prior.state == "resolved":     # reappearance -> reopen + renotify (active once 3d resolves)
            a.state = "open"
            a.notified_band = band        # (re)notifying at this band now
            a.absent_cycles = 0
            res.escalated.append(a)       # reopen always renotifies (consumed by notify in 3b)
            res.events.append(AlertEvent(alert_id=a.id, ts=now_iso, actor="system", event="reopened",
                                         detail=f"{band} p={d.proximity}"))
            continue                      # skip the normal escalation/updated branch below
        if band_rank(band) > band_rank(a.notified_band):
            a.notified_band = band
            res.escalated.append(a)
            res.events.append(AlertEvent(alert_id=a.id, ts=now_iso, actor="system", event="escalated",
                                         detail=f"-> {band} p={d.proximity}"))
        else:
            res.updated.append(a)

    # Alerts whose detection did not appear this cycle.
    # Intentional: auto-resolve applies to both 'open' AND 'acknowledged' alerts; a vanished threat
    # is resolved regardless of acknowledgement state. The prior 'ack' event stays in alert_events for audit.
    for key, prior in existing.items():
        if key in seen or prior.state == "resolved":
            continue
        absent = prior.absent_cycles + 1
        a = replace(prior, absent_cycles=absent, updated_at=now_iso, affected_hosts=list(prior.affected_hosts))
        if config.auto_resolve_cycles > 0 and absent >= config.auto_resolve_cycles:
            a.state = "resolved"
            res.resolved.append(a)
            res.events.append(AlertEvent(alert_id=a.id, ts=now_iso, actor="system", event="auto_resolved",
                                         detail=f"absent {absent} cycles"))
        else:
            res.updated.append(a)
    return res
