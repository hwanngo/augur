"""Detection Health — per-scenario liveness over the loaded corpus (additive, read-only, deterministic).

HONESTY CONTRACT: Health is computed over THIS loaded corpus only. SILENT/NEVER means the scenario did
not fire in this data — NOT that the detection is broken in production. 'Last fired' is a corpus
timestamp, not wall-clock. Fire-count is the number of growing-window snapshots in which the scenario
reached any proximity (a coarse liveness signal, NOT an alert volume).

Pure module. Imports ONLY the already-blessed read-only `windowed_detections` wrapper (which itself runs
the engine) and the cached `load_normalized` feed loader. It NEVER imports run_engine / scoring / matcher /
any normalizer, never reads wall-clock time, and uses no randomness. A static AST test enforces this.
"""
from datetime import datetime, timezone

from augur.api.detections import windowed_detections
from augur.api.feed import load_normalized

HEALTH_STATES = ("FIRING", "PARTIAL", "SILENT", "NEVER")
SWEEP_BUCKETS = 6          # number of growing-window snapshots across the corpus span

HONESTY_NOTE = (
    "Health is computed over THIS loaded corpus only. SILENT/NEVER means the scenario did not fire "
    "in this data — NOT that the detection is broken in production. 'Last fired' is a corpus timestamp, "
    "not wall-clock. Fire-count is the number of growing-window snapshots in which the scenario reached "
    "any proximity, a coarse liveness signal, NOT an alert volume. No scoring change, no ML, no now()."
)

# sort priority so problems float to the top
_STATE_ORDER = {"NEVER": 0, "SILENT": 1, "PARTIAL": 2, "FIRING": 3}


def _aware(ts: datetime) -> datetime:
    """Force tz-aware (assume-UTC for naive source timestamps) so min/max never raise."""
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)


def _scenario_row(s) -> dict:
    return {
        "scenario_id": s.scenario_id,
        "name": s.name,
        "severity": s.severity.value,
        "os_family": s.os_family,
        "tactics": [m.tactic for m in s.scenario_metadata.mitre_mappings],
    }


def compute_detection_health(log_paths, topology, scenarios) -> dict:
    rows: list[dict] = []
    stamps = [_aware(e.timestamp) for e in load_normalized(log_paths)]

    if not stamps:
        # Empty feed: every scenario NEVER, null span, no engine run.
        for s in sorted(scenarios, key=lambda x: x.scenario_id):
            base = _scenario_row(s)
            base.update(state="NEVER", max_proximity=0.0, fire_count=0,
                        last_fired=None, affected_host_count=0)
            rows.append(base)
        by_state = {st: sum(1 for r in rows if r["state"] == st) for st in HEALTH_STATES}
        return {
            "summary": {
                "scenarios_total": len(rows),
                "by_state": by_state,
                "corpus_span": {"from": None, "to": None},
                "sweep_buckets": SWEEP_BUCKETS,
                "honesty_note": HONESTY_NOTE,
            },
            "scenarios": rows,
        }

    span_min, span_max = min(stamps), max(stamps)

    # Growing-window sweep: SWEEP_BUCKETS upper bounds linearly spaced from span_min to span_max
    # (inclusive of span_max), frm fixed at span_min. Mirrors momentum.py's growing window.
    span = span_max - span_min
    bounds = [span_min + span * (i / SWEEP_BUCKETS) for i in range(1, SWEEP_BUCKETS + 1)]

    # Per bound: scenario_id -> proximity (each call returns ALL scenarios for that window).
    per_bound: list[dict[str, float]] = []
    for to_k in bounds:
        dets = windowed_detections(log_paths, topology, scenarios, frm=span_min, to=to_k)
        per_bound.append({d["scenario_id"]: round(d["proximity"], 4) for d in dets})

    # Final (authoritative) window is the largest bound == span_max.
    final = windowed_detections(log_paths, topology, scenarios, frm=span_min, to=span_max)
    final_by_id = {d["scenario_id"]: d for d in final}

    # fire_count = number of buckets in which the scenario appeared with proximity > 0.
    # max_proximity = max proximity seen across ALL buckets.
    fire_count: dict[str, int] = {}
    max_prox: dict[str, float] = {}
    for pb in per_bound:
        for sid, prox in pb.items():
            if prox > 0:
                fire_count[sid] = fire_count.get(sid, 0) + 1
            max_prox[sid] = max(max_prox.get(sid, 0.0), prox)

    for s in scenarios:
        sid = s.scenario_id
        base = _scenario_row(s)
        fc = fire_count.get(sid, 0)
        mp = round(max_prox.get(sid, 0.0), 4)
        final_det = final_by_id.get(sid)
        final_prox = round(final_det["proximity"], 4) if final_det else 0.0

        if final_prox >= 1.0:
            state = "FIRING"
        elif final_prox > 0.0:
            state = "PARTIAL"
        elif fc > 0:
            state = "SILENT"   # fired in some earlier bucket, gone in the final window
        else:
            state = "NEVER"

        # last_fired: latest matched_steps timestamp in the final window detection (corpus time).
        last_fired = None
        host_count = 0
        if final_det is not None:
            ts_list = [m["timestamp"] for m in final_det.get("matched_steps", [])
                       if m.get("timestamp")]
            last_fired = max(ts_list) if ts_list else None
            host_count = len(final_det.get("affected_hosts", []))

        base.update(state=state, max_proximity=mp, fire_count=fc,
                    last_fired=last_fired, affected_host_count=host_count)
        rows.append(base)

    rows.sort(key=lambda r: (_STATE_ORDER[r["state"]], r["scenario_id"]))
    by_state = {st: sum(1 for r in rows if r["state"] == st) for st in HEALTH_STATES}
    return {
        "summary": {
            "scenarios_total": len(rows),
            "by_state": by_state,
            "corpus_span": {"from": span_min.isoformat(), "to": span_max.isoformat()},
            "sweep_buckets": SWEEP_BUCKETS,
            "honesty_note": HONESTY_NOTE,
        },
        "scenarios": rows,
    }
