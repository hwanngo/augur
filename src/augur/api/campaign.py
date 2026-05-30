"""Purple-Team Campaign & Detection-Validation Scorecard (additive, read-only, deterministic).

Batches the read-only Purple-Team Drill (run_drill) over a scenario subset and aggregates a
detection-validation scorecard. HONESTY: a 'detected' cell means the deterministic simulator's INJECTED
attack fired the scenario at/above the threshold on an eligible host — a regression + cross-technique
coverage + topology-gap check on the library+simulator, NOT a real-world detection-efficacy claim (a
scenario authored to be detectable detects its own emitter). The engine is untouched; run_drill only does
read-only engine runs over synthetic feeds.
"""
from augur.api.drill import run_drill
from augur.metrics.coverage import _os_to_family

CAMPAIGN_MAX_SCENARIOS = 50
HONESTY_NOTE = (
    "Detection validation against the deterministic simulator's INJECTED attacks — not a real-world "
    "efficacy claim. A scenario authored to be detectable detects its own emitter; a green scorecard is a "
    "regression + cross-technique coverage + topology-gap check, not evidence against a live adversary."
)


def _driving(scen):
    m = min(scen.scenario_metadata.mitre_mappings, key=lambda m: m.tactic)
    return m.tactic, m.technique


def _resolve(scenarios, *, scenario_ids, tactic, os_family):
    by_id = {s.scenario_id: s for s in scenarios}
    if scenario_ids:
        missing = [sid for sid in scenario_ids if sid not in by_id]
        if missing:
            raise ValueError(f"unknown scenario_id(s): {missing}")
        sel = [by_id[sid] for sid in scenario_ids]
    elif tactic:
        sel = [s for s in scenarios if any(m.tactic == tactic for m in s.scenario_metadata.mitre_mappings)]
    elif os_family:
        sel = [s for s in scenarios if s.os_family == os_family]
    else:
        sel = list(scenarios)
    return sorted(sel, key=lambda s: s.scenario_id)


def _pick_host(scen, topology):
    elig = [a for a in topology.assets
            if _os_to_family(a.os) == scen.os_family
            and a.zone.value in scen.spatial_constraints.applicable_zones]
    return min(elig, key=lambda a: a.hostname.lower()).hostname if elig else None


def build_campaign_scorecard(scenarios, topology, *, scenario_ids=None, tactic=None, os_family=None,
                             min_proximity=1.0, cap=CAMPAIGN_MAX_SCENARIOS) -> dict:
    resolved = _resolve(scenarios, scenario_ids=scenario_ids, tactic=tactic, os_family=os_family)
    if len(resolved) > cap:
        raise ValueError(f"campaign exceeds {cap}-scenario cap ({len(resolved)}); narrow the scope")

    rows = []
    for scen in resolved:
        ta, tech = _driving(scen)
        host = _pick_host(scen, topology)
        base = {"scenario_id": scen.scenario_id, "name": scen.name, "tactic": ta, "technique": tech,
                "os_family": scen.os_family, "host": host, "total_steps": scen.step_count}
        if host is None:
            rows.append({**base, "status": "no_eligible_host", "detected": False, "proximity": 0.0,
                         "matched_steps": 0, "feed_summary": None, "note": None})
            continue
        try:
            res = run_drill(scen.scenario_id, host, scenarios, topology)
        except ValueError as e:
            rows.append({**base, "status": "error", "detected": False, "proximity": 0.0,
                         "matched_steps": 0, "feed_summary": None, "note": str(e)})
            continue
        det = res["detection"]
        prox = det["proximity"] if det else 0.0
        matched = len(det["matched_steps"]) if det else 0
        detected = prox >= min_proximity
        rows.append({**base, "status": "detected" if detected else "missed", "detected": detected,
                     "proximity": round(prox, 4), "matched_steps": matched,
                     "feed_summary": res["feed_summary"], "note": None})

    runnable = [r for r in rows if r["status"] in ("detected", "missed")]
    detected_rows = [r for r in runnable if r["detected"]]
    missed_rows = [r for r in runnable if not r["detected"]]
    gaps_by_tactic: dict[str, list] = {}
    for r in sorted(missed_rows, key=lambda r: r["scenario_id"]):
        gaps_by_tactic.setdefault(r["tactic"], []).append(r["scenario_id"])
    no_host = sorted(r["scenario_id"] for r in rows if r["status"] == "no_eligible_host")
    selector = ("scenario_ids" if scenario_ids else "tactic" if tactic else "os_family" if os_family else "all")
    selector_value = (list(scenario_ids) if scenario_ids else tactic if tactic else os_family or None)
    return {
        "definition": {"selector": selector, "selector_value": selector_value,
                       "min_proximity": min_proximity, "scenario_count": len(resolved)},
        "rows": rows,
        "aggregate": {"runnable": len(runnable), "detected": len(detected_rows), "missed": len(missed_rows),
                      "no_eligible_host": len(no_host),
                      "errors": sum(1 for r in rows if r["status"] == "error"),
                      "pct_detected": round(len(detected_rows) / len(runnable), 4) if runnable else 0.0,
                      "gaps_by_tactic": gaps_by_tactic, "no_eligible_host_scenarios": no_host},
        "honesty": HONESTY_NOTE,
    }
