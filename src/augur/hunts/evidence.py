"""Live hunt evidence — deterministic, read-only reuse of the engine's windowed detections.

NO persistence, NO engine change. The evidence is recomputed on every read so a saved hunt can never
show a stale proximity as current (honesty invariant). Filters + reshapes the public detection dicts the
existing windowed pipeline already produces (incl. the `stall` near-miss and the next-step enrichment).
"""

HONESTY_NOTE = (
    "Engine evidence is recomputed live from the deterministic engine over your scope — never a stored "
    "snapshot. The workbench records your hypothesis, verdict and notes; it does not auto-conclude."
)


def _matches_tactic(scen, tactic_lc: str) -> bool:
    return any((m.tactic or "").strip().lower() == tactic_lc
               for m in scen.scenario_metadata.mitre_mappings)


def scenario_ids_for_scope(scope: dict, scenarios) -> set | None:
    ids = set(scope.get("scenario_ids") or [])
    tactic = (scope.get("tactic") or "").strip().lower()
    if tactic:
        ids |= {s.scenario_id for s in scenarios if _matches_tactic(s, tactic)}
    return ids or None


def compute_hunt_evidence(scope: dict, *, windowed_at, scenarios, topology, computed_at: str = "") -> dict:
    frm = scope.get("from") or "1970-01-01T00:00:00+00:00"
    to = scope.get("to") or "9999-12-31T00:00:00+00:00"
    dets = windowed_at(frm, to)
    allow = scenario_ids_for_scope(scope, scenarios)
    zone = scope.get("zone")
    host = scope.get("host")
    evidence = []
    for d in dets:
        if allow is not None and d["scenario_id"] not in allow:
            continue
        if zone and zone not in d.get("affected_zones", []):
            continue
        if host and host not in d.get("affected_hosts", []):
            continue
        missing = d.get("missing_steps") or []
        evidence.append({
            "scenario_id": d["scenario_id"], "name": d["name"], "severity": d["severity"],
            "proximity": d["proximity"],
            "matched_count": len(d.get("matched_steps", [])),
            "total_steps": len(d.get("matched_steps", [])) + len(missing),
            "matched_steps": d.get("matched_steps", []),
            "next_step_to_hunt": missing[0] if missing else None,
            "stall": d.get("stall"),
            "hunting_queries": d.get("hunting_queries", []),
            "affected_hosts": d.get("affected_hosts", []),
            "affected_zones": d.get("affected_zones", []),
        })
    return {"evidence": evidence, "scope_resolved": {"from": frm, "to": to, "zone": zone, "host": host,
            "scenario_ids": sorted(allow) if allow else None},
            "computed_at": computed_at, "honesty_note": HONESTY_NOTE}
