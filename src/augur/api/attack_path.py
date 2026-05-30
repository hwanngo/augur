"""Crown-Jewel Technique Paths (additive, read-only, deterministic).

Plausible technique progression across a DECLARED zone model toward CRITICAL assets, assembled from the
scenario library's applicable_zones + MITRE tactics and the live engine detections. This is NOT a network-
reachability or exploitability claim — the topology carries no host adjacency and every scenario link is
same-host. Each zone "stop" is observed (a real engine detection fired in that zone) or hypothetical (an
applicable library technique not yet seen). No engine import; consumes the public detection dicts +
Topology + Scenario objects (Invariants 1/2/6).
"""
from statistics import mean

from augur.enums import Criticality

ZONE_SPINES = [
    ["DMZ", "User_Endpoint", "Internal_Server", "Active_Directory"],
    ["DMZ", "User_Endpoint", "Cloud_SaaS"],
]
ENTRY_ZONES = ("DMZ", "User_Endpoint")
MAX_PATHS = 50
HONESTY_NOTE = (
    "Plausible technique progression over the scenario library + zone model — not a network-reachability "
    "or exploitability claim. 'Observed' stops reflect live engine detections; 'hypothetical' stops are "
    "library techniques not yet seen in the logs."
)
SEV_WEIGHT = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _sevrank(sev) -> int:
    return SEV_WEIGHT.get(sev, 0)


def _primary_tactic(scen) -> str:
    return sorted(m.tactic for m in scen.scenario_metadata.mitre_mappings)[0]


def _spine_for(zone: str):
    for spine in ZONE_SPINES:
        if zone in spine:
            return spine
    return None


def _cover_zone(zone, dets, scen_by_id, applicable_by_zone, topology) -> dict:
    observed = [d for d in dets if zone in d.get("affected_zones", [])]
    if observed:
        d = sorted(observed, key=lambda d: (-d["proximity"], -_sevrank(d["severity"]), d["scenario_id"]))[0]
        matched = len(d["matched_steps"])
        total = matched + len(d["missing_steps"])
        hosts = d.get("affected_hosts", [])
        host = next((h for h in hosts if topology.enrich(h)[0].value == zone), hosts[0] if hosts else None)
        scen = scen_by_id.get(d["scenario_id"])
        return {"zone": zone, "scenario_id": d["scenario_id"], "scenario_name": d["name"],
                "tactic": _primary_tactic(scen) if scen else None, "severity": d["severity"],
                "status": "observed", "observed_proximity": round(d["proximity"], 4),
                "matched_steps": matched, "total_steps": total, "host": host}
    apps = applicable_by_zone.get(zone, [])
    if apps:
        scen = sorted(apps, key=lambda s: (-_sevrank(s.severity.value), s.scenario_id))[0]
        return {"zone": zone, "scenario_id": scen.scenario_id, "scenario_name": scen.name,
                "tactic": _primary_tactic(scen), "severity": scen.severity.value,
                "status": "hypothetical", "observed_proximity": 0.0,
                "matched_steps": 0, "total_steps": scen.step_count, "host": None}
    return {"zone": zone, "scenario_id": None, "scenario_name": "(no library coverage)",
            "tactic": None, "severity": None, "status": "hypothetical",
            "observed_proximity": 0.0, "matched_steps": 0, "total_steps": 0, "host": None}


def build_attack_paths(detections, topology, scenarios, *, min_proximity, entry_zone=None, target=None):
    dets = [d for d in detections if d["proximity"] >= min_proximity]
    scen_by_id = {s.scenario_id: s for s in scenarios}
    applicable_by_zone: dict[str, list] = {}
    for s in scenarios:
        for z in s.spatial_constraints.applicable_zones:
            applicable_by_zone.setdefault(z, []).append(s)

    if target is not None:
        a = topology.lookup(target)
        targets = [a] if a is not None else []
    else:
        targets = [a for a in topology.assets if a.criticality == Criticality.CRITICAL]

    paths: list[dict] = []
    for a in targets:
        tzone = a.zone.value
        spine = _spine_for(tzone)
        if spine is None:
            continue   # a CRITICAL asset in a zone outside ZONE_SPINES yields no path (by design)
        tidx = spine.index(tzone)
        if entry_zone is not None:
            if entry_zone not in spine:
                continue
            eidx = spine.index(entry_zone)
        else:
            eidx = next((spine.index(z) for z in spine if z in ENTRY_ZONES), None)
            if eidx is None:
                continue
        if eidx >= tidx:
            continue
        zones = spine[eidx:tidx + 1]
        stops = [_cover_zone(z, dets, scen_by_id, applicable_by_zone, topology) for z in zones]
        stops[-1]["host"] = a.hostname
        sigma_m = sum(s["matched_steps"] for s in stops)
        sigma_t = sum(s["total_steps"] for s in stops)
        observed = [s for s in stops if s["status"] == "observed"]
        max_sev = sorted((s["severity"] for s in observed), key=lambda v: -_sevrank(v))[0] if observed else None
        paths.append({
            "entry": {"zone": spine[eidx]},
            "target": {"hostname": a.hostname, "zone": tzone, "criticality": a.criticality.value},
            "realized_pct": round(sigma_m / sigma_t, 4) if sigma_t else 0.0,
            "mean_observed_proximity": round(mean(s["observed_proximity"] for s in stops), 4),
            "observed_stop_count": len(observed),
            "total_stop_count": len(stops),
            "max_severity": max_sev,
            "stops": stops,
            "honesty_note": HONESTY_NOTE,
        })
    paths.sort(key=lambda p: (-p["realized_pct"], -_sevrank(p["max_severity"]),
                              p["entry"]["zone"], p["target"]["zone"], p["target"]["hostname"]))
    return paths[:MAX_PATHS]
