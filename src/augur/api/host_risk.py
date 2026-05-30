"""Host Risk Board — deterministic per-host risk aggregation.

Pure, read-only. Consumes the already-computed `_public` detection dicts + the live `Topology`.
NO engine run, NO persistence, NO import of engine scoring / engine matcher (Invariant 1/2/6).

Per detection->host contribution: proximity * CRIT_WEIGHT[criticality] * SEV_WEIGHT[severity].
Per host score: SUM of contributions over detections whose affected_hosts include the host.
"""
from augur.enums import Criticality

# [AUDIT #1] explicit STRING-keyed severity weights (Detection.severity is a string in the public
# dict; SEVERITY_RANK is Severity-enum-keyed and stripped of _severity_rank, so it is NOT usable).
# Values intentionally == SEVERITY_RANK + 1 so a LOW detection isn't worth 0.
SEV_WEIGHT: dict[str, int] = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# [AUDIT #2] keyed by the Criticality ENUM (Topology.enrich returns a Criticality enum). UNKNOWN
# floored to 1 so off-topology hosts still surface. Topology is authoritative.
CRIT_WEIGHT: dict[Criticality, int] = {
    Criticality.CRITICAL: 4, Criticality.HIGH: 3, Criticality.MEDIUM: 2,
    Criticality.LOW: 1, Criticality.UNKNOWN: 1,
}


def _band(score: float) -> str:
    if score >= 8:
        return "CRITICAL"
    if score >= 4:
        return "HIGH"
    if score >= 1.5:
        return "WATCH"
    if score > 0:
        return "LOW"
    return "CLEAR"


def compute_host_risk(detections: list[dict], topology) -> list[dict]:
    # Canonical display name keyed by lowercased hostname. Topology assets first (authoritative
    # casing + criticality), then off-topology detection hosts unioned in. [AUDIT #4]
    display: dict[str, str] = {}
    for a in topology.assets:
        display.setdefault(a.hostname.lower(), a.hostname)
    for d in detections:
        for h in d.get("affected_hosts", []):
            display.setdefault(h.lower(), h)   # keep first-seen raw casing for off-topology hosts

    # Aggregate contributions per lowercased host key.
    agg: dict[str, dict] = {
        k: {"score": 0.0, "count": 0, "max_proximity": 0.0, "contribs": []} for k in display
    }
    for d in detections:
        sev_w = SEV_WEIGHT.get(d["severity"], 1)
        prox = d["proximity"]
        for h in d.get("affected_hosts", []):
            key = h.lower()
            _, crit = topology.enrich(h)                  # Criticality enum [AUDIT #2]
            contribution = prox * CRIT_WEIGHT.get(crit, 1) * sev_w
            bucket = agg[key]
            bucket["score"] += contribution
            bucket["count"] += 1
            bucket["max_proximity"] = max(bucket["max_proximity"], prox)
            bucket["contribs"].append((contribution, d))

    rows: list[dict] = []
    for key, name in display.items():
        zone, crit = topology.enrich(name)
        bucket = agg[key]
        score = round(bucket["score"], 4)                 # 4 dp, mirrors proximity rounding
        # top 3 contributing detections by (contribution desc, scenario_id asc)
        top = sorted(bucket["contribs"], key=lambda c: (-c[0], c[1]["scenario_id"]))[:3]
        if bucket["count"]:
            top_sev = max((d["severity"] for _, d in bucket["contribs"]),
                          key=lambda s: SEV_WEIGHT.get(s, 0))
            top_scenarios = [{"scenario_id": d["scenario_id"], "name": d["name"],
                              "severity": d["severity"], "proximity": d["proximity"]}
                             for _, d in top]
            max_prox = bucket["max_proximity"]
        else:
            top_sev, top_scenarios, max_prox = None, [], 0   # [AUDIT #5] uniform empty-host defaults
        rows.append({
            "hostname": name, "zone": zone.value, "criticality": crit.value,
            "score": score, "band": _band(score), "detection_count": bucket["count"],
            "max_proximity": max_prox, "top_severity": top_sev, "top_scenarios": top_scenarios,
        })

    # [tie-break] sort by (-score, hostname asc); clean hosts (0) fall to the bottom.
    rows.sort(key=lambda r: (-r["score"], r["hostname"]))
    return rows
