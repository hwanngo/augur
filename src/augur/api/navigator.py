"""ATT&CK Navigator (schema v4.5) layer serialization.

Additive, read-only, deterministic. No engine import; no persistence. Joins detection
dicts (which carry only scenario_id/proximity/severity) to MITRE techniques via the
loaded scenarios' scenario_metadata.mitre_mappings. [AUDIT #3] builds its own
{scenario_id: scenario} index and skips detections with no matching scenario.
"""
from __future__ import annotations

from datetime import date

# TA#### -> Navigator tactic shortname (all 14, keys mirror metrics.coverage.TACTIC_NAMES).
# A tactic not in this map is skipped defensively.
_TACTIC_SHORTNAMES: dict[str, str] = {
    "TA0043": "reconnaissance",
    "TA0042": "resource-development",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0011": "command-and-control",
    "TA0010": "exfiltration",
    "TA0040": "impact",
}

_GRADIENT = {"colors": ["#e8eaf6", "#3949ab"], "minValue": 0, "maxValue": 100}
_LEGEND_COVERAGE = [{"label": "Covered by Augur library", "color": "#3949ab"}]
_LEGEND_DETECTIONS = [
    {"label": "Low proximity (1-49)", "color": "#9fa8da"},
    {"label": "High proximity (50-100)", "color": "#3949ab"},
]


def _envelope(layer_type: str, techniques: list[dict], legend: list[dict]) -> dict:
    kind = "Coverage" if layer_type == "coverage" else "Detections"
    stamp = date.today().isoformat()
    return {
        "name": f"Augur — {kind} {stamp}",
        "versions": {"attack": "15", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Augur {kind.lower()} export ({stamp}). Read-only Navigator layer.",
        "techniques": techniques,
        "gradient": _GRADIENT,
        "legendItems": legend,
        "sorting": 0,
        "hideDisabled": False,
    }


def _emit(acc: dict[tuple[str, str], dict]) -> list[dict]:
    out: list[dict] = []
    # [AUDIT — binding sort fix] sort by (tactic_shortname, techniqueID); the accumulator
    # is keyed (techniqueID, tactic), so key on (k[1], k[0]) NOT a naive sorted(acc).
    for (tech, short) in sorted(acc, key=lambda k: (k[1], k[0])):
        slot = acc[(tech, short)]
        out.append({
            "techniqueID": tech,
            "tactic": short,
            "score": slot["score"],
            "comment": ", ".join(slot["ids"]),
            "enabled": True,
        })
    return out


def _coverage_techniques(scenarios: list) -> list[dict]:
    # (techniqueID, shortname) -> {score, scenario_ids(ordered, unique)}
    acc: dict[tuple[str, str], dict] = {}
    for sc in scenarios:
        for m in sc.scenario_metadata.mitre_mappings:
            short = _TACTIC_SHORTNAMES.get(m.tactic)
            if short is None:
                continue  # tactic not in map -> skip defensively
            key = (m.technique, short)
            slot = acc.setdefault(key, {"score": 100, "ids": []})
            if sc.scenario_id not in slot["ids"]:
                slot["ids"].append(sc.scenario_id)
    return _emit(acc)


def _detections_techniques(scenarios: list, detections: list[dict]) -> list[dict]:
    scen_by_id = {s.scenario_id: s for s in scenarios}  # [AUDIT #3] internal index
    acc: dict[tuple[str, str], dict] = {}
    for d in detections:
        sc = scen_by_id.get(d["scenario_id"])
        if sc is None:
            continue  # [AUDIT #3] detection with no matching scenario -> skip
        score = round(d["proximity"] * 100)
        for m in sc.scenario_metadata.mitre_mappings:
            short = _TACTIC_SHORTNAMES.get(m.tactic)
            if short is None:
                continue
            key = (m.technique, short)
            slot = acc.setdefault(key, {"score": score, "ids": []})
            slot["score"] = max(slot["score"], score)  # dedup-by-max
            if sc.scenario_id not in slot["ids"]:
                slot["ids"].append(sc.scenario_id)
    return _emit(acc)


def build_navigator_layer(scenarios: list, *, layer_type: str,
                          detections: list[dict] | None = None) -> dict:
    if layer_type == "coverage":
        return _envelope("coverage", _coverage_techniques(scenarios), _LEGEND_COVERAGE)
    if layer_type == "detections":
        return _envelope("detections",
                         _detections_techniques(scenarios, detections or []),
                         _LEGEND_DETECTIONS)
    raise ValueError(f"unknown layer_type: {layer_type!r}")
