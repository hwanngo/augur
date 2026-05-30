"""Incident Consolidated Response — pure fold of a clustered incident into a single, merged,
de-duplicated STANDARD response runbook (contain / eradicate / recover / validate).

HONESTY CONTRACT (verbatim in HONESTY_NOTE, the API payload, and the UI panel): a consolidated
response plan is the UNION of STANDARD, tactic-derived template runbooks for the scenarios in an
incident — exactly the per-scenario standard playbook (response/playbook.py), merged and
de-duplicated. It is NOT a bespoke incident-response plan, NOT a causal attribution, NOT a
containment guarantee.

Pure module. Consumes the already-computed public incident dicts (the cluster_incidents shape),
the scenario library (scenario_id -> Scenario for build_playbook), and a live Topology (only to
echo zone/criticality — never a new source of truth). It NEVER imports run_engine / scoring /
matcher / any graph backend / networkx / any normalizer, never reads wall-clock time, and uses no
randomness. A static AST test enforces this. The ONLY non-stdlib import is build_playbook.
"""
from __future__ import annotations

from augur.response.playbook import build_playbook

HONESTY_NOTE = (
    "A consolidated response plan is the UNION of STANDARD, tactic-derived template runbooks for "
    "the scenarios in this incident — exactly the per-scenario standard playbook, merged and "
    "de-duplicated. It is NOT a bespoke incident-response plan, NOT a causal attribution, and NOT "
    "a containment guarantee. Actions are derived from each member scenario's lowest-TA-id driving "
    "tactic and severity; nothing here is invented per-incident. Hosts and their zone/criticality "
    "come from the authoritative topology over THIS corpus. No engine run, no scoring change, no "
    "ML, no now()."
)


def _validate(incident) -> dict:
    """Validate ONE public incident dict (mirror of incidents.py::_validate style).

    Raises ValueError (-> 422 at the route) on a malformed incident."""
    if not isinstance(incident, dict):
        raise ValueError("incident must be a dict")
    for k in ("incident_id", "members"):
        if k not in incident:
            raise ValueError(f"incident missing required key: {k!r}")
    members = incident["members"]
    if not isinstance(members, list):
        raise ValueError("incident members must be a list")
    for m in members:
        if not isinstance(m, dict) or "scenario_id" not in m:
            raise ValueError("each member must be a dict with a 'scenario_id'")
    return incident


_SECTIONS = ("contain", "eradicate", "recover")  # string-line sections; validate handled separately


def build_incident_response(incident: dict, scenarios, topology) -> dict:
    """Fold one public incident dict into a consolidated STANDARD response plan.

    Deterministic: members are processed in scenario_id-sorted order; within a section the
    first-seen order of an action is its emission order; every from_scenarios list is
    scenario_id-sorted + de-duped. Raises ValueError on a malformed incident (-> 422)."""
    _validate(incident)
    by_id = {s.scenario_id: s for s in scenarios}

    # deterministic member iteration: scenario_id-sorted
    member_ids = sorted(m["scenario_id"] for m in incident["members"])

    unresolved: list[str] = []
    # string sections: action -> sorted-unique list of contributing scenario_ids, first-seen order
    line_provenance: dict[str, dict[str, set[str]]] = {s: {} for s in _SECTIONS}
    line_order: dict[str, list[str]] = {s: [] for s in _SECTIONS}
    # validate: (engine, query, query_path) -> provenance set; first-seen order preserved
    validate_provenance: dict[tuple[str, str, str], set[str]] = {}
    validate_order: list[tuple[str, str, str]] = []
    # driving tactics: tactic -> tactic_name
    tactics: dict[str, str] = {}

    for sid in member_ids:
        scen = by_id.get(sid)
        if scen is None:
            unresolved.append(sid)
            continue
        pb = build_playbook(scen)
        df = pb["derived_from"]
        tactics[df["tactic"]] = df["tactic_name"]
        secs = pb["sections"]
        for sec in _SECTIONS:
            for line in secs[sec]:
                if line not in line_provenance[sec]:
                    line_provenance[sec][line] = set()
                    line_order[sec].append(line)
                line_provenance[sec][line].add(sid)
        for v in secs["validate"]:
            key = (v["engine"], v["query"], v["query_path"])
            if key not in validate_provenance:
                validate_provenance[key] = set()
                validate_order.append(key)
            validate_provenance[key].add(sid)

    sections = {
        sec: [{"action": line, "from_scenarios": sorted(line_provenance[sec][line])}
              for line in line_order[sec]]
        for sec in _SECTIONS
    }
    sections["validate"] = [
        {"engine": eng, "query": q, "query_path": qp,
         "from_scenarios": sorted(validate_provenance[(eng, q, qp)])}
        for (eng, q, qp) in validate_order
    ]

    driving_tactics = [{"tactic": ta, "tactic_name": tactics[ta]} for ta in sorted(tactics)]

    note = ""
    if not any(sections[sec] for sec in ("contain", "eradicate", "recover", "validate")):
        note = "No member scenario resolved to a standard playbook; the plan is empty."

    return {
        "incident_id": incident["incident_id"],
        "top_severity": incident.get("top_severity"),
        "member_count": len(incident["members"]),
        "driving_tactics": driving_tactics,
        "hosts": list(incident.get("hosts", [])),
        "sections": sections,
        "unresolved_scenarios": sorted(set(unresolved)),
        "note": note,
        "honesty_note": HONESTY_NOTE,
    }


def build_all_incident_responses(incidents: list[dict], scenarios, topology) -> dict:
    """Map build_incident_response over the incident set, preserving the incidents' existing rank
    order. Returns {responses: [...], honesty_note}."""
    if not isinstance(incidents, list):
        raise ValueError("incidents must be a list")
    responses = [build_incident_response(inc, scenarios, topology) for inc in incidents]
    return {"responses": responses, "honesty_note": HONESTY_NOTE}
