"""IR Post-Incident Report — pure fold of a clustered incident + its consolidated response into a
single, deterministic hand-off artifact (JSON body + Markdown export).

HONESTY CONTRACT (verbatim in HONESTY_NOTE, the API payload, the markdown footer, and the UI panel):
this report is a deterministic ASSEMBLY of an engine correlation (cluster_incidents) and a standard
tactic-derived response template (build_incident_response). Both upstream notes are lifted verbatim
and a "what this is NOT" line is appended. It is NOT a confirmed adversary campaign, NOT a causal
attribution, NOT a bespoke incident-response plan, and NOT a containment guarantee.

Pure module. Consumes the two already-computed public dicts (the cluster_incidents incident shape +
the build_incident_response response shape) and SELECTS / re-labels fields — no new computation, no
scoring, no engine, no graph, no normalizer, no networkx, no wall-clock, no randomness. A static AST
test enforces this. No non-stdlib import at all.
"""
from __future__ import annotations

HONESTY_NOTE = (
    "This report is a deterministic ASSEMBLY of an engine correlation and standard tactic-derived "
    "templates over THIS corpus. It is NOT a confirmed adversary campaign, NOT a causal attribution, "
    "NOT a bespoke incident-response plan, and NOT a containment guarantee. Every line is traceable "
    "to a detection, a topology fact, or a standard playbook — no narrative is invented."
)


def _validate(incident, response) -> tuple[str]:
    """Validate the two public dicts share an incident_id. Returns (incident_id,).

    Raises ValueError (-> 422 at the route) on a malformed pair."""
    if not isinstance(incident, dict):
        raise ValueError("incident must be a dict")
    if not isinstance(response, dict):
        raise ValueError("response must be a dict")
    inc_id = incident.get("incident_id")
    resp_id = response.get("incident_id")
    if not inc_id:
        raise ValueError("incident missing required key: 'incident_id'")
    if not resp_id:
        raise ValueError("response missing required key: 'incident_id'")
    if inc_id != resp_id:
        raise ValueError(
            f"incident_id mismatch: incident {inc_id!r} != response {resp_id!r}")
    return (inc_id,)


def build_incident_report(incident: dict, response: dict) -> dict:
    """Assemble one deterministic post-incident report by SELECTING fields already present in the
    two cached dicts. No recompute, no now(), no randomness. Raises ValueError on an id mismatch."""
    (incident_id,) = _validate(incident, response)

    header = {
        "incident_id": incident_id,
        "top_severity": incident.get("top_severity"),
        "max_proximity": incident.get("max_proximity"),
        "score": incident.get("score"),
        "member_count": incident.get("size"),
        "host_count": len(incident.get("hosts", [])),
        "technique_count": len(incident.get("techniques", [])),
        "first_ts": incident.get("first_ts"),
        "last_ts": incident.get("last_ts"),
        "relations": list(incident.get("relations", [])),
        "members_truncated": incident.get("members_truncated", False),
    }

    return {
        "incident_id": incident_id,
        "header": header,
        "affected_assets": list(incident.get("hosts", [])),
        "techniques": list(incident.get("techniques", [])),
        "detection_summary": list(incident.get("members", [])),
        "response": response,
        # both upstream notes carried verbatim for the markdown footer + the UI honesty panel
        "source_notes": {
            "incident": incident.get("honesty_note", ""),
            "response": response.get("honesty_note", ""),
        },
        "honesty_note": HONESTY_NOTE,
    }


def _md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    """A GitHub-flavoured markdown table as a list of lines. Empty rows -> a single italic line."""
    if not rows:
        return ["_none_"]
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return out


def report_to_markdown(report: dict) -> str:
    """Deterministic, total markdown render. Stable section order; tables in the payload's
    already-deterministic order; honest truncation line preserved; honesty footer lifts both upstream
    notes verbatim. No template engine, no now(), no randomness."""
    h = report["header"]
    lines: list[str] = []

    lines.append(f"# Post-Incident Report — {report['incident_id']}")
    lines.append("")

    # Header
    lines.append("## Header")
    lines.append("")
    lines += _md_table(
        ["Field", "Value"],
        [
            ["Top severity", h["top_severity"]],
            ["Max proximity", h["max_proximity"]],
            ["Score", h["score"]],
            ["Members", h["member_count"]],
            ["Hosts", h["host_count"]],
            ["Techniques", h["technique_count"]],
            ["First seen (corpus)", h["first_ts"] or "—"],
            ["Last seen (corpus)", h["last_ts"] or "—"],
            ["Correlation relations", ", ".join(h["relations"]) or "—"],
        ],
    )
    if h["members_truncated"]:
        shown = len(report["detection_summary"])
        lines.append("")
        lines.append(f"> Truncated: {shown} of {h['member_count']} members shown.")
    lines.append("")

    # Affected Assets
    lines.append("## Affected Assets")
    lines.append("")
    lines += _md_table(
        ["Host", "Zone", "Criticality"],
        [[a["hostname"], a["zone"], a["criticality"]] for a in report["affected_assets"]],
    )
    lines.append("")

    # MITRE Technique Coverage
    lines.append("## MITRE Technique Coverage")
    lines.append("")
    lines.append(", ".join(report["techniques"]) if report["techniques"] else "_none_")
    lines.append("")

    # Detection Summary
    lines.append("## Detection Summary")
    lines.append("")
    lines += _md_table(
        ["Scenario", "Name", "Severity", "Proximity", "Latest (corpus)"],
        [[m["scenario_id"], m.get("name", ""), m["severity"], m["proximity"],
          m.get("latest_ts") or "—"] for m in report["detection_summary"]],
    )
    lines.append("")

    # Consolidated Response
    resp = report["response"]
    lines.append("## Consolidated Response")
    lines.append("")
    tactics = ", ".join(f"{d['tactic']} ({d['tactic_name']})" for d in resp["driving_tactics"])
    lines.append(f"**Driving tactics:** {tactics or '—'}")
    lines.append("")
    for sec in ("contain", "eradicate", "recover"):
        lines.append(f"### {sec.capitalize()}")
        lines.append("")
        rows = [[a["action"], ", ".join(a["from_scenarios"])] for a in resp["sections"][sec]]
        lines += _md_table(["Action", "From scenarios"], rows)
        lines.append("")
    lines.append("### Validate")
    lines.append("")
    vrows = [[v["engine"], v["query"], v.get("query_path") or "—", ", ".join(v["from_scenarios"])]
             for v in resp["sections"]["validate"]]
    lines += _md_table(["Engine", "Query", "Query path", "From scenarios"], vrows)
    lines.append("")
    if resp.get("unresolved_scenarios"):
        lines.append(f"_Unresolved scenarios (skipped): {', '.join(resp['unresolved_scenarios'])}_")
        lines.append("")
    if resp.get("note"):
        lines.append(f"_{resp['note']}_")
        lines.append("")

    # Honesty — combined note, then BOTH upstream notes lifted verbatim from source_notes
    lines.append("## Honesty")
    lines.append("")
    lines.append(report["honesty_note"])
    lines.append("")
    lines.append(f"- _Correlation (incident) note:_ {report['source_notes']['incident']}")
    lines.append(f"- _Standard-template (response) note:_ {report['source_notes']['response']}")

    return "\n".join(lines) + "\n"
