"""Grounded prompt builder for the ClaudeScenarioGenerator.

Pure functions — no network, no side effects — so they're fully testable.
"""
from pathlib import Path

from augur.generative.base import GenerationRequest
from augur.pipeline import default_topology
from augur.scenarios.loader import load_scenarios

_PKG = Path(__file__).resolve().parent
_REPO_ROOT = _PKG.parents[2]
_SCENARIOS_DIR = _REPO_ROOT / "scenarios"

# Schema contract text embedded in the system prompt so the LLM always knows the format.
_SCHEMA_CONTRACT = """\
## Scenario YAML Schema Contract

Every candidate MUST be valid YAML with these exact top-level keys:
  scenario_metadata: {scenario_id, name, description, severity, mitre_mappings}
  spatial_constraints: {applicable_zones, critical_assets_only, required_log_sources}
  attack_sequence_flow:
    steps: list of steps, each with {step_id, name, matching_criteria}
      - step 1: no temporal_link
      - steps 2+: temporal_link: {previous_step, link_scope, min_time_delta_seconds, max_time_delta_seconds}
  actionable_hunting_outputs:
    validation_queries: [{engine, query}]

matching_criteria MUST include Node_Type ("Process" or "File").
Criteria operators: literal value, {in: [...]}, {regex: "..."}, {equals: v}, {exists: true/false}
applicable_zones must be a subset of known zones: User_Endpoint, Internal_Server, Active_Directory, DMZ, Cloud_SaaS.
scenario_id format: SCEN-GEN-NNNN (e.g. SCEN-GEN-0001).
severity: one of CRITICAL, HIGH, MEDIUM, LOW.
"""


def _get_exemplar_scenarios(n: int = 3) -> list[str]:
    """Load n exemplar scenarios from the library as raw YAML strings."""
    exemplars = []
    try:
        scenarios = load_scenarios(_SCENARIOS_DIR)
        # Pick one from credential_access, one from execution, one from lateral_movement if possible
        preferred = ["SCEN-WIN-001", "SCEN-LNX-001"]
        by_id = {s.scenario_id: s for s in scenarios}
        picked = [by_id[sid] for sid in preferred if sid in by_id]
        # fill from the rest
        remaining = [s for s in scenarios if s.scenario_id not in {p.scenario_id for p in picked}]
        picked.extend(remaining)
        for s in picked[:n]:
            import yaml as _yaml
            exemplars.append(_yaml.safe_dump(s.model_dump(mode="json"), sort_keys=False))
    except Exception:
        pass
    return exemplars


def build_system_prompt() -> str:
    """Build the grounded system prompt containing schema contract, topology, and exemplars."""
    topo = default_topology()
    zone_lines = "\n".join(
        f"  - {a.hostname} (zone={a.zone.value}, criticality={a.criticality.value})"
        for a in topo.assets
    )

    exemplars = _get_exemplar_scenarios(3)
    exemplar_block = "\n\n---\n\n".join(f"### Exemplar scenario\n```yaml\n{e}\n```" for e in exemplars)

    return f"""\
You are a senior threat-intelligence engineer generating candidate attack-scenario YAML files
for the Augur threat-hunting platform.

{_SCHEMA_CONTRACT}

## Known topology (use applicable_zones and hosts from this list only)

{zone_lines}

## Exemplar scenarios from the library

{exemplar_block}

## Instructions

- Output ONLY valid YAML, no prose. Separate multiple candidates with `---`.
- Each scenario must represent a realistic, multi-step attack chain.
- Node_Type must be "Process" or "File" on every step.
- Do NOT copy an existing scenario verbatim — mutate technique, LOLBin choice, zone, or timing.
- applicable_zones must match the topology above.
"""


def build_user_prompt(request: GenerationRequest, seed_yaml: str) -> str:
    """Build the per-request user prompt from a seed YAML and axes."""
    axes_text = ", ".join(request.axes) if request.axes else "general mutation"
    lines = [
        f"Seed scenario (scenario_id={request.seed_id}):",
        "```yaml",
        seed_yaml,
        "```",
        "",
        f"Generate {request.n} candidate mutations of the seed above.",
        f"Mutation axes to emphasize: {axes_text}.",
        "",
        "Rules:",
        "- Output each candidate as a complete, standalone YAML document.",
        "- Separate candidates with `---`.",
        "- Use SCEN-GEN-NNNN ids (e.g. SCEN-GEN-0001, SCEN-GEN-0002 ...).",
        "- Every step must include Node_Type.",
        "- Do not output any prose — YAML only.",
    ]
    if request.category:
        lines.append(f"- Target MITRE tactic category: {request.category}.")
    if request.technique:
        lines.append(f"- Focus on technique: {request.technique}.")
    return "\n".join(lines)
