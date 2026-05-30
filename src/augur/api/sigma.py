"""Deterministic Sigma rule export from Augur scenarios (pure transform).

Renders one vendor-neutral Sigma detection rule **per scenario step**. Reuses the
criteria.py field maps inverted so the field mapping can never drift from the engine.

HONESTY: a flat Sigma rule is a single-event selection. It CANNOT express Augur's
cross-step temporal correlation or spatial zone gating. Each rule therefore matches one
technique step in isolation — a hunting/alerting building block, NOT a 1:1 reproduction of
the validated Augur scenario chain. This caveat rides in every rule (description +
falsepositives), the YAML header comment, and the API/CLI/UI/docs.

Pure: no engine/graph/scoring import, deterministic UUIDs only, no now(), no persistence
(guarded by a test, like response/playbook.py).
"""
from __future__ import annotations

from typing import Any
from uuid import UUID, uuid5

import yaml

from augur.metrics.coverage import TACTIC_NAMES
from augur.scenarios.schema import Scenario, Step

# Inlined from engine/criteria.py so this module has zero augur.engine dependency.
# These MUST stay byte-identical to criteria.py — guarded by the purity test.
BEHAVIOR_KEYS: frozenset[str] = frozenset({"TargetProcess", "GrantedAccess", "Behavior_Markers"})
_PROCESS_KEY_MAP = {
    "ProcessName": "name", "ProcessPath": "path", "CommandLine": "command_line",
    "ParentProcessName": "parent_process_name", "IntegrityLevel": "integrity_level",
    "ProcessGuid": "id",
}
_FILE_KEY_MAP = {
    "Extension": "extension", "IsSigned": "is_signed", "IsInjected": "is_injected",
    "ApiHookingDetected": "api_hooking_detected", "FileName": "name", "Path": "path",
    "SignatureVendor": "signature_vendor",
}

# One fixed project namespace UUID — hard-coded constant (deterministic, uuid5 only). Stable forever.
SIGMA_NAMESPACE = UUID("8b6c2f1a-3d4e-5a6b-7c8d-9e0f1a2b3c4d")

# Static export-contract date — determinism over freshness. Never now().
SIGMA_EXPORT_DATE = "2026/06/01"

HONESTY_NOTE = (
    "Augur-derived per-step detection. This rule matches ONE technique step in isolation. "
    "Augur's full detection additionally requires cross-step temporal correlation "
    "(link_scope/time-delta) and spatial zone gating (applicable_zones, resolved by Augur "
    "topology) that a flat Sigma rule cannot express. Treat as a hunting / alerting building "
    "block, not a 1:1 reproduction of the Augur scenario."
)

UNMAPPABLE_NOTE = (
    "This step has no Sigma-expressible fields — it requires Augur's behavior/temporal/spatial "
    "correlation and cannot be detected by a flat Sigma rule (rule intentionally non-firing)."
)

# Sentinel selection used in non-firing rules — non-empty so it does not accidentally match
# everything, but references a field that NEVER exists in any real event.
_NONFIRING_SELECTION = {"AugurNonFiringPlaceholder|exists": False}

_HEADER = (
    "# Augur Sigma export — per-step detection (NOT the full temporal+spatial scenario chain). "
    "See description.\n"
)

# os_family → Sigma logsource product. Cloud-stub (SCEN-CLD-*) approximates cloud via endpoint
# telemetry, so it maps to windows (with an x-augur note).
_OS_PRODUCT = {"windows": "windows", "linux": "linux", "macos": "macos"}

# Severity.value.lower() == Sigma level (low|medium|high|critical), 1:1.

# Process criteria key → (Sigma field, modifier-style). 'endswith' fields hold a *name* but
# Sysmon/Sigma carry the full Image path, so we emit |endswith for name semantics.
_PROCESS_FIELD = {
    "ProcessName": ("Image", "endswith"),
    "ProcessPath": ("Image", None),
    "CommandLine": ("CommandLine", None),
    "ParentProcessName": ("ParentImage", "endswith"),
    "IntegrityLevel": ("IntegrityLevel", None),
    "ProcessGuid": ("ProcessGuid", None),       # no clean Sigma field — emit + comment in x-augur
}
# File / image_load criteria key → (Sigma field, modifier-style).
_FILE_FIELD = {
    "FileName": ("ImageLoaded", "endswith"),
    "Path": ("ImageLoaded", None),
    "IsSigned": ("Signed", None),
    "SignatureVendor": ("Signature", None),
    "Extension": ("ImageLoaded", "endswith"),   # best-effort; no clean Sigma field
    "IsInjected": ("IsInjected", None),         # no clean Sigma field
    "ApiHookingDetected": ("ApiHookingDetected", None),
}
# Behavior keys (process_access logsource, EDR-specific).
_BEHAVIOR_FIELD = {
    "TargetProcess": ("TargetImage", "endswith"),
    "GrantedAccess": ("GrantedAccess", None),
    # Behavior_Markers has no standard field — see _emit_behavior.
}

# Keys with no clean cross-vendor Sigma field — flagged in x-augur.unmapped, never dropped.
_NO_CLEAN_FIELD = {"ProcessGuid", "Extension", "IsInjected", "ApiHookingDetected"}


def _path_sep(os_family: str) -> str:
    """Return the path separator used by the scenario's native OS.

    - linux / macos  → POSIX "/"   (Image paths like /usr/bin/bash)
    - windows (default) → "\\"     (Image paths like C:\\Windows\\...\\rundll32.exe)
    The cloud-stub (SCEN-CLD-*) has os_family="linux", so it correctly gets "/".
    """
    if os_family in ("linux", "macos"):
        return "/"
    return "\\"


def _name_value(name: str, sep: str = "\\") -> str:
    r"""Process/image name → a leading-separator endswith literal (e.g. \rundll32.exe or /bash)."""
    return sep + name


def _emit_value(field_base: str, modifier: str | None, crit: Any, sep: str = "\\") -> tuple[str, Any]:
    """Map ONE (field, modifier, criterion) to a (sigma_key, sigma_value) pair.

    Mirrors engine.criteria.match_value's operator order exactly (regex→equals→in→exists→literal);
    any other operator dict fails closed with ValueError (never silently drops a criterion).
    sep: path separator for endswith name literals ("/" for linux/macos, "\\" for windows).
    """
    use_endswith = modifier == "endswith"

    def key_for(extra_mod: str | None) -> str:
        mods = [m for m in (modifier, extra_mod) if m]
        return field_base + "".join(f"|{m}" for m in mods)

    if isinstance(crit, dict):
        if "regex" in crit:
            # regex always overrides endswith; emit |re (PCRE/RE2, unanchored — matches Python re.search)
            return f"{field_base}|re", crit["regex"]
        if "equals" in crit:
            return field_base, crit["equals"]
        if "in" in crit:
            vals = crit["in"]
            if use_endswith:
                vals = [_name_value(str(v), sep) for v in vals]
            return key_for(None), list(vals)
        if "exists" in crit:
            return f"{field_base}|exists", bool(crit["exists"])
        raise ValueError(f"unknown operator in {crit!r}")
    # bare scalar == literal equality
    if use_endswith:
        return key_for(None), _name_value(str(crit), sep)
    return field_base, crit


def _step_kind(criteria: dict) -> str:
    """behavior | image_load | process_creation — exactly as the engine sees the step."""
    if any(k in BEHAVIOR_KEYS for k in criteria):
        return "behavior"
    if criteria.get("Node_Type") == "File":
        return "image_load"
    return "process_creation"


def _tags_and_refs(scenario: Scenario) -> tuple[list[str], list[str]]:
    tags: set[str] = set()
    refs: list[str] = []
    seen_ref: set[str] = set()
    for m in scenario.scenario_metadata.mitre_mappings:
        name = TACTIC_NAMES.get(m.tactic, "")
        if name:
            slug = name.lower().replace(" ", "-").replace("/", "")
            tags.add(f"attack.{slug}")
        tags.add(f"attack.{m.technique.lower()}")
        tech_path = m.technique.replace(".", "/")
        ref = f"https://attack.mitre.org/techniques/{tech_path}/"
        if ref not in seen_ref:
            seen_ref.add(ref)
            refs.append(ref)
    return sorted(tags), refs


def _emit_selection(
    criteria: dict, fieldmap: dict, extra_keys: set[str], sep: str = "\\"
) -> tuple[dict, list[str]]:
    """Build the selection dict + a list of unmapped-field notes.

    sep: path separator for endswith name literals ("/" for linux/macos, "\\" for windows).
    """
    selection: dict[str, Any] = {}
    unmapped: list[str] = []
    for key, crit in criteria.items():
        if key == "Node_Type" or key in extra_keys:
            continue
        spec = fieldmap.get(key)
        if spec is None:
            unmapped.append(f"{key}: no Sigma field mapping; review")
            continue
        field_base, modifier = spec
        sk, sv = _emit_value(field_base, modifier, crit, sep)
        selection[sk] = sv
        if key in _NO_CLEAN_FIELD:
            unmapped.append(f"{key}: no standard Sigma field — best-effort {field_base}; review")
    return selection, unmapped


def step_to_sigma(scenario: Scenario, step: Step) -> dict:
    """One Sigma rule dict for one scenario step (per-step granularity, §4.1)."""
    criteria = step.matching_criteria
    kind = _step_kind(criteria)
    os_family = scenario.os_family
    is_cloud = scenario.scenario_id.startswith("SCEN-CLD-")
    product = _OS_PRODUCT.get("windows" if is_cloud else os_family, "windows")
    # Path separator is keyed on the criteria's native os_family, NOT the mapped product.
    # Cloud-stub has os_family="linux" → POSIX "/" even though product="windows".
    sep = _path_sep(os_family)

    falsepositives = [
        "Per-step rule — the full Augur scenario chain (temporal + zone) is not reproduced here."
    ]

    if kind == "behavior":
        selection, unmapped = _emit_selection(criteria, _PROCESS_FIELD, BEHAVIOR_KEYS, sep)
        beh_sel, beh_unmapped = _emit_selection(criteria, _BEHAVIOR_FIELD, set(), sep)
        selection.update(beh_sel)
        unmapped += beh_unmapped
        if "Behavior_Markers" in criteria:
            unmapped.append("Behavior_Markers: no standard Sigma field (EDR markers); review")
        category = "process_access"
        falsepositives.append(
            "Behavior step — EDR-specific; verify field mapping in your SIEM."
        )
    elif kind == "image_load":
        selection, unmapped = _emit_selection(criteria, _FILE_FIELD, set(), sep)
        category = "image_load"
    else:
        selection, unmapped = _emit_selection(criteria, _PROCESS_FIELD, set(), sep)
        category = "process_creation"

    tags, refs = _tags_and_refs(scenario)

    # ── non-firing guard ──────────────────────────────────────────────────────
    # An empty selection dict (no Sigma-expressible fields) would emit
    # `detection: {selection: {}, condition: selection}`, which matches EVERY event —
    # a dangerous always-true rule. Detect this before building the final rule.
    no_sigma_fields = not selection

    if no_sigma_fields:
        description = (
            f"{scenario.name} — step {step.step_id}/{scenario.step_count}: {step.name}.\n"
            f"{UNMAPPABLE_NOTE}\n{HONESTY_NOTE}"
        )
    else:
        description = (
            f"{scenario.name} — step {step.step_id}/{scenario.step_count}: {step.name}.\n"
            f"{HONESTY_NOTE}"
        )

    x_augur: dict[str, Any] = {
        "scenario_id": scenario.scenario_id,
        "step_id": step.step_id,
        "total_steps": scenario.step_count,
    }
    if is_cloud:
        x_augur["note"] = (
            "cloud-stub scenario — approximated via windows endpoint telemetry."
        )
    if no_sigma_fields:
        x_augur["unmapped"] = True
    elif unmapped:
        x_augur["unmapped"] = unmapped

    if no_sigma_fields:
        return {
            "title": f"Augur {scenario.scenario_id} step{step.step_id} {step.name}",
            "id": str(uuid5(SIGMA_NAMESPACE, f"{scenario.scenario_id}:{step.step_id}")),
            "status": "unsupported",
            "description": description,
            "references": refs,
            "author": "Augur (deterministic export)",
            "date": SIGMA_EXPORT_DATE,
            "tags": tags,
            "logsource": {"product": product, "category": category},
            "detection": {
                "selection": _NONFIRING_SELECTION,
                "condition": "selection and not selection",
            },
            "falsepositives": [UNMAPPABLE_NOTE],
            "level": scenario.severity.value.lower(),
            "x-augur": x_augur,
        }

    return {
        "title": f"Augur {scenario.scenario_id} step{step.step_id} {step.name}",
        "id": str(uuid5(SIGMA_NAMESPACE, f"{scenario.scenario_id}:{step.step_id}")),
        "status": "experimental",
        "description": description,
        "references": refs,
        "author": "Augur (deterministic export)",
        "date": SIGMA_EXPORT_DATE,
        "tags": tags,
        "logsource": {"product": product, "category": category},
        "detection": {"selection": selection, "condition": "selection"},
        "falsepositives": falsepositives,
        "level": scenario.severity.value.lower(),
        "x-augur": x_augur,
    }


def scenario_to_sigma(scenario: Scenario) -> list[dict]:
    """One rule per step, in step order (deterministic)."""
    return [step_to_sigma(scenario, s) for s in scenario.attack_sequence_flow.steps]


def to_yaml(rule: dict) -> str:
    """Dump one rule to Sigma YAML, header comment prepended."""
    body = yaml.safe_dump(rule, sort_keys=False, default_flow_style=False, allow_unicode=True)
    return _HEADER + body


def pack_to_yaml(scenarios: list[Scenario]) -> str:
    """Multi-doc YAML for the whole library: scenario load order, then step order."""
    docs = []
    for sc in scenarios:
        for rule in scenario_to_sigma(sc):
            docs.append(yaml.safe_dump(rule, sort_keys=False, default_flow_style=False,
                                       allow_unicode=True))
    return _HEADER + "\n---\n".join(docs)
