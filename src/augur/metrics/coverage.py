"""MITRE ATT&CK tactic/technique coverage analysis."""
from __future__ import annotations

from augur.scenarios.schema import Scenario

TACTIC_NAMES: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

_TOTAL_TACTICS = len(TACTIC_NAMES)  # 14


def mitre_coverage(scenarios: list[Scenario]) -> dict:
    """Return MITRE ATT&CK coverage metrics for a list of scenarios."""
    tactics_seen: set[str] = set()
    techniques_seen: set[str] = set()
    per_tactic: dict[str, int] = {}

    for sc in scenarios:
        sc_tactics: set[str] = set()
        for m in sc.scenario_metadata.mitre_mappings:
            techniques_seen.add(m.technique)
            sc_tactics.add(m.tactic)
        for t in sc_tactics:
            tactics_seen.add(t)
            per_tactic[t] = per_tactic.get(t, 0) + 1

    tactics_covered = sorted(tactics_seen)
    tactics_missing = sorted(t for t in TACTIC_NAMES if t not in tactics_seen)
    coverage_pct = round(len(tactics_covered) / _TOTAL_TACTICS, 6) if scenarios else 0.0

    return {
        "scenario_count": len(scenarios),
        "tactics_covered": tactics_covered,
        "tactics_missing": tactics_missing,
        "techniques": sorted(techniques_seen),
        "per_tactic": per_tactic,
        "tactic_coverage_pct": coverage_pct,
    }


# Coverage-Gap Matrix (additive, read-only; no engine import). [AUDIT #1] tactics are read from
# scenario.scenario_metadata.mitre_mappings — NOT scenario.mitre_mappings (no such attribute).
_OS_FAMILY_SUBSTRINGS: list[tuple[str, str]] = [
    ("windows", "windows"),
    ("linux", "linux"),
    ("mac", "macos"),
    ("cloud", "cloud"),
    ("saas", "cloud"),
]

# Columns are restricted to OS families the engine can actually express. Cloud is deliberately
# excluded: cloud-stub scenarios carry os_family windows/linux (endpoint telemetry), so a literal
# cloud column would always read 14/14 gap and misrepresent the design.
_EXPRESSIBLE_FAMILIES: tuple[str, ...] = ("windows", "linux", "macos")


def _os_to_family(os_string: str) -> str | None:
    """Case-insensitive substring map of an Asset.os / Scenario.os_family string to a family,
    or None when unmappable (caller ignores Nones — no spurious columns / silent miscounts)."""
    lowered = (os_string or "").lower()
    for needle, family in _OS_FAMILY_SUBSTRINGS:
        if needle in lowered:
            return family
    return None


def coverage_gap_matrix(scenarios: list, topology) -> dict:
    """Tactics × OS coverage-gap matrix. Pure, deterministic, no engine import, no persistence.

    Columns = (families present in topology.assets) ∩ {windows, linux, macos}, in that fixed order.
    Rows = the 14 TACTIC_NAMES (always the full grid). A cell (tactic, os) is covered iff >=1
    scenario whose os_family maps to `os` lists that tactic in its mitre_mappings.
    """
    present = {f for a in topology.assets if (f := _os_to_family(a.os)) is not None}
    os_families = [f for f in _EXPRESSIBLE_FAMILIES if f in present]

    # (tactic_id, family) -> covering scenario count.
    counts: dict[tuple[str, str], int] = {}
    for sc in scenarios:
        fam = _os_to_family(sc.os_family)
        if fam not in os_families:  # ignore cloud-stub & unknown os_family for grid purposes
            continue
        sc_tactics = {m.tactic for m in sc.scenario_metadata.mitre_mappings}  # [AUDIT #1]
        for tac in sc_tactics:
            if tac in TACTIC_NAMES:
                counts[(tac, fam)] = counts.get((tac, fam), 0) + 1

    cells: dict[str, dict] = {}
    total_cells = covered_cells = 0
    for tac in TACTIC_NAMES:  # canonical 14-row order
        row: dict[str, dict] = {}
        for fam in os_families:
            n = counts.get((tac, fam), 0)
            row[fam] = {"covered": n > 0, "count": n}
            total_cells += 1
            if n > 0:
                covered_cells += 1
        cells[tac] = row

    gap_cells = total_cells - covered_cells
    coverage_pct = round(covered_cells / total_cells, 4) if total_cells else 0.0
    return {
        "tactics": [{"id": tid, "name": name} for tid, name in TACTIC_NAMES.items()],
        "os_families": os_families,
        "cells": cells,
        "summary": {
            "os_families": os_families,
            "total_cells": total_cells,
            "covered_cells": covered_cells,
            "gap_cells": gap_cells,
            "coverage_pct": coverage_pct,
        },
    }
