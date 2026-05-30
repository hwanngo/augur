"""Compose coverage, falsepos, and detectability into a single report dict + Markdown renderer."""
from __future__ import annotations

from datetime import datetime

from augur.metrics.coverage import TACTIC_NAMES, mitre_coverage
from augur.metrics.detectability import detectability
from augur.metrics.falsepos import false_positive_rate
from augur.metrics.robustness import criteria_overlap_diagnostic, detection_robustness
from augur.scenarios.schema import Scenario
from augur.topology.network import Topology


def build_report(
    scenarios: list[Scenario],
    topology: Topology,
    benign_raws: list[dict],
    generated_at: datetime,
    *,
    all_steps: bool = False,
) -> dict:
    """Pure function: compose all three metric modules into one report dict.

    Args:
        scenarios: Loaded scenario list (from load_scenarios / default_scenarios).
        topology: Topology object (from default_topology).
        benign_raws: Raw log dicts for FP measurement (pre-normalize).
        generated_at: Timestamp to embed (caller must supply; do not call datetime.now here).

    Returns a dict with keys: generated_at, coverage, false_positive, detectability.
    """
    cov = mitre_coverage(scenarios)
    fp = false_positive_rate(scenarios, benign_raws, topology)
    det = detectability(scenarios, topology)
    rob = detection_robustness(scenarios, topology, all_steps=all_steps)
    # Informational, NON-GATING precision diagnostic. Only computed in the deeper
    # --all-steps pass (it's a depth tool, not part of the default last-step gate).
    overlap = criteria_overlap_diagnostic(scenarios, topology) if all_steps else None

    report = {
        "generated_at": generated_at.isoformat(),
        "coverage": cov,
        "false_positive": fp,
        "detectability": det,
        "robustness": rob,
    }
    if overlap is not None:
        report["criteria_overlap"] = overlap
    return report


def render_markdown(report: dict) -> str:
    """Render a report dict as a human-readable Markdown string."""
    lines: list[str] = []
    ts = report.get("generated_at", "unknown")

    lines.append("# Augur Detection Library Quality Report")
    lines.append("")
    lines.append(f"**Generated:** {ts}")
    lines.append("")

    # ── Overview ──────────────────────────────────────────────────────────
    cov = report["coverage"]
    fp = report["false_positive"]
    det = report["detectability"]

    lines.append("## Overview")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Scenario count | {cov['scenario_count']} |")
    lines.append(f"| MITRE tactic coverage | {len(cov['tactics_covered'])}/14 ({cov['tactic_coverage_pct']:.1%}) |")
    lines.append(f"| False positive rate | {fp['fp_rate']:.4f} ({fp['false_positives']}/{fp['benign_events']} events) |")
    lines.append(f"| Detectability rate | {det['detectability_rate']:.1%} ({det['detectable']}/{det['total']}) |")
    lines.append("")

    # ── MITRE ATT&CK Coverage ─────────────────────────────────────────────
    lines.append("## MITRE ATT&CK Coverage")
    lines.append("")
    lines.append(f"**Tactics covered:** {len(cov['tactics_covered'])}/14  ")
    lines.append(f"**Techniques covered:** {len(cov['techniques'])}")
    lines.append("")

    lines.append("### Per-Tactic Breakdown")
    lines.append("")
    lines.append("| Tactic ID | Tactic Name | Scenarios |")
    lines.append("|-----------|-------------|-----------|")
    for tac_id in sorted(TACTIC_NAMES.keys()):
        name = TACTIC_NAMES[tac_id]
        count = cov["per_tactic"].get(tac_id, 0)
        marker = "" if count > 0 else " _(not covered)_"
        lines.append(f"| {tac_id} | {name}{marker} | {count} |")
    lines.append("")

    if cov["tactics_missing"]:
        missing_names = ", ".join(f"{t} ({TACTIC_NAMES[t]})" for t in cov["tactics_missing"])
        lines.append(f"**Tactics missing:** {missing_names}")
        lines.append("")

    # ── False Positive Rate ───────────────────────────────────────────────
    lines.append("## False Positive Rate")
    lines.append("")
    lines.append(f"**Benign events tested:** {fp['benign_events']}  ")
    lines.append(f"**False positives (proximity ≥ 0.30):** {fp['false_positives']}  ")
    lines.append(f"**FP rate:** {fp['fp_rate']:.6f}")
    lines.append("")
    if fp["fired_scenarios"]:
        lines.append("**Fired scenarios (false positives):**")
        for sid in fp["fired_scenarios"]:
            lines.append(f"- {sid}")
    else:
        lines.append("_No false positives detected._")
    lines.append("")

    # ── Detectability ─────────────────────────────────────────────────────
    lines.append("## Detectability")
    lines.append("")
    lines.append(f"**Total scenarios:** {det['total']}  ")
    lines.append(f"**Fully detectable (proximity = 1.0):** {det['detectable']}  ")
    lines.append(f"**Unsynthesizable:** {len(det['unsynthesizable'])}  ")
    lines.append(f"**Partial (synth bug — should be 0):** {len(det['partial'])}  ")
    lines.append(f"**Detectability rate:** {det['detectability_rate']:.1%}")
    lines.append("")
    if det["unsynthesizable"]:
        lines.append("**Unsynthesizable scenarios:**")
        for sid in det["unsynthesizable"]:
            lines.append(f"- {sid}")
        lines.append("")
    if det["partial"]:
        lines.append("**Partial scenarios (synth contract violation):**")
        for sid in det["partial"]:
            lines.append(f"- {sid}")
        lines.append("")

    # ── Detection Robustness (false-negative boundary) ────────────────────
    rob = report.get("robustness")
    if rob is not None:
        agg = rob["aggregate"]
        lines.append("## Detection Robustness")
        lines.append("")
        lines.append(f"> {rob['honesty_note']}")
        lines.append("")
        lines.append(f"**Mutations run:** {agg['total']}  ")
        lines.append(f"**Passed:** {agg['passed']}  ")
        lines.append(f"**Failed:** {agg['failed']}  ")
        lines.append(f"**Skipped (unsynthesizable / no off-zone host / n/a):** {agg['skipped']}  ")
        lines.append(f"**Pass rate:** {agg['pass_pct']:.1%}")
        lines.append("")
        failing = [r for r in rob["rows"] if not r["pass"]
                   and r["status"] not in ("unsynthesizable", "no_offzone_host", "not_applicable")]
        if failing:
            lines.append("**Failing rows (gate did NOT reject as required):**")
            for r in failing:
                lines.append(
                    f"- {r['scenario_id']} / {r['kind']} (step {r['step_id']}): "
                    f"expected {r['expected']}, observed {r['observed']} — {r['status']}"
                )
            lines.append("")
        else:
            lines.append("_All gates rejected correctly._")
            lines.append("")

    # ── Criteria cross-step overlap (informational, NON-GATING) ───────────
    ovl = report.get("criteria_overlap")
    if ovl is not None:
        lines.append("## Criteria Cross-Step Overlap (informational — NOT a gate failure)")
        lines.append("")
        lines.append(f"> {ovl['note']}")
        lines.append("")
        if ovl["rows"]:
            lines.append(
                f"**Flagged:** {ovl['flagged']} scenario-step(s) where dropping a "
                "non-last step left the chain matching above the naive (k-1)/n oracle:"
            )
            for r in ovl["rows"]:
                lines.append(
                    f"- {r['scenario_id']} / drop step {r['step_id']} ({r['kind']}): "
                    f"naive {r['naive_expected']}, observed {r['observed']}"
                )
            lines.append("")
        else:
            lines.append("_No cross-step criteria overlap detected._")
            lines.append("")

    return "\n".join(lines) + "\n"
