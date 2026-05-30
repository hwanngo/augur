"""Evaluation harness for the scenario generator + gauntlet pipeline.

Metrics computed:
  schema_valid_rate   - fraction of generated candidates that pass schema validation
  fp_on_benign_rate   - fraction that fire on the benign corpus (must be 0.0 for a good generator)
  detectability_rate  - fraction of schema-valid candidates that pass the detectability gate
  dedup_rate          - fraction that are structural duplicates of existing scenarios
  mitre_coverage      - fraction of unique MITRE techniques covered by passing candidates
  yield               - fraction of all candidates that fully pass the gauntlet
"""
import json
import sys
from typing import Any

from augur.generative.base import GenerationRequest, ScenarioGenerator
from augur.generative.gauntlet import run_gauntlet, GauntletResult
from augur.scenarios.schema import Scenario


def evaluate(
    generator: ScenarioGenerator,
    seeds: list[str],
    existing: list[Scenario],
    n_per_seed: int = 3,
) -> dict[str, Any]:
    """Run generate → gauntlet over seeds and compute quality metrics."""
    all_results: list[GauntletResult] = []

    for seed_id in seeds:
        request = GenerationRequest(seed_id=seed_id, n=n_per_seed)
        raw_yamls = generator.generate(request, n_per_seed)
        for y in raw_yamls:
            result = run_gauntlet(y, existing)
            all_results.append(result)

    total = len(all_results)
    if total == 0:
        return {k: 0.0 for k in ("schema_valid_rate", "fp_on_benign_rate", "detectability_rate",
                                  "dedup_rate", "mitre_coverage", "yield")}

    schema_valid = [r for r in all_results if r.reject_stage != "schema"]
    fp_guard_failed = [r for r in schema_valid if r.reject_stage == "fp_guard"]
    dedup_failed = [r for r in schema_valid if r.reject_stage == "dedup"]
    detectability_failed = [r for r in schema_valid if r.reject_stage == "detectability"]
    passed = [r for r in all_results if r.passed]

    # MITRE coverage: unique techniques across passed candidates
    import yaml
    mitre_techniques: set[str] = set()
    for r in passed:
        try:
            data = yaml.safe_load(r.yaml)
            for m in data.get("scenario_metadata", {}).get("mitre_mappings", []):
                mitre_techniques.add(m.get("technique", ""))
        except Exception:
            pass

    existing_techniques = {m.technique for s in existing for m in s.scenario_metadata.mitre_mappings}
    mitre_coverage = (len(mitre_techniques & existing_techniques) / len(existing_techniques)
                      if existing_techniques else 0.0)

    return {
        "schema_valid_rate": round(len(schema_valid) / total, 4),
        "fp_on_benign_rate": round(len(fp_guard_failed) / total, 4),
        "detectability_rate": round(
            (len(schema_valid) - len(detectability_failed)) / len(schema_valid)
            if schema_valid else 0.0, 4),
        "dedup_rate": round(len(dedup_failed) / total, 4),
        "mitre_coverage": round(mitre_coverage, 4),
        "yield": round(len(passed) / total, 4),
        # detail counts for the report
        "total": total,
        "passed": len(passed),
        "schema_rejected": total - len(schema_valid),
        "fp_rejected": len(fp_guard_failed),
        "dedup_rejected": len(dedup_failed),
        "detectability_rejected": len(detectability_failed),
        "mitre_techniques_new": sorted(mitre_techniques - existing_techniques),
    }


def main(argv: list[str] | None = None) -> None:
    import argparse
    import os
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Augur generator eval harness")
    parser.add_argument("--generator", default=None, help="Generator name (fake|claude)")
    parser.add_argument("--seeds", default="", help="Comma-separated seed scenario_ids")
    parser.add_argument("--n", type=int, default=3, help="Candidates per seed")
    parser.add_argument("--out", default=None, help="Optional JSON output path")
    args = parser.parse_args(argv)

    from augur.generative import get_generator
    from augur.scenarios.loader import load_scenarios

    generator = get_generator(args.generator)
    existing = load_scenarios("scenarios")

    seeds = [s.strip() for s in args.seeds.split(",") if s.strip()]
    if not seeds:
        # default: use the first 5 scenario ids from the library as seeds
        seeds = [s.scenario_id for s in existing[:5]]

    report = evaluate(generator, seeds, existing, n_per_seed=args.n)

    print(json.dumps(report, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2))
        print(f"\nReport saved to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
