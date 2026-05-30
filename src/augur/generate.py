"""CLI entry point: generate candidate scenarios via the gauntlet pipeline.

Usage:
    uv run python -m augur.generate --seed SCEN-WIN-001 --n 5
    AUGUR_AI_GENERATOR=fake AUGUR_DB=/tmp/g.db uv run python -m augur.generate --seed SCEN-WIN-001 --n 5
"""
import argparse
import os
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Augur candidate scenario generator")
    parser.add_argument("--seed", help="Seed scenario_id to mutate")
    parser.add_argument("--category", help="Target category (alternative to --seed)")
    parser.add_argument("--technique", help="Target MITRE technique")
    parser.add_argument("--n", type=int, default=5, help="Number of candidates to generate")
    parser.add_argument("--axes", default="", help="Comma-separated mutation axes")
    parser.add_argument("--generator", default=None, help="Generator name (fake|claude)")
    args = parser.parse_args(argv)

    from augur.generative.config import load_ai_config
    from augur.generative import get_generator
    from augur.generative.base import GenerationRequest
    from augur.generative.candidates import CandidateStore
    from augur.generative.engine import generate_candidates
    from augur.auth.store import connect
    from augur.scenarios.loader import load_scenarios

    cfg = load_ai_config()
    n = min(args.n, cfg.max_n)

    axes = [a.strip() for a in args.axes.split(",") if a.strip()] if args.axes else []
    request = GenerationRequest(
        seed_id=args.seed,
        category=args.category,
        technique=args.technique,
        n=n,
        axes=axes,
    )

    generator = get_generator(args.generator)
    existing = load_scenarios("scenarios")

    db_path = os.environ.get("AUGUR_DB", "data/augur.db")
    store = CandidateStore(connect(db_path))

    results = generate_candidates(request, generator, existing, store=store, created_by="cli")

    passed = [r for r in results if r.passed]
    rejected = [r for r in results if not r.passed]

    for r in results:
        if r.passed:
            print(f"  PASSED  candidate={r.scenario_id}  plausibility={r.plausibility:.2f}  notes={r.notes}")
        else:
            print(f"  REJECTED candidate={r.scenario_id or '(invalid)'}  stage={r.reject_stage}  reason={r.reason[:80] if r.reason else ''}")

    print(f"\nSummary: {len(passed)}/{len(results)} candidates passed the gauntlet. {len(passed)} stored as pending.")


if __name__ == "__main__":
    main()
