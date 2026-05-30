"""CLI entry-point: python -m augur.metrics"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from augur.ingest.jsonl import read_jsonl
from augur.metrics.falsepos import generate_benign_corpus
from augur.metrics.report import build_report, render_markdown
from augur.pipeline import default_scenarios, default_topology


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        prog="augur.metrics",
        description="Augur detection library quality report",
    )
    p.add_argument(
        "--logs", metavar="PATH",
        help="JSONL log file for FP measurement (default: generate benign corpus)",
    )
    p.add_argument(
        "--out", metavar="PATH.md",
        help="Write Markdown report to this file (default: stdout)",
    )
    p.add_argument(
        "--json", metavar="PATH",
        help="Also write raw report dict as JSON to this file",
    )
    p.add_argument(
        "--duration", type=int, default=3600,
        help="Benign corpus duration in seconds (default: 3600)",
    )
    p.add_argument(
        "--rate", type=int, default=60,
        help="Benign corpus event rate per minute (default: 60)",
    )
    p.add_argument(
        "--seed", type=int, default=1234,
        help="Benign corpus RNG seed (default: 1234)",
    )
    p.add_argument(
        "--fail-on-robustness", action="store_true",
        help="Exit non-zero if any detection-robustness mutation row failed (CI gate)",
    )
    p.add_argument(
        "--all-steps", action="store_true",
        help="Sweep EVERY applicable step per gate (stretch/relink 2..n; drop/relocate "
             "last/single), proving the gates reject at every prefix position",
    )
    args = p.parse_args(argv)

    # Wall-clock stamp lives only in the CLI layer
    generated_at = datetime.now(timezone.utc)

    scenarios = default_scenarios()
    topology = default_topology()

    if args.logs:
        benign_raws = read_jsonl(args.logs)
    else:
        benign_raws = generate_benign_corpus(
            seed=args.seed,
            duration_seconds=args.duration,
            rate_per_minute=args.rate,
        )

    report = build_report(scenarios, topology, benign_raws, generated_at,
                          all_steps=args.all_steps)
    md = render_markdown(report)

    if args.out:
        with open(args.out, "w") as fh:
            fh.write(md)
    else:
        print(md)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)

    # One-line summary to stderr
    cov = report["coverage"]
    fp = report["false_positive"]
    det = report["detectability"]
    rob = report["robustness"]["aggregate"]
    print(
        f"[metrics] {cov['scenario_count']} scenarios | "
        f"MITRE {len(cov['tactics_covered'])}/14 tactics | "
        f"FP rate {fp['fp_rate']:.4f} | "
        f"detectability {det['detectability_rate']:.1%} | "
        f"robustness {rob['pass_pct']:.1%} ({rob['passed']}/{rob['passed'] + rob['failed']})",
        file=sys.stderr,
    )

    if args.fail_on_robustness and rob["failed"] > 0:
        print(
            f"[metrics] FAIL: {rob['failed']} robustness mutation(s) did not reject as required",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
