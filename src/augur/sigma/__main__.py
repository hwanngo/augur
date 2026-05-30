"""CLI entry-point: python -m augur.sigma

Deterministic Sigma rule export. No server, no DB, no engine — pure transform over
default_scenarios().

  python -m augur.sigma                          # all scenarios → stdout (multi-doc YAML)
  python -m augur.sigma --scenario SCEN-WIN-001  # one scenario's rules → stdout
  python -m augur.sigma --out dist/sigma         # write one <id>-step<N>.yml per rule
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from augur.api.sigma import scenario_to_sigma, pack_to_yaml, to_yaml, HONESTY_NOTE
from augur.pipeline import default_scenarios


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="augur.sigma",
        description="Deterministic Sigma rule export from Augur scenarios (per-step).",
    )
    p.add_argument("--scenario", metavar="ID", help="export one scenario (default: all)")
    p.add_argument("--out", metavar="DIR", help="write one <id>-step<N>.yml per rule (default: stdout)")
    args = p.parse_args(argv)

    scenarios = default_scenarios()
    if args.scenario:
        scen = next((s for s in scenarios if s.scenario_id == args.scenario), None)
        if scen is None:
            print(f"[sigma] unknown scenario: {args.scenario!r}", file=sys.stderr)
            return 2
        selected = [scen]
    else:
        selected = scenarios

    # Honesty banner — CLI may print; library code may not.
    print(f"[sigma] {HONESTY_NOTE}", file=sys.stderr)

    if args.out:
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        for scen in selected:
            for rule in scenario_to_sigma(scen):
                fname = f"{scen.scenario_id}-step{rule['x-augur']['step_id']}.yml"
                (out_dir / fname).write_text(to_yaml(rule))
                count += 1
        print(f"[sigma] wrote {count} rule(s) to {out_dir}", file=sys.stderr)
        return 0

    sys.stdout.write(pack_to_yaml(selected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
