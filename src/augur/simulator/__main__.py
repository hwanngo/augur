import argparse
import sys
from datetime import datetime, timezone

import yaml

from augur.simulator.config import SimConfig
from augur.simulator.profiles import default_profiles
from augur.simulator.run import generate_feed
from augur.simulator.sinks import JsonlBatchSink
from augur.pipeline import default_scenarios, default_topology

_BASE = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


def _load_config(args) -> SimConfig:
    if args.config:
        with open(args.config) as fh:
            return SimConfig(**(yaml.safe_load(fh) or {}))
    return SimConfig(seed=args.seed, duration_seconds=args.duration, rate_per_minute=args.rate)


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="augur.simulator",
                                description="Deterministic multi-OS log generator (PoC)")
    p.add_argument("--batch", action="store_true", help="render one window to a JSONL file (default)")
    p.add_argument("--stream", action="store_true", help="(P4) continuous emit to a directory")
    p.add_argument("--config", help="YAML SimConfig (seed, duration_seconds, rate_per_minute, injections)")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--duration", type=int, default=3600)
    p.add_argument("--rate", type=int, default=12)
    p.add_argument("--out", default="data/sim_feed.jsonl")
    p.add_argument("--out-dir", default="data/sim_feed", help="output directory (--stream drop-feed)")
    p.add_argument("--batch-size", type=int, default=50, help="events per batch file (--stream)")
    p.add_argument("--interval", type=float, default=1.0, help="seconds between batches (--stream)")
    args = p.parse_args(argv)

    config = _load_config(args)
    raws = generate_feed(config, default_profiles(), default_scenarios(), default_topology(), _BASE)
    if args.stream:
        from augur.simulator.stream import stream_feed
        paths = stream_feed(args.out_dir, raws, batch_size=args.batch_size, interval=args.interval)
        print(f"streamed {len(raws)} events in {len(paths)} batch file(s) to {args.out_dir}", file=sys.stderr)
        print(f"{len(paths)} batches", file=sys.stdout)
        return
    sink = JsonlBatchSink(args.out)
    sink.write(raws)
    sink.close()
    print(f"wrote {len(raws)} events ({len(config.injections)} injection(s)) to {args.out}", file=sys.stderr)
    print(f"{len(raws)} events", file=sys.stdout)


if __name__ == "__main__":
    main()
