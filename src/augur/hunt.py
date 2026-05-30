import argparse
import os
import sys

from augur.connectors import get_sink, get_source, run_hunt

_WEBHOOK_ENV = {"webhook": "AUGUR_WEBHOOK_URL", "slack": "AUGUR_SLACK_WEBHOOK_URL"}


def _parse_kv(items: list[str]) -> dict:
    out = {}
    for it in items:
        k, _, v = it.partition("=")
        out[k] = v
    return out


def _sink_args(items: list[str]) -> dict[str, dict]:
    by_sink: dict[str, dict] = {}
    for it in items:
        name, _, kv = it.partition(":")
        k, _, v = kv.partition("=")
        by_sink.setdefault(name, {})[k] = v
    return by_sink


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="augur.hunt",
                                description="Run a hunt: source -> engine -> sinks")
    p.add_argument("--source", default="jsonl")
    p.add_argument("--source-arg", action="append", default=[], metavar="KEY=VAL")
    p.add_argument("--sink", action="append", default=[], metavar="NAME")
    p.add_argument("--sink-arg", action="append", default=[], metavar="NAME:KEY=VAL")
    p.add_argument("--min-proximity", type=float, default=0.30)
    args = p.parse_args(argv)

    source = get_source(args.source, **_parse_kv(args.source_arg))
    sink_names = args.sink or ["stdout"]
    by_sink = _sink_args(args.sink_arg)
    sinks = []
    for name in sink_names:
        kw = dict(by_sink.get(name, {}))
        env = _WEBHOOK_ENV.get(name)
        if env and "url" not in kw and os.environ.get(env):
            kw["url"] = os.environ[env]
        sinks.append(get_sink(name, **kw))

    detections = run_hunt(source, sinks, min_proximity=args.min_proximity)
    print(f"hunt complete: {len(detections)} detection(s) "
          f"at min_proximity={args.min_proximity}", file=sys.stderr)


if __name__ == "__main__":
    main()
