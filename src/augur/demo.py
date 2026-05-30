import argparse
import os
from pathlib import Path

from augur.pipeline import build_backend, default_topology, default_scenarios
from augur.engine.runner import run_engine

_DEFAULT_REAL_DATASET = "empire_mimikatz_logonpasswords"
_OTRF_TOPOLOGY = "datasets/real/topology_otrf_theshire.yaml"
_WAVE1_TOPOLOGY = "datasets/real/topology_wave1.yaml"


def run_headless(log_paths, min_proximity: float = 0.30, topology=None, scenarios=None):
    backend = build_backend(log_paths, topology or default_topology())
    detections = run_engine(backend, scenarios or default_scenarios(), min_proximity=min_proximity)
    print("=" * 72)
    print(f"Augur — {len(detections)} scenario(s) matched (min_proximity={min_proximity})")
    print("=" * 72)
    for d in detections:
        matched = len(d.matched_steps)
        total = matched + len(d.missing_steps)
        pct = round(d.proximity * 100)
        print(f"[{d.severity:8}] {d.name}")
        print(f"           {d.scenario_id} — {matched}/{total} steps — {pct}% — hosts: {', '.join(d.affected_hosts)}")
        if d.missing_steps:
            print(f"           missing: {', '.join(s['name'] for s in d.missing_steps)}")
    if not detections:
        print("No scenarios matched.")
    print("=" * 72)
    return detections


def _ensure_tagged(dataset: str) -> str:
    """Fetch+tag the dataset if its tagged.jsonl is absent; return the tagged path. Idempotent."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
    import fetch_real_datasets as fetcher
    tagged = fetcher.DEST_ROOT / dataset / "tagged.jsonl"
    if not tagged.exists():
        fetcher.fetch_and_tag(dataset)
    return str(tagged)


def _wave1_tags() -> list[str]:
    """Return the ordered real-suite tag list (Wave 1 + Wave 2) from the fetcher (registry order =
    deterministic feed order). `--real all` serves every wave's feeds so all real detections show."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
    import fetch_real_datasets as fetcher
    return list(fetcher.SUITES["all"])


def _real_app(log_paths):
    """Build the FastAPI app wired for the real OTRF dataset (OTRF topology + default∪real scenarios)."""
    from augur.api.app import create_app
    from augur.topology.network import load_topology
    from augur.scenarios.loader import load_scenarios
    topology = load_topology(_OTRF_TOPOLOGY)
    scenarios = default_scenarios() + load_scenarios("scenarios_real")
    return create_app(log_paths=log_paths, topology=topology, scenarios=scenarios)


def _real_app_suite(log_paths):
    """FastAPI app for the Wave-1 suite (combined topology + default∪real scenarios; multi-feed)."""
    from augur.api.app import create_app
    from augur.topology.network import load_topology
    from augur.scenarios.loader import load_scenarios
    topology = load_topology(_WAVE1_TOPOLOGY)
    scenarios = default_scenarios() + load_scenarios("scenarios_real")
    return create_app(log_paths=log_paths, topology=topology, scenarios=scenarios)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Augur demo")
    parser.add_argument("--logs", nargs="+", default=["sample_data/acceptance/demo_multi_os.jsonl"])
    parser.add_argument("--min-proximity", type=float, default=0.30)
    parser.add_argument("--no-serve", action="store_true", help="print detections and exit (CI)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true",
                        help="auto-reload the API when src/augur/*.py changes (dev)")
    parser.add_argument("--real", nargs="?", const=_DEFAULT_REAL_DATASET, default=None,
                        metavar="DATASET",
                        help="run on a real OTRF dataset (auto fetch+tag if absent; "
                             f"default: {_DEFAULT_REAL_DATASET})")
    args = parser.parse_args(argv)

    if args.real == "all":
        log_paths = [_ensure_tagged(t) for t in _wave1_tags()]
        from augur.topology.network import load_topology
        from augur.scenarios.loader import load_scenarios
        topology = load_topology(_WAVE1_TOPOLOGY)
        scenarios = default_scenarios() + load_scenarios("scenarios_real")
        run_headless(log_paths, args.min_proximity, topology=topology, scenarios=scenarios)
        if args.no_serve:
            return
        import uvicorn
        print(f"Serving REAL Wave-1 SUITE dashboard at http://127.0.0.1:{args.port}  (Ctrl-C to stop)")
        os.environ.setdefault("AUGUR_ADMIN_USER", "admin")
        os.environ.setdefault("AUGUR_ADMIN_PASSWORD", "dev-password-123")
        if args.reload:
            # AUGUR_LOGS is single-path only; the suite needs all 7 feeds → reload is unsupported here.
            print("[--real all] reload unsupported for the multi-feed suite; serving non-reload.")
        uvicorn.run(_real_app_suite(log_paths), host="127.0.0.1", port=args.port)
        return

    if args.real is not None:
        tagged = _ensure_tagged(args.real)
        log_paths = [tagged]
        from augur.topology.network import load_topology
        from augur.scenarios.loader import load_scenarios
        topology = load_topology(_OTRF_TOPOLOGY)
        scenarios = default_scenarios() + load_scenarios("scenarios_real")
        run_headless(log_paths, args.min_proximity, topology=topology, scenarios=scenarios)
        if args.no_serve:
            return
        import uvicorn
        print(f"Serving REAL-dataset dashboard at http://127.0.0.1:{args.port}  (Ctrl-C to stop)")
        os.environ.setdefault("AUGUR_ADMIN_USER", "admin")
        os.environ.setdefault("AUGUR_ADMIN_PASSWORD", "dev-password-123")
        if args.reload:
            os.environ["AUGUR_LOGS"] = log_paths[0]
            os.environ["AUGUR_TOPOLOGY"] = _OTRF_TOPOLOGY
            os.environ["AUGUR_SCENARIOS_DIR"] = "scenarios"
            os.environ["AUGUR_SCENARIOS_EXTRA_DIR"] = "scenarios_real"
            uvicorn.run("augur.api.app:create_app", factory=True, reload=True,
                        reload_dirs=["src/augur"], host="127.0.0.1", port=args.port)
            return
        uvicorn.run(_real_app(log_paths), host="127.0.0.1", port=args.port)
        return

    run_headless(args.logs, args.min_proximity)
    if args.no_serve:
        return
    import uvicorn
    print(f"Serving dashboard at http://127.0.0.1:{args.port}  (Ctrl-C to stop)")
    if args.reload:
        # Reload needs an import string + factory (uvicorn re-imports the app on change). The
        # factory create_app() takes no args, so pass the corpus through AUGUR_LOGS (single path).
        os.environ["AUGUR_LOGS"] = args.logs[0]
        if len(args.logs) > 1:
            print(f"[--reload] watching only {args.logs[0]} (AUGUR_LOGS takes a single path)")
        uvicorn.run("augur.api.app:create_app", factory=True, reload=True,
                    reload_dirs=["src/augur"], host="127.0.0.1", port=args.port)
        return
    from augur.api.app import create_app
    uvicorn.run(create_app(log_paths=args.logs), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
