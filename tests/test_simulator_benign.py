from datetime import datetime, timezone
from augur.simulator.config import SimConfig
from augur.simulator.baseline import generate_baseline
from augur.simulator.profiles import default_profiles
from augur.simulator.sinks import JsonlBatchSink
from augur.normalize.registry import normalize_events
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.engine.runner import run_engine
from augur.pipeline import default_topology, default_scenarios

BASE = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


def test_baseline_produces_zero_detections():
    cfg = SimConfig(seed=99, duration_seconds=3600, rate_per_minute=30)
    raws = generate_baseline(default_profiles(), cfg, BASE)
    events = sorted(normalize_events(raws), key=lambda e: e.timestamp)
    backend = NetworkXBackend()
    build_graph(events, default_topology(), backend)
    dets = [d for d in run_engine(backend, default_scenarios(), min_proximity=0.0) if d.proximity >= 0.30]
    assert dets == [], f"benign baseline should not fire any scenario, got {[d.scenario_id for d in dets]}"


def test_jsonl_batch_sink_writes_lines(tmp_path):
    out = tmp_path / "feed.jsonl"
    sink = JsonlBatchSink(str(out))
    sink.write([{"a": 1}, {"b": 2}])
    sink.close()
    lines = out.read_text().strip().splitlines()
    assert len(lines) == 2


def test_directory_sink_writes_a_file(tmp_path):
    from augur.simulator.sinks import DirectoryBatchSink
    sink = DirectoryBatchSink(str(tmp_path))
    path = sink.write_batch([{"a": 1}], name="batch-0001")
    import os
    assert os.path.isfile(path) and path.endswith(".jsonl")
