"""Test the gRPC detection-engine servicer (polyglot slice, services/engine_grpc).

Skipped unless the optional `grpc` extra is installed (uv sync --extra grpc), so the
default suite stays infra-free. Exercises the real servicer in-process — no network.
"""
import pathlib
import sys

import pytest

pytest.importorskip("grpc")  # only runs with `uv sync --extra grpc`

sys.path.insert(0, str(pathlib.Path("services/engine_grpc").resolve()))
import server  # noqa: E402
from fsrpc.v1 import detector_pb2 as pb  # noqa: E402


def _request(path: str, min_proximity: float = 0.0) -> "pb.AnalyzeRequest":
    lines = [l for l in pathlib.Path(path).read_text().splitlines() if l.strip()]
    return pb.AnalyzeRequest(events=[pb.RawEvent(json=l) for l in lines], min_proximity=min_proximity)


def test_servicer_detects_true_positive_at_full_confidence():
    resp = server.DetectorServicer().Analyze(_request("sample_data/acceptance/full_detection.jsonl"), None)
    dets = {d.scenario_id: d for d in resp.detections}
    assert "SCEN-WIN-001" in dets
    assert abs(dets["SCEN-WIN-001"].proximity - 1.0) < 1e-9
    assert list(dets["SCEN-WIN-001"].affected_hosts) == ["HR_User_PC"]


def test_servicer_filters_by_min_proximity():
    resp = server.DetectorServicer().Analyze(
        _request("sample_data/acceptance/demo_multi_os.jsonl", min_proximity=0.9), None)
    ids = {d.scenario_id for d in resp.detections}
    assert "SCEN-WIN-001" in ids          # 1.0 passes
    assert "SCEN-LNX-002" not in ids        # 0.3333 filtered out
