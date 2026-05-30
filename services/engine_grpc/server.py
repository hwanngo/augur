"""Augur detection-engine gRPC server (polyglot service slice — see docs/en/ARCHITECTURE.md).

Wraps the existing deterministic engine behind a gRPC `Detector.Analyze` RPC so other
services (e.g. the Go collector in services/collector-go) can stream raw log events in and
get ranked detections back. The Python monolith is unchanged — this only exposes it.

Run:  uv run --extra grpc python services/engine_grpc/server.py [port]
"""
import json
import sys
from concurrent import futures
from pathlib import Path

import grpc

# the generated stubs live next to this file (fsrpc/v1)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fsrpc.v1 import detector_pb2 as pb
from fsrpc.v1 import detector_pb2_grpc as pbg

from augur.normalize.ecs import normalize_events
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.engine.runner import run_engine
from augur.pipeline import default_topology, default_scenarios

_TOPOLOGY = default_topology()
_SCENARIOS = default_scenarios()


class DetectorServicer(pbg.DetectorServicer):
    def Analyze(self, request, context):
        try:
            raws = [json.loads(e.json) for e in request.events]
            events = sorted(normalize_events(raws), key=lambda e: e.timestamp)
        except (json.JSONDecodeError, ValueError) as exc:
            msg = f"invalid event payload: {exc}"
            if context is not None:   # real gRPC call: fail cleanly with a typed error
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details(msg)
                return pb.AnalyzeResponse()
            raise                     # in-process (tests): surface the error
        backend = NetworkXBackend()
        build_graph(events, _TOPOLOGY, backend)
        detections = run_engine(backend, _SCENARIOS, min_proximity=request.min_proximity)

        resp = pb.AnalyzeResponse()
        for d in detections:
            resp.detections.add(
                scenario_id=d.scenario_id, name=d.name, severity=d.severity,
                proximity=d.proximity, affected_hosts=d.affected_hosts,
                matched_steps=len(d.matched_steps),
                total_steps=len(d.matched_steps) + len(d.missing_steps),
            )
        return resp


def serve(port: int = 50051) -> None:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pbg.add_DetectorServicer_to_server(DetectorServicer(), server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    print(f"Augur gRPC detection engine on :{port}  ({len(_SCENARIOS)} scenarios loaded)", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 50051)
