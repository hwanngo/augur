import os
from pathlib import Path
from augur.ingest.jsonl import read_jsonl
from augur.normalize.ecs import normalize_events
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.graph.interface import GraphBackend
from augur.topology.network import load_topology, Topology
from augur.scenarios.loader import load_scenarios

_PKG = Path(__file__).resolve().parent
_ROOT = _PKG.parent.parent
DEFAULT_TOPOLOGY = _PKG / "topology" / "standard_topology.yaml"
DEFAULT_SCENARIOS_DIR = _ROOT / "scenarios"


def default_topology() -> Topology:
    return load_topology(DEFAULT_TOPOLOGY)


def default_scenarios():
    return load_scenarios(DEFAULT_SCENARIOS_DIR)


def load_events(paths: list[str]):
    raws: list[dict] = []
    for p in paths:
        raws.extend(read_jsonl(p))
    return normalize_events(raws)


def _select_backend() -> GraphBackend:
    if os.environ.get("AUGUR_BACKEND") == "neo4j":
        from augur.graph.neo4j_backend import Neo4jBackend
        return Neo4jBackend(
            uri=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
            user=os.environ.get("NEO4J_USER", "neo4j"),
            password=os.environ.get("NEO4J_PASSWORD", "augur"),
        )
    return NetworkXBackend()


def build_backend(paths: list[str], topology: Topology, backend: GraphBackend | None = None) -> GraphBackend:
    backend = backend or _select_backend()
    events = sorted(load_events(paths), key=lambda e: e.timestamp)
    build_graph(events, topology, backend)
    return backend
