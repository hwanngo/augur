import contextlib
import logging

from augur.connectors.base import Sink, Source
from augur.engine.runner import run_engine
from augur.engine.scoring import Detection
from augur.graph.builder import build_graph
from augur.normalize.ecs import normalize_events
from augur.pipeline import _select_backend, default_scenarios, default_topology

_log = logging.getLogger("augur.connectors")


def run_hunt(source: Source, sinks: list[Sink], *, topology=None, scenarios=None,
             min_proximity: float = 0.30, backend=None) -> list[Detection]:
    """source -> normalize -> graph -> engine -> fan detections out to every sink.

    Each sink is isolated: one failing sink is logged and does not block the others.
    Returns the ranked detections.
    """
    raws = list(source.read())
    events = sorted(normalize_events(raws), key=lambda e: e.timestamp)
    backend = backend or _select_backend()
    build_graph(events, topology or default_topology(), backend)
    detections = run_engine(backend, scenarios or default_scenarios(), min_proximity=min_proximity)

    with contextlib.ExitStack() as stack:
        for s in sinks:
            if hasattr(s, "__enter__"):
                stack.enter_context(s)
        for s in sinks:
            try:
                s.emit_all(detections)
            except Exception as exc:  # one sink must never break the others
                _log.warning("sink %r failed: %s", s, exc)
    return detections
