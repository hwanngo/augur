"""Per-window detections helper.

Mirrors `alerting.scan._detections_for`: read raws → normalize → sort by timestamp →
keep events within absolute [frm, to] bounds → build a fresh graph → run the engine.

Determinism (Invariant 1): the engine never sees "now". Bounds are absolute, injected
``datetime`` values resolved at the API layer. No wall-clock here.
"""
from dataclasses import asdict
from datetime import datetime

from augur.engine.runner import run_engine
from augur.engine.diagnose import diagnose_stall
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.api.feed import load_normalized


def _public(d: dict) -> dict:
    return {k: v for k, v in d.items() if not k.startswith("_")}


def windowed_detections(log_paths, topology, scenarios, *, frm: datetime, to: datetime) -> list[dict]:
    """Compute the ranked detection list over events within [frm, to].

    Returns ``_public(asdict(d))`` dicts (private keys stripped), ranked exactly as the
    full pipeline ranks (proximity, severity, recency). ``min_proximity=0`` here — the
    caller applies any proximity floor after windowing.
    """
    events = sorted(load_normalized(log_paths), key=lambda e: e.timestamp)
    events = [e for e in events if frm <= e.timestamp <= to]
    backend = NetworkXBackend()
    build_graph(events, topology, backend)
    scen_by_id = {s.scenario_id: s for s in scenarios}
    out: list[dict] = []
    for d in run_engine(backend, scenarios, min_proximity=0.0):
        pub = _public(asdict(d))
        # [AUDIT #1] diagnose only k+1 of a sub-100% detection with matched_len >= 1.
        # [AUDIT #3] folded into this once-per-window builder, not a per-request endpoint.
        if d.proximity < 1.0 and len(d.matched_steps) >= 1:
            stall = diagnose_stall(backend, scen_by_id[d.scenario_id], d)
            if stall is not None:
                pub["stall"] = stall
        out.append(pub)
    return out
