"""TDD: StreamingGraph — bounded rolling-window graph. Gates: window-off byte-identity, incremental ==
one-shot, prune correctness, bounded memory, honesty guard. Engine determinism stays intact."""
from datetime import timedelta

import pytest

from augur.api.feed import load_normalized
from augur.engine.runner import run_engine
from augur.graph.builder import build_graph, ingest_events, IngestState
from augur.graph.networkx_backend import NetworkXBackend
from augur.pipeline import default_scenarios, default_topology
from augur.streaming.graph import (
    StreamingGraph, WindowTooSmallError, scenario_max_span_seconds, library_max_span_seconds,
)

_LOGS = ["sample_data/corpus/enterprise_day.jsonl"]
_TOPO = default_topology()
_SCEN = default_scenarios()


def _events():
    return sorted(load_normalized(_LOGS), key=lambda e: e.timestamp)


def _batches(events, n):
    size = max(1, (len(events) + n - 1) // n)
    return [events[i:i + size] for i in range(0, len(events), size)]


def _snapshot(backend):
    g = backend._g
    nodes = {nid: (data.get("node_type"), getattr(data.get("obj"), "timestamp", None))
             for nid, data in g.nodes(data=True)}
    edges = sorted((u, v, d["edge_type"], d["timestamp"].isoformat())
                   for u, v, _k, d in g.edges(keys=True, data=True))
    return nodes, edges


# ── 9.1 window=None byte-identical ──────────────────────────────────────────
def test_window_none_is_byte_identical():
    events = _events()
    b1 = NetworkXBackend()
    build_graph(events, _TOPO, b1)

    sg = StreamingGraph(NetworkXBackend(), _TOPO, window=None)
    for batch in _batches(events, 4):
        rep = sg.ingest(batch)
        assert rep.prune is None                     # window=None ⇒ prune NEVER called

    assert _snapshot(b1) == _snapshot(sg.backend)     # identical node + edge sets
    assert run_engine(b1, _SCEN, 0.0) == run_engine(sg.backend, _SCEN, 0.0)   # identical detections


# ── 9.2 incremental == one-shot ─────────────────────────────────────────────
def test_incremental_append_equals_one_shot():
    events = _events()
    b1 = NetworkXBackend(); build_graph(events, _TOPO, b1)
    b2 = NetworkXBackend(); st = IngestState()
    for batch in _batches(events, 5):
        ingest_events(batch, _TOPO, b2, state=st)
    assert _snapshot(b1) == _snapshot(b2)
    assert run_engine(b1, _SCEN, 0.0) == run_engine(b2, _SCEN, 0.0)


# ── prune correctness ───────────────────────────────────────────────────────
def test_prune_removes_everything_before_cutoff_and_stays_consistent():
    events = _events()
    backend = NetworkXBackend(); build_graph(events, _TOPO, backend)
    g = backend._g
    tss = sorted({getattr(d.get("obj"), "timestamp", None) for _n, d in g.nodes(data=True)
                  if getattr(d.get("obj"), "timestamp", None) is not None})
    cutoff = tss[len(tss) // 2]

    nodes_before = g.number_of_nodes()
    stats = backend.prune_before(cutoff)
    assert stats.cutoff == cutoff and stats.nodes_removed > 0

    # nothing older than cutoff survives (nodes or edges)
    for _n, d in g.nodes(data=True):
        ts = getattr(d.get("obj"), "timestamp", None)
        assert ts is None or ts >= cutoff
    for _u, _v, _k, d in g.edges(keys=True, data=True):
        assert d["timestamp"] >= cutoff
    # no dangling edge: both endpoints still present
    present = set(g.nodes)
    for u, v, _k, _d in g.edges(keys=True, data=True):
        assert u in present and v in present
    assert g.number_of_nodes() < nodes_before

    # idempotent: re-pruning at the same cutoff removes nothing
    again = backend.prune_before(cutoff)
    assert again.nodes_removed == 0 and again.edges_removed == 0


def test_hosts_are_never_evicted():
    events = _events()
    backend = NetworkXBackend(); build_graph(events, _TOPO, backend)
    hosts_before = {n for n, d in backend._g.nodes(data=True) if d.get("node_type") == "Host"}
    # prune with a cutoff far in the future — every timestamped node goes, hosts remain
    far = max(getattr(d.get("obj"), "timestamp", None) for _n, d in backend._g.nodes(data=True)
              if getattr(d.get("obj"), "timestamp", None) is not None) + timedelta(days=3650)
    backend.prune_before(far)
    hosts_after = {n for n, d in backend._g.nodes(data=True) if d.get("node_type") == "Host"}
    assert hosts_after == hosts_before
    assert all(d.get("node_type") == "Host" for _n, d in backend._g.nodes(data=True))  # only hosts left


# ── 9.4 bounded memory ──────────────────────────────────────────────────────
def test_resident_set_bounded_under_streaming():
    events = _events()
    full = NetworkXBackend(); build_graph(events, _TOPO, full)
    full_nodes = full._g.number_of_nodes()

    # A window that covers the longest chain but is far shorter than the corpus span ⇒ eviction happens.
    window = timedelta(seconds=library_max_span_seconds(_SCEN) + 60)
    span = events[-1].timestamp - events[0].timestamp
    assert span > window, "corpus must span longer than the window for this test to be meaningful"

    sg = StreamingGraph(NetworkXBackend(), _TOPO, window=window, scenarios=_SCEN, allow_lossy=True)
    for batch in _batches(events, 12):
        sg.ingest(batch)

    g = sg.backend._g
    assert g.number_of_nodes() < full_nodes          # bounded: did NOT accumulate all history
    # every resident timestamped node is within the window of the latest event
    cutoff = sg.max_ts - window
    for _n, d in g.nodes(data=True):
        ts = getattr(d.get("obj"), "timestamp", None)
        assert ts is None or ts >= cutoff


# ── 9.6 honesty guard ───────────────────────────────────────────────────────
def test_scenario_max_span_is_sum_of_step_maxima():
    s = next(s for s in _SCEN if scenario_max_span_seconds(s) > 0)
    expected = sum(st.temporal_link.max_time_delta_seconds
                   for st in s.attack_sequence_flow.steps if st.temporal_link is not None)
    assert scenario_max_span_seconds(s) == expected
    assert library_max_span_seconds(_SCEN) == max(scenario_max_span_seconds(s) for s in _SCEN)


def test_window_smaller_than_span_refuses():
    with pytest.raises(WindowTooSmallError) as exc:
        StreamingGraph(NetworkXBackend(), _TOPO, window=timedelta(seconds=1), scenarios=_SCEN)
    assert "coverage" in str(exc.value).lower()


def test_lossy_window_warns_not_silent():
    sg = StreamingGraph(NetworkXBackend(), _TOPO, window=timedelta(seconds=1),
                        scenarios=_SCEN, allow_lossy=True)   # no raise
    rep = sg.ingest(_events()[:50])
    assert rep.lossy_warnings, "a too-small lossy window must surface warnings on every report"
    assert all(w.required_span_seconds > w.window_seconds for w in rep.lossy_warnings)


def test_window_requires_evictable_backend():
    class _Dumb:
        pass
    with pytest.raises(TypeError):
        StreamingGraph(_Dumb(), _TOPO, window=timedelta(hours=1))


def test_empty_batch_is_noop():
    sg = StreamingGraph(NetworkXBackend(), _TOPO, window=timedelta(hours=1), scenarios=_SCEN, allow_lossy=True)
    rep = sg.ingest([])
    assert rep.ingested == 0 and rep.max_ts is None and rep.prune is None
