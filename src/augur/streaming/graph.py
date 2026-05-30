"""StreamingGraph — a bounded rolling-time-window driver over a graph backend.

Opt-in and OFF by default. ``window=None`` ⇒ ``prune_before`` is NEVER called ⇒ the resident graph is
the exact accumulation a one-shot ``build_graph`` produces (byte-identical). A finite ``window`` evicts
everything whose event timestamp is older than ``max_event_ts_seen − window`` after each batch, so
resident memory is O(window) not O(all history).

Determinism: the cutoff derives ONLY from ingested event timestamps — never ``now()``. The engine reads
``.backend`` exactly as today.

Honesty: a window shorter than a scenario's max temporal span evicts a chain's early steps before it can
complete, so that detection is missed. We refuse such a window by default; ``allow_lossy=True`` opts in but
surfaces a structured warning on every report so the SOC can never read an absent detection as "clean."
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from augur.graph.builder import IngestState, ingest_events
from augur.graph.eviction import EvictableBackend, PruneStats


class WindowTooSmallError(ValueError):
    """Raised when a finite window cannot cover the scenario library's longest temporal chain."""


@dataclass(frozen=True)
class LossyWindowWarning:
    scenario_id: str
    required_span_seconds: int
    window_seconds: int


@dataclass
class IngestReport:
    ingested: int
    max_ts: datetime | None
    prune: PruneStats | None
    lossy_warnings: list[LossyWindowWarning] = field(default_factory=list)


def scenario_max_span_seconds(scenario) -> int:
    """Worst-case end-to-end span a full chain can occupy = sum of each linked step's max time delta.
    Pure function of the scenario (no clock, no data)."""
    return sum(s.temporal_link.max_time_delta_seconds
               for s in scenario.attack_sequence_flow.steps if s.temporal_link is not None)


def library_max_span_seconds(scenarios) -> int:
    return max((scenario_max_span_seconds(s) for s in scenarios), default=0)


def under_covered(scenarios, window: timedelta) -> list[LossyWindowWarning]:
    """Scenarios whose max span exceeds the window (their detection cannot be guaranteed)."""
    w = int(window.total_seconds())
    out = []
    for s in scenarios:
        span = scenario_max_span_seconds(s)
        if span > w:
            out.append(LossyWindowWarning(scenario_id=s.scenario_id, required_span_seconds=span,
                                          window_seconds=w))
    return out


class StreamingGraph:
    def __init__(self, backend, topology, *, window: timedelta | None = None,
                 scenarios=None, allow_lossy: bool = False) -> None:
        if window is not None and not isinstance(backend, EvictableBackend):
            raise TypeError("backend does not support eviction; v1 windowing is NetworkX-only")
        self._backend = backend
        self._topology = topology
        self._window = window
        self._state = IngestState()
        self._max_ts: datetime | None = None
        self._lossy: list[LossyWindowWarning] = []
        if window is not None and scenarios:
            self._lossy = under_covered(scenarios, window)
            if self._lossy and not allow_lossy:
                w0 = self._lossy[0]
                raise WindowTooSmallError(
                    f"window {int(window.total_seconds())}s < scenario {w0.scenario_id} span "
                    f"{w0.required_span_seconds}s — coverage cannot be guaranteed. Raise the window "
                    f"or pass allow_lossy=True to accept reduced coverage.")

    @property
    def backend(self):
        """The live snapshot the engine reads, exactly as today: run_engine(sg.backend, scenarios)."""
        return self._backend

    @property
    def max_ts(self) -> datetime | None:
        return self._max_ts

    def ingest(self, batch: list) -> IngestReport:
        """Append a batch (upsert, no reset), advance max_ts, then evict everything older than the window.
        Empty batch is a deterministic no-op (no advance, no prune)."""
        ingest_events(batch, self._topology, self._backend, state=self._state)
        prune = None
        if batch:
            bmax = max(e.timestamp for e in batch)
            if self._max_ts is None or bmax > self._max_ts:
                self._max_ts = bmax
            if self._window is not None:
                prune = self._backend.prune_before(self._max_ts - self._window)
        return IngestReport(ingested=len(batch), max_ts=self._max_ts, prune=prune,
                            lossy_warnings=list(self._lossy))
