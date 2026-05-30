"""Optional time-window eviction capability for graph backends.

Deliberately a SEPARATE Protocol, NOT a method on the `GraphBackend` ABC: adding it to the ABC would
force a `Neo4jBackend` implementation. In v1 only `NetworkXBackend` implements it; the `StreamingGraph`
driver feature-detects the capability via `isinstance(backend, EvictableBackend)`.

No wall-clock anywhere — the cutoff is supplied by the caller and is derived from event timestamps.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class PruneStats:
    nodes_removed: int
    edges_removed: int
    cutoff: datetime


@runtime_checkable
class EvictableBackend(Protocol):
    def prune_before(self, cutoff: datetime) -> PruneStats:
        """Evict everything originating strictly before ``cutoff`` (see NetworkXBackend for semantics)."""
        ...
