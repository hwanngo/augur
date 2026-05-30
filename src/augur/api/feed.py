"""Cached normalized-feed loader.

The on-disk JSONL feed is static for the life of the process. Without caching,
every windowed-detection / IOC-match / rarity / timeline request re-reads and
re-normalizes the ENTIRE corpus from disk — a DoS surface for any authenticated
viewer, and wasted I/O on every cache-missed window. This memoizes the
read+normalize step (keyed on the path set) so it happens once.

Events are returned in file order (the natural output of ``normalize_events``);
callers that need a sort apply their own (e.g. ``windowed_detections`` sorts by
timestamp), matching their prior behavior exactly.
"""
from functools import lru_cache

from augur.ingest.jsonl import read_jsonl
from augur.normalize.registry import normalize_events
from augur.normalize.model import NormalizedEvent


@lru_cache(maxsize=4)
def _load_normalized(paths: tuple[str, ...]) -> tuple[NormalizedEvent, ...]:
    raws: list[dict] = []
    for p in paths:
        raws.extend(read_jsonl(p))
    return tuple(normalize_events(raws))


def load_normalized(log_paths) -> list[NormalizedEvent]:
    """Return the normalized feed (file order), reading+normalizing at most once
    per distinct path set. Returns a fresh list so callers may sort/mutate freely."""
    return list(_load_normalized(tuple(log_paths)))
