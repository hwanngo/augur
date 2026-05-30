"""Proximity Momentum helpers (additive, read-only, deterministic).

Pure span + series math for GET /api/momentum. No engine import beyond reading the public
detection dicts produced by windowed_detections; no persistence. The engine is never re-touched.
"""
from datetime import datetime, timezone

from augur.ingest.jsonl import read_jsonl
from augur.normalize.ecs import normalize_events

_RISE_BAND = 0.05   # below one prefix-step on most 3-8 step scenarios; any real prefix gain registers


def _aware(ts: datetime) -> datetime:
    # [AUDIT #1] normalizers do not coerce tz; a naive source timestamp would raise TypeError when
    # compared to the aware _EPOCH_MIN / t_i. Assume UTC for naive values so comparisons never raise.
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)


def corpus_time_span(log_paths) -> tuple[datetime | None, datetime | None]:
    """Return (min_ts, max_ts) of all normalized events across log_paths, or (None, None) if empty.

    Reuses the same read_jsonl -> normalize_events path the windowed builder uses; every timestamp is
    forced tz-aware (assume-UTC fallback). Intended to be computed ONCE at startup and closed over.
    """
    raws: list[dict] = []
    for p in log_paths:
        raws.extend(read_jsonl(p))
    stamps = [_aware(e.timestamp) for e in normalize_events(raws)]
    if not stamps:
        return None, None
    return min(stamps), max(stamps)


def build_time_grid(min_ts: datetime, max_ts: datetime, *, steps: int) -> list[datetime]:
    """N evenly-spaced cumulative UPPER bounds t_1<...<t_N over [min_ts, max_ts] with t_N == max_ts:
    t_i = min_ts + (max_ts - min_ts) * i / N  for i = 1..N.

    [AUDIT #2] degenerate min_ts == max_ts -> every t_i collapses to max_ts (flat line); no div-by-zero
    (span is a timedelta scaled by i/N, which is the zero timedelta when span is zero).
    [AUDIT #3] callers pass the span ALREADY clamped by from/to; this helper never touches the window
    lower bound (which stays _EPOCH_MIN in the route).
    """
    span = max_ts - min_ts                                 # timedelta; zero when degenerate
    return [min_ts + span * (i / steps) for i in range(1, steps + 1)]


def momentum_series(windowed_at, bounds, scenario_ids, *, steps) -> list[dict]:
    """Pivot N windowed result-lists (one per bound) by scenario_id into per-scenario series.

    windowed_at: callable bound_iso -> list[public detection dict] (the LRU _windowed_cached closure).
    bounds:      the N ascending datetimes from build_time_grid (len == steps).
    scenario_ids: the scenario set (full-window proximity >= min_proximity) to project.

    points[i] = round(proximity_at_bound_i, 4) or 0.0 if absent; delta = points[-1]-points[0];
    velocity = delta/(N-1); trend rising>0.05 / falling<-0.05 / else flat.
    """
    # One pass per bound (N engine passes total, scenario-independent): each call returns ALL scenarios.
    per_bound = [{d["scenario_id"]: round(d["proximity"], 4) for d in windowed_at(b.isoformat())}
                 for b in bounds]
    out: list[dict] = []
    for sid in scenario_ids:
        points = [pb.get(sid, 0.0) for pb in per_bound]
        delta = round(points[-1] - points[0], 4)
        velocity = round(delta / (steps - 1), 4) if steps > 1 else 0.0
        trend = "rising" if delta > _RISE_BAND else "falling" if delta < -_RISE_BAND else "flat"
        out.append({"scenario_id": sid, "points": points,
                    "trend": trend, "delta": delta, "velocity": velocity})
    return out
