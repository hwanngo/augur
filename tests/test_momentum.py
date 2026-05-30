"""TDD: proximity-momentum span + pure series helpers (infra-free, deterministic)."""
from datetime import datetime, timezone

from augur.api.momentum import corpus_time_span, build_time_grid, momentum_series

_FULL = ["sample_data/acceptance/full_detection.jsonl"]  # events 2026-01-01T09:00:00..09:00:10 +00:00


# --- A1: corpus_time_span -------------------------------------------------

def test_corpus_time_span_returns_real_min_max():
    lo, hi = corpus_time_span(_FULL)
    assert lo == datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    assert hi == datetime(2026, 1, 1, 9, 0, 10, tzinfo=timezone.utc)
    assert lo.tzinfo is not None and hi.tzinfo is not None


def test_corpus_time_span_empty_feed_is_none(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    assert corpus_time_span([str(empty)]) == (None, None)


def test_corpus_time_span_coerces_naive_timestamp_to_utc(tmp_path):
    """[AUDIT #1] an offset-less source timestamp normalizes to a NAIVE datetime; the span helper
    must assume-UTC so later comparison against aware _EPOCH_MIN/t_i never raises TypeError."""
    # offset-less timestamp on an otherwise valid windows_sysmon (legacy, no source_type) line.
    line = ('{"timestamp": "2026-01-01T09:00:05", "host": "HR_User_PC", "event_id": 1, '
            '"process_guid": "{g}", "process_name": "powershell.exe", "Image": "C:\\\\x.exe"}')
    f = tmp_path / "naive.jsonl"
    f.write_text(line + "\n")
    lo, hi = corpus_time_span([str(f)])
    assert lo is not None and lo.tzinfo is not None        # aware (assumed UTC), did not raise
    assert lo == datetime(2026, 1, 1, 9, 0, 5, tzinfo=timezone.utc)


# --- A2: build_time_grid --------------------------------------------------

def test_build_time_grid_n_evenly_spaced_ending_at_max():
    lo = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    hi = datetime(2026, 1, 1, 9, 0, 10, tzinfo=timezone.utc)
    grid = build_time_grid(lo, hi, steps=5)
    assert len(grid) == 5
    assert grid[-1] == hi                                  # t_N == max_ts
    assert grid == sorted(grid)                            # strictly ascending
    # t_i = lo + (hi-lo)*i/N  for i=1..N -> 2,4,6,8,10 seconds
    assert [t.second for t in grid] == [2, 4, 6, 8, 10]


def test_build_time_grid_degenerate_span_collapses_flat():
    """[AUDIT #2] min_ts == max_ts (single timestamp): all t_i collapse to max_ts, no divide-by-zero."""
    t = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    grid = build_time_grid(t, t, steps=4)
    assert grid == [t, t, t, t]


def test_build_time_grid_clamps_span_by_from_to_not_lower_bound():
    """[AUDIT #3] from/to clamp only the GRID SPAN [min_ts,max_ts]; the window lower bound stays
    _EPOCH_MIN (applied later in the route). build_time_grid only sees the clamped span."""
    # span clamped to [09:00:04, 09:00:08] by the caller; grid runs over THAT, ending at 08.
    grid = build_time_grid(datetime(2026, 1, 1, 9, 0, 4, tzinfo=timezone.utc),
                           datetime(2026, 1, 1, 9, 0, 8, tzinfo=timezone.utc), steps=4)
    assert grid[-1] == datetime(2026, 1, 1, 9, 0, 8, tzinfo=timezone.utc)
    assert grid[0] >= datetime(2026, 1, 1, 9, 0, 4, tzinfo=timezone.utc)


# --- A3: momentum_series --------------------------------------------------

def _windowed_stub(by_bound):
    """Return a fn mapping a bound-iso -> list of public detection dicts, like _windowed_cached."""
    return lambda iso: by_bound[iso]


def _bounds(n):
    base = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    return [base.replace(second=s) for s in range(1, n + 1)]


def test_momentum_series_ascending_scenario_is_rising():
    b = _bounds(4)
    iso = [t.isoformat() for t in b]
    # SCEN-A accrues prefix: 0.25 -> 0.50 -> 0.75 -> 1.0 across the 4 bounds.
    by_bound = {
        iso[0]: [{"scenario_id": "SCEN-A", "proximity": 0.25}],
        iso[1]: [{"scenario_id": "SCEN-A", "proximity": 0.50}],
        iso[2]: [{"scenario_id": "SCEN-A", "proximity": 0.75}],
        iso[3]: [{"scenario_id": "SCEN-A", "proximity": 1.00}],
    }
    series = momentum_series(_windowed_stub(by_bound), b, ["SCEN-A"], steps=4)
    s = next(x for x in series if x["scenario_id"] == "SCEN-A")
    assert s["points"] == [0.25, 0.5, 0.75, 1.0]
    assert s["trend"] == "rising"
    assert s["delta"] == round(1.0 - 0.25, 4)
    assert s["velocity"] == round((1.0 - 0.25) / 3, 4)


def test_momentum_series_full_from_first_bound_is_flat():
    b = _bounds(3); iso = [t.isoformat() for t in b]
    by_bound = {i: [{"scenario_id": "SCEN-A", "proximity": 1.0}] for i in iso}
    s = momentum_series(_windowed_stub(by_bound), b, ["SCEN-A"], steps=3)[0]
    assert s["points"] == [1.0, 1.0, 1.0]
    assert s["trend"] == "flat" and s["delta"] == 0.0 and s["velocity"] == 0.0


def test_momentum_series_absent_at_early_bounds_leads_with_zeros():
    b = _bounds(3); iso = [t.isoformat() for t in b]
    by_bound = {iso[0]: [], iso[1]: [], iso[2]: [{"scenario_id": "SCEN-A", "proximity": 0.5}]}
    s = momentum_series(_windowed_stub(by_bound), b, ["SCEN-A"], steps=3)[0]
    assert s["points"] == [0.0, 0.0, 0.5]
    assert s["trend"] == "rising"


def test_momentum_series_falling_below_threshold_is_flat():
    b = _bounds(3); iso = [t.isoformat() for t in b]
    # tiny drop of 0.04 (< 0.05 band) -> flat, not falling.
    by_bound = {iso[0]: [{"scenario_id": "SCEN-A", "proximity": 0.50}],
                iso[1]: [{"scenario_id": "SCEN-A", "proximity": 0.48}],
                iso[2]: [{"scenario_id": "SCEN-A", "proximity": 0.46}]}
    s = momentum_series(_windowed_stub(by_bound), b, ["SCEN-A"], steps=3)[0]
    assert s["trend"] == "flat"


def test_momentum_series_steps_count_matches_bounds():
    b = _bounds(6); iso = [t.isoformat() for t in b]
    by_bound = {iso[k]: [{"scenario_id": "SCEN-A", "proximity": round(0.16 * (k + 1), 4)}]
                for k in range(6)}
    s = momentum_series(_windowed_stub(by_bound), b, ["SCEN-A"], steps=6)[0]
    assert len(s["points"]) == 6


def test_momentum_series_deterministic_across_two_calls():
    b = _bounds(4); iso = [t.isoformat() for t in b]
    by_bound = {iso[k]: [{"scenario_id": "SCEN-A", "proximity": round(0.25 * (k + 1), 4)}]
                for k in range(4)}
    a = momentum_series(_windowed_stub(by_bound), b, ["SCEN-A"], steps=4)
    c = momentum_series(_windowed_stub(by_bound), b, ["SCEN-A"], steps=4)
    assert a == c


# --- A4: no-engine-import guard ------------------------------------------

def test_momentum_module_does_not_import_engine():
    """Invariant: momentum is pure series math over public dicts — no engine/scoring/matcher import."""
    import augur.api.momentum as m
    src = open(m.__file__).read()
    assert "from augur.engine" not in src and "import augur.engine" not in src
    assert "run_engine" not in src
