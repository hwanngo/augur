"""
TDD: /api/detections from/to time-window query params (Task 10).

Uses the acceptance full_detection.jsonl feed so SCEN-WIN-001 fires deterministically.
Events span 2026-01-01T09:00:00 .. 09:00:10 (+00:00).
"""
import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password

_LOGS = ["sample_data/acceptance/full_detection.jsonl"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    app = create_app(log_paths=_LOGS)
    app.state.auth.users.create_user("viewer1", hash_password("password1234"), "viewer")
    return TestClient(app)


def _login(client):
    r = client.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"})
    assert r.status_code == 200, r.text


def _get(client, params=None):
    return client.get("/api/detections", params=params or {})


def test_no_bounds_matches_precompute(client):
    _login(client)
    full = _get(client, {"min_proximity": 0.0}).json()
    ids = [d["scenario_id"] for d in full]
    assert "SCEN-WIN-001" in ids
    assert any(d["proximity"] == 1.0 for d in full)


def test_no_bounds_equals_full_span_window(client):
    """The no-bounds fast path covers exactly the same detections as a window spanning
    the entire feed — proves windowing the full feed reproduces the precompute set/order."""
    _login(client)
    no_bounds = [d["scenario_id"] for d in _get(client, {"min_proximity": 0.0}).json()]
    windowed = [d["scenario_id"] for d in _get(
        client, {"from": "1970-01-01T00:00:00+00:00",
                 "to": "9999-12-31T00:00:00+00:00", "min_proximity": 0.0}).json()]
    assert no_bounds == windowed


def test_no_bounds_order_stable(client):
    _login(client)
    a = [d["scenario_id"] for d in _get(client, {"min_proximity": 0.0}).json()]
    b = [d["scenario_id"] for d in _get(client, {"min_proximity": 0.0}).json()]
    assert a == b


def test_window_includes_events(client):
    _login(client)
    r = _get(client, {"from": "2026-01-01T08:00:00+00:00",
                      "to": "2026-01-01T10:00:00+00:00", "min_proximity": 0.0})
    assert r.status_code == 200, r.text
    ids = [d["scenario_id"] for d in r.json()]
    assert "SCEN-WIN-001" in ids


def test_window_before_events_empty(client):
    _login(client)
    r = _get(client, {"from": "2025-01-01T00:00:00+00:00",
                      "to": "2025-01-01T01:00:00+00:00", "min_proximity": 0.0})
    assert r.status_code == 200, r.text
    assert r.json() == []


def test_from_after_to_is_422(client):
    _login(client)
    r = _get(client, {"from": "2026-01-02T00:00:00+00:00", "to": "2026-01-01T00:00:00+00:00"})
    assert r.status_code == 422, r.text


def test_bad_iso_is_422(client):
    _login(client)
    r = _get(client, {"from": "not-a-date"})
    assert r.status_code == 422, r.text


def test_min_proximity_still_applies_post_window(client):
    _login(client)
    # generous window so events match, but a high min_proximity filters partials out
    r = _get(client, {"from": "2026-01-01T08:00:00+00:00",
                      "to": "2026-01-01T10:00:00+00:00", "min_proximity": 1.0})
    assert r.status_code == 200, r.text
    assert all(d["proximity"] >= 1.0 for d in r.json())


def test_viewer_rbac_enforced(client):
    # unauthenticated request rejected
    r = _get(client, {"min_proximity": 0.0})
    assert r.status_code in (401, 403), r.text


# --- F3 (D2): stall exposure parity (startup precompute + windowed) + cache-hit ---------

_PARTIAL_LOGS = ["sample_data/acceptance/no_detection_temporal_gap.jsonl"]


@pytest.fixture
def partial_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "p.db"))
    app = create_app(log_paths=_PARTIAL_LOGS)
    app.state.auth.users.create_user("viewer1", hash_password("password1234"), "viewer")
    return TestClient(app)


def test_full_detection_route_has_no_stall(client):
    """100% detections from the no-bounds precompute path carry no stall (per spec)."""
    _login(client)
    full = _get(client, {"min_proximity": 0.0}).json()
    win = next(d for d in full if d["scenario_id"] == "SCEN-WIN-001")
    assert win["proximity"] == 1.0
    assert "stall" not in win


def test_partial_detection_route_carries_stall(partial_client):
    """Partial detections via the no-bounds precompute path carry a stall dict (parity with windowed)."""
    _login(partial_client)
    r = _get(partial_client, {"min_proximity": 0.0})
    win = next(d for d in r.json() if d["scenario_id"] == "SCEN-WIN-001")
    assert 0 < win["proximity"] < 1.0
    assert "stall" in win
    assert win["stall"]["step_id"] == len(win["matched_steps"]) + 1


def test_precompute_and_windowed_stall_parity(partial_client):
    """The no-bounds precompute path and a full-span windowed query produce identical stall payloads."""
    _login(partial_client)
    no_bounds = _get(partial_client, {"min_proximity": 0.0}).json()
    windowed = _get(partial_client, {"from": "1970-01-01T00:00:00+00:00",
                                     "to": "9999-12-31T00:00:00+00:00", "min_proximity": 0.0}).json()
    nb = {d["scenario_id"]: d.get("stall") for d in no_bounds}
    wd = {d["scenario_id"]: d.get("stall") for d in windowed}
    assert nb == wd


def test_stall_computed_once_per_window_cache_hit(partial_client, monkeypatch):
    import augur.api.detections as det_mod
    calls = {"n": 0}
    real = det_mod.diagnose_stall

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(det_mod, "diagnose_stall", counting)
    _login(partial_client)
    p = {"from": "2026-01-01T08:00:00+00:00", "to": "2026-01-01T10:00:00+00:00", "min_proximity": 0.0}
    _get(partial_client, p)
    first = calls["n"]
    assert first > 0                                 # diagnosis ran on the first windowed call
    _get(partial_client, p)                          # identical bounds → cache hit
    assert calls["n"] == first                       # not recomputed on the 2nd call


def test_windowed_cache_maxsize_is_32():
    """Momentum adds up to 12 bound-windows; the LRU must hold them + detection windows w/o thrash."""
    import inspect
    import augur.api.app as app_mod
    src = inspect.getsource(app_mod.create_app)
    assert "lru_cache(maxsize=32)" in src


def test_detections_unchanged_after_cache_bump(client):
    """The maxsize bump is transparent: /api/detections returns the same ranked ids as before."""
    _login(client)
    ids = [d["scenario_id"] for d in _get(client, {"min_proximity": 0.0}).json()]
    assert "SCEN-WIN-001" in ids
    # full-span window still equals the no-bounds precompute (order preserved).
    windowed = [d["scenario_id"] for d in _get(
        client, {"from": "1970-01-01T00:00:00+00:00",
                 "to": "9999-12-31T00:00:00+00:00", "min_proximity": 0.0}).json()]
    assert ids == windowed
