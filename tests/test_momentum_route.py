"""TDD: GET /api/momentum route (viewer, deterministic, read-only)."""
import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password

_LOGS = ["sample_data/acceptance/full_detection.jsonl"]  # SCEN-WIN-001 fires at 1.0


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
    return client.get("/api/momentum", params=params or {})


# --- C1: happy path + shape ----------------------------------------------

def test_momentum_viewer_200_shape(client):
    _login(client)
    r = _get(client, {"min_proximity": 0.0, "steps": 6})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"from", "to", "bounds", "series"}
    assert len(body["bounds"]) == 6
    win = next(s for s in body["series"] if s["scenario_id"] == "SCEN-WIN-001")
    assert set(win) == {"scenario_id", "points", "trend", "delta", "velocity"}
    assert len(win["points"]) == 6
    assert win["points"][-1] == 1.0                        # full proximity at t_N (whole feed)


def test_momentum_default_steps_is_6(client):
    _login(client)
    body = _get(client, {"min_proximity": 0.0}).json()
    assert len(body["bounds"]) == 6


def test_momentum_empty_feed_returns_empty_series(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "e.db"))
    feed = tmp_path / "empty.jsonl"; feed.write_text("")
    app = create_app(log_paths=[str(feed)])
    app.state.auth.users.create_user("v", hash_password("password1234"), "viewer")
    c = TestClient(app)
    c.post("/api/auth/login", data={"username": "v", "password": "password1234"})
    body = c.get("/api/momentum").json()
    assert body["series"] == []


# --- C2: filter, clamp, steps-range, RBAC, 422, determinism --------------

def test_min_proximity_filters_scenario_set(client):
    _login(client)
    high = _get(client, {"min_proximity": 1.0}).json()
    low = _get(client, {"min_proximity": 0.0}).json()
    high_ids = {s["scenario_id"] for s in high["series"]}
    low_ids = {s["scenario_id"] for s in low["series"]}
    assert high_ids <= low_ids                             # higher floor -> subset
    assert "SCEN-WIN-001" in high_ids                      # it fires at 1.0


def test_from_to_clamp_the_span(client):
    _login(client)
    # clamp the grid span to a sub-window of the feed; bounds[-1] <= 'to'.
    body = _get(client, {"min_proximity": 0.0, "steps": 4,
                         "from": "2026-01-01T09:00:04+00:00",
                         "to": "2026-01-01T09:00:08+00:00"}).json()
    assert len(body["bounds"]) == 4
    assert body["bounds"][-1] <= "2026-01-01T09:00:08+00:00"


def test_steps_out_of_range_clamped(client):
    _login(client)
    assert len(_get(client, {"steps": 1}).json()["bounds"]) == 3     # clamp up to 3
    assert len(_get(client, {"steps": 99}).json()["bounds"]) == 12   # clamp down to 12


def test_inverted_bounds_is_422(client):
    _login(client)
    r = _get(client, {"from": "2026-01-02T00:00:00+00:00", "to": "2026-01-01T00:00:00+00:00"})
    assert r.status_code == 422, r.text


def test_bad_iso_is_422(client):
    _login(client)
    assert _get(client, {"from": "not-a-date"}).status_code == 422


def test_viewer_rbac_enforced(client):
    r = _get(client, {"min_proximity": 0.0})               # unauthenticated
    assert r.status_code in (401, 403), r.text


def test_momentum_deterministic_across_two_calls(client):
    _login(client)
    p = {"min_proximity": 0.0, "steps": 6}
    assert _get(client, p).json() == _get(client, p).json()   # byte-identical
