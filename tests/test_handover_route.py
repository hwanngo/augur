"""TDD: GET /api/handover route (viewer, deterministic, read-only, board diff only)."""
import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password

_LOGS = ["sample_data/corpus/enterprise_day.jsonl"]


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
    return client.get("/api/handover", params=params or {})


def test_handover_viewer_200_shape(client):
    _login(client)
    r = _get(client, {"min_proximity": 0.0})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"window", "meta", "detections", "host_risk", "summary"}
    assert set(body["detections"]) == {"new", "escalated", "decayed", "gone", "unchanged_count"}
    assert set(body["host_risk"]) == {"entered", "left", "escalated", "deescalated"}
    assert body["meta"]["basis"] == "corpus-windowed"
    assert "triage" not in body


def test_handover_default_bounds_use_corpus_midpoint_and_max(client):
    _login(client)
    body = _get(client, {"min_proximity": 0.0}).json()
    assert body["window"]["from"] < body["window"]["to"]


def test_handover_explicit_full_window_shows_detections_as_new(client):
    _login(client)
    body = _get(client, {"min_proximity": 0.30,
                         "from": "1970-01-01T00:00:00+00:00",
                         "to": "2999-01-01T00:00:00+00:00"}).json()
    assert body["detections"]["new"]
    assert body["detections"]["gone"] == []


def test_handover_inverted_bounds_is_422(client):
    _login(client)
    r = _get(client, {"from": "2026-02-01T00:00:00+00:00", "to": "2026-01-01T00:00:00+00:00"})
    assert r.status_code == 422, r.text


def test_handover_bad_iso_is_422(client):
    _login(client)
    assert _get(client, {"from": "not-a-date"}).status_code == 422


def test_handover_viewer_rbac_enforced(client):
    assert _get(client, {"min_proximity": 0.0}).status_code in (401, 403)


def test_handover_deterministic_across_two_calls(client):
    _login(client)
    p = {"min_proximity": 0.0, "from": "2026-01-01T00:00:00+00:00", "to": "2026-12-31T00:00:00+00:00"}
    assert _get(client, p).json() == _get(client, p).json()


def test_handover_empty_feed_returns_empty_diff(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "e.db"))
    feed = tmp_path / "empty.jsonl"; feed.write_text("")
    app = create_app(log_paths=[str(feed)])
    app.state.auth.users.create_user("v", hash_password("password1234"), "viewer")
    c = TestClient(app)
    c.post("/api/auth/login", data={"username": "v", "password": "password1234"})
    body = c.get("/api/handover").json()
    assert body["detections"]["new"] == [] and body["detections"]["gone"] == []
    assert body["host_risk"]["entered"] == []
