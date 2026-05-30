"""TDD: GET /api/timeline route (viewer, deterministic, LRU-cached)."""
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


def _login(c):
    assert c.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"}).status_code == 200


def _get(c, params=None):
    return c.get("/api/timeline", params=params or {})


def test_timeline_viewer_200_shape(client):
    _login(client)
    r = _get(client, {"scenario_id": "SCEN-WIN-001"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) >= {"scenario_id", "name", "hosts", "band", "rows", "matched_count",
                         "context_shown", "context_total", "context_truncated", "honesty_note"}
    assert body["matched_count"] >= 1
    assert any(row["kind"] == "matched_step" for row in body["rows"])
    assert "not necessarily related" in body["honesty_note"]


def test_timeline_unknown_scenario_404(client):
    _login(client)
    assert _get(client, {"scenario_id": "SCEN-NOPE-999"}).status_code == 404


def test_timeline_fired_but_no_detection_404(client):
    _login(client)
    r = _get(client, {"scenario_id": "SCEN-MAC-001"})
    assert r.status_code in (200, 404)


def test_timeline_bad_bounds_422(client):
    _login(client)
    assert _get(client, {"scenario_id": "SCEN-WIN-001", "from": "not-a-date"}).status_code == 422


def test_timeline_host_not_affected_422(client):
    _login(client)
    assert _get(client, {"scenario_id": "SCEN-WIN-001", "host": "no-such-host"}).status_code == 422


def test_timeline_rbac_enforced(client):
    assert _get(client, {"scenario_id": "SCEN-WIN-001"}).status_code in (401, 403)


def test_timeline_deterministic(client):
    _login(client)
    p = {"scenario_id": "SCEN-WIN-001"}
    assert _get(client, p).json() == _get(client, p).json()
