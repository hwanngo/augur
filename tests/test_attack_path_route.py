"""TDD: GET /api/attack_paths route (viewer, deterministic, read-only)."""
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
    return c.get("/api/attack_paths", params=params or {})


def test_attack_paths_viewer_200_shape(client):
    _login(client)
    r = _get(client, {"min_proximity": 0.0})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"paths", "honesty_note", "from", "to"}
    assert "not a network-reachability" in body["honesty_note"]
    if body["paths"]:
        p = body["paths"][0]
        assert set(p) >= {"entry", "target", "realized_pct", "stops", "honesty_note"}
        assert p["target"]["criticality"] == "CRITICAL"
        assert all(s["status"] in ("observed", "hypothetical") for s in p["stops"])


def test_attack_paths_unknown_entry_zone_422(client):
    _login(client)
    assert _get(client, {"entry_zone": "NotAZone"}).status_code == 422


def test_attack_paths_unknown_target_422(client):
    _login(client)
    assert _get(client, {"target": "no-such-host"}).status_code == 422


def test_attack_paths_inverted_bounds_422(client):
    _login(client)
    r = _get(client, {"from": "2026-02-01T00:00:00+00:00", "to": "2026-01-01T00:00:00+00:00"})
    assert r.status_code == 422


def test_attack_paths_rbac_enforced(client):
    assert _get(client, {"min_proximity": 0.0}).status_code in (401, 403)


def test_attack_paths_deterministic(client):
    _login(client)
    p = {"min_proximity": 0.0}
    assert _get(client, p).json() == _get(client, p).json()
