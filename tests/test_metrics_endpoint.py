# tests/test_metrics_endpoint.py
import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from augur.auth.router import attach_auth
from augur.auth.hashing import hash_password


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "m.db"))
    app = FastAPI()
    state = attach_auth(app)
    state.users.create_user("admin1", hash_password("password1234"), "admin")
    state.users.create_user("analyst1", hash_password("password1234"), "analyst")

    from augur.api.metrics_endpoint import platform_metrics
    from augur.auth.deps import require_role

    @app.get("/api/metrics")
    def metrics(_=Depends(require_role("admin"))):
        return platform_metrics(state)

    return TestClient(app)


def _login(client, user, pw="password1234"):
    return client.post("/api/auth/login", data={"username": user, "password": pw})


def test_metrics_as_admin_returns_200_with_required_keys(client):
    _login(client, "admin1")
    r = client.get("/api/metrics")
    assert r.status_code == 200
    data = r.json()
    assert "users" in data
    assert "alerts" in data
    assert "candidates" in data
    assert "scenarios" in data


def test_metrics_users_structure(client):
    _login(client, "admin1")
    r = client.get("/api/metrics")
    assert r.status_code == 200
    users = r.json()["users"]
    assert "total" in users
    assert "by_role" in users
    assert "disabled" in users
    assert users["total"] == 2  # admin1 + analyst1


def test_metrics_sessions_active_key(client):
    _login(client, "admin1")
    r = client.get("/api/metrics")
    assert r.status_code == 200
    assert "sessions_active" in r.json()


def test_metrics_as_analyst_returns_403(client):
    _login(client, "analyst1")
    r = client.get("/api/metrics")
    assert r.status_code == 403


def test_metrics_unauthenticated_returns_401(client):
    r = client.get("/api/metrics")
    assert r.status_code == 401
