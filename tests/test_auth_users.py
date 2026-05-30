import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from augur.auth.router import attach_auth
from augur.auth.hashing import hash_password


@pytest.fixture
def app_state(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "u.db"))
    app = FastAPI()
    state = attach_auth(app)
    state.users.create_user("admin1", hash_password("password1234"), "admin")
    state.users.create_user("analyst1", hash_password("password1234"), "analyst")
    return TestClient(app), state


def _auth(client, user):
    csrf = client.post("/api/auth/login", data={"username": user, "password": "password1234"}).json()["csrf_token"]
    return {"X-CSRF-Token": csrf}


def test_admin_can_crud_users(app_state):
    client, _ = app_state
    h = _auth(client, "admin1")
    r = client.post("/api/users", json={"username": "newbie", "password": "password1234", "role": "viewer"}, headers=h)
    assert r.status_code == 201
    uid = r.json()["id"]
    assert any(u["username"] == "newbie" for u in client.get("/api/users").json())
    assert client.patch(f"/api/users/{uid}", json={"role": "analyst"}, headers=h).status_code == 200
    assert client.post(f"/api/users/{uid}/reset-password", json={"password": "anotherpass99"}, headers=h).status_code == 200
    assert client.delete(f"/api/users/{uid}", headers=h).status_code == 200


def test_analyst_forbidden_from_user_mgmt(app_state):
    client, _ = app_state
    h = _auth(client, "analyst1")
    assert client.get("/api/users").status_code == 403
    assert client.post("/api/users", json={"username": "x", "password": "password1234", "role": "viewer"}, headers=h).status_code == 403


def test_cannot_delete_last_admin(app_state):
    client, state = app_state
    h = _auth(client, "admin1")
    admin = state.users.get_by_username("admin1")
    assert client.delete(f"/api/users/{admin.id}", headers=h).status_code == 409


def test_password_policy_enforced(app_state):
    client, _ = app_state
    h = _auth(client, "admin1")
    r = client.post("/api/users", json={"username": "weak", "password": "short", "role": "viewer"}, headers=h)
    assert r.status_code == 422


def test_csrf_required_for_mutation(app_state):
    client, _ = app_state
    client.post("/api/auth/login", data={"username": "admin1", "password": "password1234"})
    # no X-CSRF-Token header
    assert client.post("/api/users", json={"username": "z", "password": "password1234", "role": "viewer"}).status_code == 403


def test_bootstrap_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "b.db"))
    monkeypatch.setenv("AUGUR_ADMIN_USER", "root")
    monkeypatch.setenv("AUGUR_ADMIN_PASSWORD", "password1234")
    app = FastAPI(); state = attach_auth(app)
    assert state.users.get_by_username("root").role == "admin"


def test_cannot_remove_last_enabled_admin_with_a_disabled_admin_present(app_state):
    """Regression: a disabled admin must not satisfy the last-admin guard."""
    client, state = app_state
    h = _auth(client, "admin1")
    # add a second admin, then disable it -> admin1 is the only ENABLED admin
    admin2_id = client.post("/api/users", json={"username": "admin2", "password": "password1234", "role": "admin"}, headers=h).json()["id"]
    assert client.patch(f"/api/users/{admin2_id}", json={"disabled": True}, headers=h).status_code == 200
    admin1 = state.users.get_by_username("admin1")
    # deleting or disabling the last ENABLED admin must be blocked (409), despite admin2 existing
    assert client.delete(f"/api/users/{admin1.id}", headers=h).status_code == 409
    assert client.patch(f"/api/users/{admin1.id}", json={"disabled": True}, headers=h).status_code == 409
