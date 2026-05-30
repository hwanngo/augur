import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from augur.auth.router import attach_auth
from augur.auth.deps import require_role
from augur.auth.config import AuthConfig


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    app = FastAPI()
    state = attach_auth(app)                       # creates store, mounts /api/auth + /api/users
    # seed a viewer + admin directly
    from augur.auth.hashing import hash_password
    state.users.create_user("viewer1", hash_password("password1234"), "viewer")
    state.users.create_user("admin1", hash_password("password1234"), "admin")

    @app.get("/api/secret")
    def secret(u=Depends(require_role("viewer"))):
        return {"who": u.username}

    return TestClient(app)


def _login(client, user, pw="password1234"):
    r = client.post("/api/auth/login", data={"username": user, "password": pw})
    return r


def test_login_sets_cookie_and_me(client):
    r = _login(client, "viewer1")
    assert r.status_code == 200 and "csrf_token" in r.json()
    assert client.cookies.get("fs_session")
    me = client.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["username"] == "viewer1"


def test_unauthenticated_is_401(client):
    assert client.get("/api/secret").status_code == 401
    assert client.get("/api/auth/me").status_code == 401


def test_wrong_password_401(client):
    assert _login(client, "viewer1", "nope").status_code == 401


def test_logout_clears_session(client):
    csrf = _login(client, "viewer1").json()["csrf_token"]
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_rate_limit_locks_out(client):
    for _ in range(5):
        _login(client, "viewer1", "bad")
    assert _login(client, "viewer1", "bad").status_code == 429
