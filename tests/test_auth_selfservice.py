"""Tests for self-service auth routes, session management, and audit endpoint."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from augur.auth.router import attach_auth
from augur.auth.hashing import hash_password, verify_password


@pytest.fixture
def app_state(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "ss.db"))
    app = FastAPI()
    state = attach_auth(app)
    state.users.create_user("admin1", hash_password("password1234"), "admin")
    state.users.create_user("analyst1", hash_password("password1234"), "analyst")
    state.users.create_user("user1", hash_password("password1234"), "viewer")
    return TestClient(app), state


def _login(client, user, pw="password1234"):
    r = client.post("/api/auth/login", data={"username": user, "password": pw})
    assert r.status_code == 200, f"login failed: {r.text}"
    return r.json()["csrf_token"]


# ---------------------------------------------------------------------------
# change-password
# ---------------------------------------------------------------------------

def test_change_password_success(app_state):
    client, state = app_state
    csrf = _login(client, "user1")
    r = client.post("/api/auth/change-password",
                    json={"current_password": "password1234",
                          "new_password": "newpassword5678"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    # new password works
    u = state.users.get_by_username("user1")
    assert verify_password(u.password_hash, "newpassword5678")


def test_change_password_revokes_other_sessions(app_state):
    client, state = app_state
    # Create a second session (login from another "device")
    user = state.users.get_by_username("user1")
    other_session = state.sessions.create_session(user.id)

    csrf = _login(client, "user1")
    r = client.post("/api/auth/change-password",
                    json={"current_password": "password1234",
                          "new_password": "newpassword5678"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200

    # Other session should be revoked
    assert state.sessions.get(other_session.id) is None
    # Current session still works
    assert client.get("/api/auth/me").status_code == 200


def test_change_password_wrong_current_returns_401(app_state):
    client, state = app_state
    csrf = _login(client, "user1")
    r = client.post("/api/auth/change-password",
                    json={"current_password": "wrongpassword!",
                          "new_password": "newpassword5678"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 401


def test_change_password_weak_new_returns_422(app_state):
    client, state = app_state
    csrf = _login(client, "user1")
    # Too short
    r = client.post("/api/auth/change-password",
                    json={"current_password": "password1234",
                          "new_password": "short"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 422


def test_change_password_containing_username_returns_422(app_state):
    client, state = app_state
    csrf = _login(client, "user1")
    # Contains username "user1"
    r = client.post("/api/auth/change-password",
                    json={"current_password": "password1234",
                          "new_password": "user1isverysecure999"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 422


def test_change_password_requires_csrf(app_state):
    client, state = app_state
    _login(client, "user1")
    r = client.post("/api/auth/change-password",
                    json={"current_password": "password1234",
                          "new_password": "newpassword5678"})
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# sessions list
# ---------------------------------------------------------------------------

def test_sessions_list_shows_current_true(app_state):
    client, state = app_state
    _login(client, "user1")
    r = client.get("/api/auth/sessions")
    assert r.status_code == 200
    sessions = r.json()
    assert len(sessions) >= 1
    current_sessions = [s for s in sessions if s["current"]]
    assert len(current_sessions) == 1


def test_sessions_list_shows_multiple_sessions(app_state):
    client, state = app_state
    user = state.users.get_by_username("user1")
    # Create extra sessions directly in the store
    state.sessions.create_session(user.id)
    state.sessions.create_session(user.id)
    _login(client, "user1")
    r = client.get("/api/auth/sessions")
    assert r.status_code == 200
    sessions = r.json()
    assert len(sessions) >= 3  # 2 pre-created + 1 from login
    # Only one marked current
    assert sum(1 for s in sessions if s["current"]) == 1


def test_sessions_list_requires_auth(app_state):
    client, state = app_state
    r = client.get("/api/auth/sessions")
    assert r.status_code == 401


def test_sessions_list_has_expected_fields(app_state):
    client, state = app_state
    _login(client, "user1")
    r = client.get("/api/auth/sessions")
    assert r.status_code == 200
    s = r.json()[0]
    for field in ("id", "created_at", "last_seen", "expires_at", "current"):
        assert field in s, f"missing field: {field}"


# ---------------------------------------------------------------------------
# revoke a session (DELETE /api/auth/sessions/{sid})
# ---------------------------------------------------------------------------

def test_revoke_session_invalidates_that_session(app_state):
    client, state = app_state
    user = state.users.get_by_username("user1")
    # Create a second session
    other = state.sessions.create_session(user.id)

    csrf = _login(client, "user1")
    r = client.delete(f"/api/auth/sessions/{other.id}",
                      headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    # Revoked session is gone
    assert state.sessions.get(other.id) is None


def test_revoke_session_of_other_user_returns_404(app_state):
    client, state = app_state
    other_user = state.users.get_by_username("analyst1")
    other_sess = state.sessions.create_session(other_user.id)

    csrf = _login(client, "user1")
    r = client.delete(f"/api/auth/sessions/{other_sess.id}",
                      headers={"X-CSRF-Token": csrf})
    assert r.status_code == 404


def test_revoke_nonexistent_session_returns_404(app_state):
    client, state = app_state
    csrf = _login(client, "user1")
    r = client.delete("/api/auth/sessions/totally-fake-session-id",
                      headers={"X-CSRF-Token": csrf})
    assert r.status_code == 404


def test_revoke_session_requires_csrf(app_state):
    client, state = app_state
    user = state.users.get_by_username("user1")
    other = state.sessions.create_session(user.id)
    _login(client, "user1")
    r = client.delete(f"/api/auth/sessions/{other.id}")
    assert r.status_code == 403


def test_me_returns_csrf_usable_for_mutations(app_state):
    """Regression: a reloaded SPA restores its CSRF token from /me (not only from
    login). Without /me returning csrf_token, every mutation 403s after a refresh."""
    client, state = app_state
    user = state.users.get_by_username("user1")
    other = state.sessions.create_session(user.id)

    _login(client, "user1")  # establishes the session cookie on the client

    # The reload path: /me must hand back the current session's CSRF token.
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    csrf = me.json().get("csrf_token")
    assert csrf, "/me must return a non-empty csrf_token for the current session"

    # And that token must authorize a mutation (e.g. revoking another session).
    r = client.delete(f"/api/auth/sessions/{other.id}",
                      headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    assert state.sessions.get(other.id) is None


# ---------------------------------------------------------------------------
# audit endpoint
# ---------------------------------------------------------------------------

def test_audit_endpoint_admin_only(app_state):
    client, state = app_state
    # analyst → 403
    _login(client, "analyst1")
    r = client.get("/api/audit")
    assert r.status_code == 403

    # admin → 200
    _login(client, "admin1")
    r = client.get("/api/audit")
    assert r.status_code == 200


def test_audit_endpoint_returns_events(app_state):
    client, state = app_state
    _login(client, "admin1")
    r = client.get("/api/audit")
    assert r.status_code == 200
    events = r.json()
    assert isinstance(events, list)
    assert len(events) >= 1  # at least the login event
    assert all("event" in e for e in events)


def test_audit_endpoint_limit_param(app_state):
    client, state = app_state
    # Generate several events
    for _ in range(5):
        _login(client, "analyst1")
    _login(client, "admin1")
    r = client.get("/api/audit?limit=3")
    assert r.status_code == 200
    assert len(r.json()) <= 3


# ---------------------------------------------------------------------------
# admin revoke-sessions
# ---------------------------------------------------------------------------

def test_admin_revoke_user_sessions(app_state):
    client, state = app_state
    target = state.users.get_by_username("analyst1")
    # Create sessions for analyst1
    s1 = state.sessions.create_session(target.id)
    s2 = state.sessions.create_session(target.id)

    csrf = _login(client, "admin1")
    r = client.post(f"/api/users/{target.id}/revoke-sessions",
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    # Both sessions gone
    assert state.sessions.get(s1.id) is None
    assert state.sessions.get(s2.id) is None


def test_admin_revoke_sessions_requires_admin(app_state):
    client, state = app_state
    target = state.users.get_by_username("user1")
    csrf = _login(client, "analyst1")
    r = client.post(f"/api/users/{target.id}/revoke-sessions",
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403
