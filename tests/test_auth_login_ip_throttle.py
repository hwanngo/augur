"""TDD: login throttles by client IP (password-spray defense) in addition to
username, and only trusts X-Forwarded-For when explicitly configured."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from augur.auth.router import attach_auth, _client_ip
from augur.auth.hashing import hash_password


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "g.db"))
    monkeypatch.setenv("AUGUR_RL_IP_MAX", "8")  # small cap so the test is fast
    a = FastAPI()
    state = attach_auth(a)
    state.users.create_user("admin1", hash_password("password1234"), "admin")
    return a


def test_password_spray_across_usernames_locks_the_ip(app):
    client = TestClient(app)
    # Each attempt uses a DISTINCT username so the per-username limiter never trips;
    # only the per-IP limiter can stop this. After the IP cap we must get 429.
    got_429 = False
    for i in range(12):
        r = client.post("/api/auth/login",
                        data={"username": f"ghost{i}", "password": "wrong"})
        if r.status_code == 429:
            got_429 = True
            break
    assert got_429, "per-IP throttle did not engage on a username-rotating spray"


def test_login_rejects_oversized_password_without_hashing(app, monkeypatch):
    # The pre-auth DoS guard: an absurdly long password is rejected 401 before
    # any argon2 verify runs (so it can't burn CPU on the spray surface).
    import augur.auth.router as r
    calls = {"n": 0}
    real = r.verify_password
    monkeypatch.setattr(r, "verify_password", lambda *a, **k: (calls.__setitem__("n", calls["n"] + 1), real(*a, **k))[1])
    client = TestClient(app)
    huge = "a" * 5000
    resp = client.post("/api/auth/login", data={"username": "admin1", "password": huge})
    assert resp.status_code == 401
    assert calls["n"] == 0, "argon2 verify must not run for an oversized password"


def test_client_ip_ignores_xff_by_default(monkeypatch):
    from augur.auth import config as cfg
    monkeypatch.delenv("AUGUR_TRUST_PROXY", raising=False)

    class _Req:
        headers = {"x-forwarded-for": "1.2.3.4"}

        class client:  # noqa: N801
            host = "10.0.0.1"

    # Default: do NOT trust the header; use the socket peer.
    assert _client_ip(_Req()) == "10.0.0.1"


def test_client_ip_uses_xff_first_hop_when_trusted(monkeypatch):
    monkeypatch.setenv("AUGUR_TRUST_PROXY", "1")

    class _Req:
        headers = {"x-forwarded-for": "1.2.3.4, 10.0.0.9"}

        class client:  # noqa: N801
            host = "10.0.0.1"

    assert _client_ip(_Req()) == "1.2.3.4"
