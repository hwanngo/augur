import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from augur.auth.router import attach_auth
from augur.auth.hashing import hash_password
from augur.auth.ratelimit import RateLimiter
from augur.generative.router import attach_generative
from augur.scenarios.loader import load_scenarios


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "g.db"))
    monkeypatch.setenv("AUGUR_AI_GENERATOR", "fake")
    app = FastAPI()
    state = attach_auth(app)
    state.users.create_user("admin1", hash_password("password1234"), "admin")
    state.users.create_user("analyst1", hash_password("password1234"), "analyst")
    state.users.create_user("viewer1", hash_password("password1234"), "viewer")
    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir()
    attach_generative(app, state, scenarios_dir=scenarios_dir)
    return TestClient(app), scenarios_dir


def _auth(c, user):
    csrf = c.post("/api/auth/login", data={"username": user, "password": "password1234"}).json()["csrf_token"]
    return {"X-CSRF-Token": csrf}


def _gen(c, h, **body):
    body.setdefault("seed", "SCEN-WIN-001")
    body.setdefault("category", "credential_access")
    body.setdefault("n", 3)
    return c.post("/api/generate", json=body, headers=h)


def test_admin_generate_creates_pending(client):
    c, _ = client
    h = _auth(c, "admin1")
    r = _gen(c, h)
    assert r.status_code == 200 and r.json()["passed"] >= 1
    pend = c.get("/api/candidates", params={"status": "pending"}).json()
    assert len(pend) >= 1 and pend[0]["status"] == "pending"


def test_analyst_cannot_generate(client):
    c, _ = client
    h = _auth(c, "analyst1")
    assert _gen(c, h).status_code == 403


def test_analyst_can_list_candidates(client):
    c, _ = client
    _auth(c, "analyst1")
    assert c.get("/api/candidates").status_code == 200


def test_viewer_cannot_list_candidates(client):
    c, _ = client
    _auth(c, "viewer1")
    assert c.get("/api/candidates").status_code == 403


def test_generate_requires_csrf(client):
    c, _ = client
    c.post("/api/auth/login", data={"username": "admin1", "password": "password1234"})
    # logged in (cookie set) but NO X-CSRF-Token header
    assert c.post("/api/generate", json={"seed": "SCEN-WIN-001", "n": 1}).status_code == 403


def test_n_is_capped(client):
    c, _ = client
    h = _auth(c, "admin1")
    r = _gen(c, h, n=999)
    assert r.json()["requested"] <= 10


def test_approve_writes_scenario_and_loader_picks_it_up(client):
    c, scenarios_dir = client
    h = _auth(c, "admin1")
    _gen(c, h)
    cid = c.get("/api/candidates", params={"status": "pending"}).json()[0]["id"]
    r = c.post(f"/api/candidates/{cid}/approve", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "approved"
    from pathlib import Path
    assert Path(r.json()["path"]).is_file()
    loaded = {s.scenario_id for s in load_scenarios(str(scenarios_dir))}
    assert r.json()["scenario_id"] in loaded
    # candidate is no longer pending
    assert c.get("/api/candidates", params={"status": "pending"}).json() == []


def test_reject_sets_status(client):
    c, _ = client
    h = _auth(c, "admin1")
    _gen(c, h)
    cid = c.get("/api/candidates", params={"status": "pending"}).json()[0]["id"]
    r = c.post(f"/api/candidates/{cid}/reject", json={"reason": "not novel"}, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert c.get("/api/candidates", params={"status": "rejected"}).json()[0]["id"] == cid


def test_approve_nonexistent_404(client):
    c, _ = client
    h = _auth(c, "admin1")
    assert c.post("/api/candidates/deadbeef/approve", headers=h).status_code == 404


def test_generate_rate_limited(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "rl.db"))
    monkeypatch.setenv("AUGUR_AI_GENERATOR", "fake")
    app = FastAPI()
    state = attach_auth(app)
    state.users.create_user("admin1", hash_password("password1234"), "admin")
    sdir = tmp_path / "scenarios"; sdir.mkdir()
    attach_generative(app, state, scenarios_dir=sdir,
                      rate_limiter=RateLimiter(max_failures=1, window_seconds=900, lockout_seconds=900))
    c = TestClient(app)
    h = _auth(c, "admin1")
    assert c.post("/api/generate", json={"seed": "SCEN-WIN-001", "category": "credential_access", "n": 1}, headers=h).status_code == 200
    # second call trips the limiter
    assert c.post("/api/generate", json={"seed": "SCEN-WIN-001", "category": "credential_access", "n": 1}, headers=h).status_code == 429
