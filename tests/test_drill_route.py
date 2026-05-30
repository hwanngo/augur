import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password


@pytest.fixture
def client():
    app = create_app(log_paths=["sample_data/acceptance/demo_multi_os.jsonl"])
    app.state.auth.users.create_user("analyst1", hash_password("password1234"), "analyst")
    app.state.auth.users.create_user("viewer1", hash_password("password1234"), "viewer")
    return TestClient(app)


def _auth(c, u):
    csrf = c.post("/api/auth/login",
                  data={"username": u, "password": "password1234"}).json()["csrf_token"]
    return {"X-CSRF-Token": csrf}


def test_post_drill_analyst_returns_detection(client):
    h = _auth(client, "analyst1")
    r = client.post("/api/drill",
                    json={"scenario_id": "SCEN-WIN-001", "host": "HR_User_PC"}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scenario_id"] == "SCEN-WIN-001"
    assert body["host"] == "HR_User_PC"
    assert body["detection"]["proximity"] == 1.0
    fs = body["feed_summary"]
    assert set(fs) == {"total_events", "baseline_events", "injected_events"}


def test_post_drill_viewer_forbidden(client):
    h = _auth(client, "viewer1")
    r = client.post("/api/drill",
                    json={"scenario_id": "SCEN-WIN-001", "host": "HR_User_PC"}, headers=h)
    assert r.status_code == 403, r.text


def test_post_drill_no_csrf_forbidden(client):
    client.post("/api/auth/login", data={"username": "analyst1", "password": "password1234"})
    r = client.post("/api/drill",
                    json={"scenario_id": "SCEN-WIN-001", "host": "HR_User_PC"})
    assert r.status_code == 403, r.text


def test_post_drill_unknown_host_422(client):
    h = _auth(client, "analyst1")
    r = client.post("/api/drill",
                    json={"scenario_id": "SCEN-WIN-001", "host": "NOPE"}, headers=h)
    assert r.status_code == 422, r.text
    assert "NOPE" in r.json()["detail"]


def test_post_drill_os_mismatch_422(client):
    h = _auth(client, "analyst1")
    r = client.post("/api/drill",
                    json={"scenario_id": "SCEN-LNX-001", "host": "HR_User_PC"}, headers=h)
    assert r.status_code == 422, r.text


def test_post_drill_unknown_scenario_422(client):
    h = _auth(client, "analyst1")
    r = client.post("/api/drill",
                    json={"scenario_id": "SCEN-NOPE-999", "host": "HR_User_PC"}, headers=h)
    assert r.status_code == 422, r.text


def test_post_drill_response_shape(client):
    h = _auth(client, "analyst1")
    r = client.post("/api/drill",
                    json={"scenario_id": "SCEN-WIN-001", "host": "HR_User_PC"}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"detection", "feed_summary", "scenario_id", "host", "mode", "note"}
    assert body["mode"] == "inject"


def test_post_drill_extra_field_422(client):
    h = _auth(client, "analyst1")
    r = client.post("/api/drill",
                    json={"scenario_id": "SCEN-WIN-001", "host": "HR_User_PC", "bogus": 1},
                    headers=h)
    assert r.status_code == 422, r.text
