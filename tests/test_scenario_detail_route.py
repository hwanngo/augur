import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password


@pytest.fixture
def client():
    app = create_app(log_paths=["sample_data/acceptance/demo_multi_os.jsonl"])
    app.state.auth.users.create_user("viewer1", hash_password("password1234"), "viewer")
    return TestClient(app)


def _auth(c, u):
    c.post("/api/auth/login", data={"username": u, "password": "password1234"})


def test_get_scenario_detail_viewer_ok(client):
    _auth(client, "viewer1")
    r = client.get("/api/scenarios/SCEN-WIN-001")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scenario_id"] == "SCEN-WIN-001"
    assert set(body) == {
        "scenario_id", "name", "severity", "os_family",
        "applicable_zones", "mitre", "step_count", "steps",
    }
    # MITRE shape
    assert isinstance(body["mitre"], list) and body["mitre"]
    assert set(body["mitre"][0]) == {"tactic", "technique"}
    # Step bodies present + correctly shaped
    steps = body["steps"]
    assert isinstance(steps, list) and len(steps) == body["step_count"] >= 1
    for s in steps:
        assert set(s) == {"step_id", "name", "temporal_link", "matching_criteria"}
        assert "Node_Type" in s["matching_criteria"]
    # step_ids contiguous 1..N; step 1 has no temporal_link
    assert [s["step_id"] for s in steps] == list(range(1, len(steps) + 1))
    assert steps[0]["temporal_link"] is None
    if len(steps) > 1:
        assert steps[1]["temporal_link"]["previous_step"] == 1


def test_get_scenario_detail_unknown_404(client):
    _auth(client, "viewer1")
    r = client.get("/api/scenarios/SCEN-NOPE-999")
    assert r.status_code == 404, r.text


def test_get_scenario_detail_requires_auth(client):
    r = client.get("/api/scenarios/SCEN-WIN-001")
    assert r.status_code == 401, r.text


def test_get_scenario_detail_deterministic(client):
    _auth(client, "viewer1")
    a = client.get("/api/scenarios/SCEN-WIN-001")
    b = client.get("/api/scenarios/SCEN-WIN-001")
    assert a.status_code == b.status_code == 200
    assert a.json() == b.json()          # byte-identical across calls
