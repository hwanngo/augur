import pytest
from fastapi.testclient import TestClient
from augur.api.app import create_app
from augur.auth.hashing import hash_password


@pytest.fixture
def client():
    app = create_app(log_paths=["sample_data/acceptance/demo_multi_os.jsonl"])
    app.state.auth.users.create_user("t", hash_password("password1234"), "viewer")
    c = TestClient(app)
    c.post("/api/auth/login", data={"username": "t", "password": "password1234"})
    return c


def test_health():
    app = create_app(log_paths=["sample_data/acceptance/demo_multi_os.jsonl"])
    assert TestClient(app).get("/api/health").json() == {"status": "ok", "real_data": False}


def test_detections_ranked(client):
    r = client.get("/api/detections")
    assert r.status_code == 200
    data = r.json()
    assert data[0]["scenario_id"] == "SCEN-WIN-001"
    assert data[0]["proximity"] == 1.0
    assert "hunting_queries" in data[0]


def test_detections_min_proximity_param(client):
    r = client.get("/api/detections?min_proximity=0.9")
    ids = [d["scenario_id"] for d in r.json()]
    assert "SCEN-LNX-002" not in ids  # 0.3333 filtered out


def test_scenarios_and_topology_endpoints(client):
    assert len(client.get("/api/scenarios").json()) == 40   # the v2 library
    assert "assets" in client.get("/api/topology").json()


def test_scenarios_view_exposes_os_family_and_applicable_zones(client):
    r = client.get("/api/scenarios")
    assert r.status_code == 200
    rows = r.json()
    win = next(s for s in rows if s["scenario_id"] == "SCEN-WIN-001")
    assert win["os_family"] == "windows"
    assert "User_Endpoint" in win["applicable_zones"]
    assert isinstance(win["applicable_zones"], list) and win["applicable_zones"]
    # additive: existing keys untouched
    assert {"scenario_id", "name", "severity", "steps", "mitre"} <= set(win)
