from fastapi.testclient import TestClient
from augur.api.app import create_app
from augur.auth.hashing import hash_password


def test_full_pipeline_via_api():
    """logs -> normalize -> graph -> engine -> API -> ranked detections."""
    app = create_app(log_paths=["sample_data/acceptance/demo_multi_os.jsonl"])
    app.state.auth.users.create_user("t", hash_password("password1234"), "viewer")
    client = TestClient(app)
    client.post("/api/auth/login", data={"username": "t", "password": "password1234"})
    data = client.get("/api/detections").json()
    by_id = {d["scenario_id"]: d for d in data}
    assert by_id["SCEN-WIN-001"]["proximity"] == 1.0
    assert by_id["SCEN-WIN-001"]["severity"] == "CRITICAL"
    assert by_id["SCEN-LNX-001"]["proximity"] == 1.0
    # ranking: full-confidence detections sort to the top
    assert data[0]["proximity"] >= data[-1]["proximity"]
    # hunting queries present and copyable
    assert any(q.get("query") for q in by_id["SCEN-WIN-001"]["hunting_queries"])
