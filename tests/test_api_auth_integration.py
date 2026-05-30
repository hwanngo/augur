import pytest
from fastapi.testclient import TestClient
from augur.api.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "i.db"))
    app = create_app(log_paths=["sample_data/acceptance/demo_multi_os.jsonl"])
    from augur.auth.hashing import hash_password
    st = app.state.auth
    st.users.create_user("viewer1", hash_password("password1234"), "viewer")
    return TestClient(app)


def test_health_public_but_data_protected(client):
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/detections").status_code == 401
    assert client.get("/api/scenarios").status_code == 401


def test_viewer_can_read_data(client):
    client.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"})
    assert client.get("/api/detections").status_code == 200
    assert client.get("/api/scenarios").status_code == 200
    assert client.get("/api/topology").status_code == 200
