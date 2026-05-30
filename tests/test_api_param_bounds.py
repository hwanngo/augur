"""TDD: float query params reject NaN/inf/out-of-range with 422 instead of
silently returning wrong (empty) results."""
import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password

_LOGS = ["sample_data/acceptance/full_detection.jsonl"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    app = create_app(log_paths=_LOGS)
    app.state.auth.users.create_user("viewer1", hash_password("password1234"), "viewer")
    c = TestClient(app, raise_server_exceptions=False)
    c.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"})
    return c


@pytest.mark.parametrize("bad", ["nan", "inf", "-inf", "1.5", "-0.1"])
def test_detections_rejects_bad_min_proximity(client, bad):
    r = client.get("/api/detections", params={"min_proximity": bad})
    assert r.status_code == 422, f"{bad!r} -> {r.status_code}: {r.text}"


def test_detections_accepts_valid_min_proximity(client):
    r = client.get("/api/detections", params={"min_proximity": 0.3})
    assert r.status_code == 200


@pytest.mark.parametrize("path", ["/api/host_risk", "/api/attack_paths"])
def test_other_routes_reject_nan(client, path):
    r = client.get(path, params={"min_proximity": "nan"})
    assert r.status_code == 422, f"{path} -> {r.status_code}"
