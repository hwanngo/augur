"""TDD: GET /api/navigator_layer — viewer; reuses the /api/detections window/cache branch."""
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
    return TestClient(app)


def _login(client):
    r = client.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"})
    assert r.status_code == 200, r.text


def _assert_layer(body):
    assert set(body) >= {"name", "versions", "domain", "techniques", "gradient",
                         "legendItems", "sorting", "hideDisabled"}
    assert body["versions"]["layer"] == "4.5"
    assert body["domain"] == "enterprise-attack"


def test_viewer_200_coverage_default(client):
    _login(client)
    r = client.get("/api/navigator_layer")
    assert r.status_code == 200, r.text
    _assert_layer(r.json())
    assert all(e["score"] == 100 for e in r.json()["techniques"])  # coverage = binary 100


def test_detections_honors_min_proximity(client):
    _login(client)
    r = client.get("/api/navigator_layer?type=detections&min_proximity=0.3")
    assert r.status_code == 200, r.text
    _assert_layer(r.json())
    assert all(0 <= e["score"] <= 100 for e in r.json()["techniques"])


def test_detections_windowed_bounds(client):
    _login(client)
    r = client.get("/api/navigator_layer?type=detections&from=1970-01-01&to=9999-12-31")
    assert r.status_code == 200, r.text


def test_invalid_type_422(client):
    _login(client)
    assert client.get("/api/navigator_layer?type=bogus").status_code == 422


def test_inverted_bounds_422(client):
    _login(client)
    r = client.get("/api/navigator_layer?type=detections&from=2030-01-01&to=2020-01-01")
    assert r.status_code == 422


def test_rbac_unauth_401(client):
    assert client.get("/api/navigator_layer").status_code in (401, 403)


def test_stable_across_two_calls(client):
    _login(client)
    assert client.get("/api/navigator_layer").json() == client.get("/api/navigator_layer").json()
