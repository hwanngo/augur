"""TDD: POST /api/ioc_extract route (viewer, CSRF, 422s, deterministic shape)."""
import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password

_LOGS = ["sample_data/corpus/enterprise_day.jsonl"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    app = create_app(log_paths=_LOGS)
    app.state.auth.users.create_user("viewer1", hash_password("password1234"), "viewer")
    return TestClient(app)


def _login(c):
    r = c.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]


def _post(c, body):
    return c.post("/api/ioc_extract", json=body)


def test_extract_viewer_200_shape(client):
    _login(client)
    r = _post(client, {"text": "actor used T1059.001 and rundll32.exe; c2 192[.]0[.]2[.]9"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"summary", "matchable", "unmatchable"}
    assert body["summary"]["matchable_count"] >= 1
    assert any(i["type"] == "technique" for i in body["matchable"])
    assert any(i["type"] == "ip" and i["matchable"] is True for i in body["matchable"])
    assert "not AI" in body["summary"]["honesty_note"]


def test_extract_empty_text_422(client):
    _login(client)
    assert _post(client, {"text": "   "}).status_code == 422


def test_extract_extra_field_422(client):
    _login(client)
    assert _post(client, {"text": "x", "junk": 1}).status_code == 422


def test_extract_csrf_required(client):
    client.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"})
    assert client.post("/api/ioc_extract", json={"text": "T1059"}).status_code == 403


def test_extract_rbac_enforced(client):
    assert client.post("/api/ioc_extract", json={"text": "T1059"}).status_code in (401, 403)


def test_extract_deterministic(client):
    _login(client)
    b = {"text": "T1059.001 192.0.2.9 evil.example.com rundll32.exe"}
    assert _post(client, b).json() == _post(client, b).json()
