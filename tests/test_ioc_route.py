"""TDD: POST /api/ioc_match route (viewer, CSRF, deterministic)."""
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
    return c.post("/api/ioc_match", json=body)


def test_ioc_viewer_200_shape(client):
    _login(client)
    r = _post(client, {"iocs": [{"type": "process_name", "value": "powershell.exe"}]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"summary", "iocs", "hosts"}
    assert "RFC 5737" in body["summary"]["honesty_note"]
    assert body["iocs"][0]["type"] == "process_name"


def test_ioc_hash_domain_ip_cidr_ipv6_accepted_unknown_rejected_422(client):
    _login(client)
    # hash + domain + ip + cidr + ipv6 are accepted (matchable) types — a clean miss returns 200, not 422.
    for good, val in (("hash", "a" * 64), ("domain", "x.example.com"), ("ip", "203.0.113.99"),
                      ("cidr", "203.0.113.0/24"), ("ipv6", "2001:db8::1")):
        r = _post(client, {"iocs": [{"type": good, "value": val}]})
        assert r.status_code == 200, r.text
        assert r.json()["iocs"][0]["type"] == good
    # truly-unknown types stay hard-rejected; a malformed CIDR is an honest 422 too.
    assert _post(client, {"iocs": [{"type": "weird", "value": "x"}]}).status_code == 422
    assert _post(client, {"iocs": [{"type": "cidr", "value": "203.0.113.0/99"}]}).status_code == 422


def test_ioc_empty_422(client):
    _login(client)
    assert _post(client, {"iocs": []}).status_code == 422


def test_ioc_extra_field_422(client):
    _login(client)
    assert _post(client, {"iocs": [{"type": "command", "value": "x"}], "junk": 1}).status_code == 422


def test_ioc_csrf_required(client):
    c = client
    c.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"})
    assert c.post("/api/ioc_match", json={"iocs": [{"type": "command", "value": "x"}]}).status_code == 403


def test_ioc_rbac_enforced(client):
    assert client.post("/api/ioc_match", json={"iocs": [{"type": "command", "value": "x"}]}).status_code in (401, 403)


def test_ioc_deterministic(client):
    _login(client)
    b = {"iocs": [{"type": "command", "value": "powershell"}]}
    assert _post(client, b).json() == _post(client, b).json()
