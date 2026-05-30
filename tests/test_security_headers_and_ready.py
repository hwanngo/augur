"""TDD: security-headers middleware on every response + a real /api/ready probe."""
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
    return TestClient(app, raise_server_exceptions=False)


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("referrer-policy")
    csp = r.headers.get("content-security-policy")
    assert csp and "frame-ancestors" in csp and "default-src" in csp


def test_no_hsts_outside_prod(client):
    r = client.get("/api/health")
    assert "strict-transport-security" not in {k.lower() for k in r.headers}


def test_hsts_in_prod(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "prod")
    monkeypatch.setenv("AUGUR_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "p.db"))
    app = create_app(log_paths=_LOGS)
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/api/health")
    assert "max-age" in r.headers.get("strict-transport-security", "")


def test_ready_endpoint_reports_checks(client):
    r = client.get("/api/ready")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ready"
    # Surfaces the dependency checks it actually performed.
    assert body["checks"]["database"] is True
    assert body["checks"]["graph_backend"] is True
