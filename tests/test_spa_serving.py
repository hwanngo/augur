"""
Tests that FastAPI serves the React SPA from frontend/dist when it exists,
serves /api/health regardless, and handles deep-link paths like /users.
"""
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from augur.api.app import create_app, _FRONTEND_DIST


@pytest.fixture()
def spa_dist(tmp_path, monkeypatch):
    """Stub out frontend/dist with a minimal index.html so tests don't need a real build."""
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text(
        "<!doctype html><html><body><div id='root'></div>"
        "<title>Augur React SPA</title></body></html>"
    )
    assets = dist / "assets"
    assets.mkdir()
    (assets / "main.js").write_text("// stub js")

    # Patch the module-level constant so create_app picks up our stub dist
    import augur.api.app as app_module
    monkeypatch.setattr(app_module, "_FRONTEND_DIST", dist)
    # Also clear the legacy web dir so it doesn't interfere
    monkeypatch.setattr(app_module, "_WEB_LEGACY", tmp_path / "nonexistent_web")

    return dist


def _client(spa_dist):  # noqa: ARG001 – fixture consumed for side-effects
    return TestClient(
        create_app(log_paths=["sample_data/acceptance/demo_multi_os.jsonl"]),
        raise_server_exceptions=False,
    )


def test_get_root_returns_spa_index(spa_dist):
    """GET / should return the React SPA index.html."""
    client = _client(spa_dist)
    r = client.get("/")
    assert r.status_code == 200
    assert "Augur React SPA" in r.text


def test_get_deep_link_returns_spa_index(spa_dist):
    """GET /users (React route) should return the SPA shell for client-side routing."""
    client = _client(spa_dist)
    r = client.get("/users")
    assert r.status_code == 200
    assert "Augur React SPA" in r.text


def test_get_dashboard_deep_link_returns_spa(spa_dist):
    """GET /dashboard deep-link survives a hard refresh."""
    client = _client(spa_dist)
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "Augur React SPA" in r.text


def test_api_health_still_200(spa_dist):
    """/api/health must remain 200 even when SPA fallback is active."""
    client = _client(spa_dist)
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "real_data": False}


def test_path_traversal_does_not_escape_dist(spa_dist, tmp_path):
    """A percent-encoded ../ path must NOT serve files outside frontend/dist.

    The dist dir is tmp_path/dist; we drop a secret next to it (tmp_path/secret.txt).
    Starlette URL-decodes %2e%2e into '..' in the path param, so an unguarded
    `web / full_path` would resolve to tmp_path/secret.txt. The fallback must
    instead refuse and return the SPA shell.
    """
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-DO-NOT-LEAK")
    client = _client(spa_dist)
    r = client.get("/%2e%2e/secret.txt")
    assert "TOP-SECRET-DO-NOT-LEAK" not in r.text
    # Should fall back to the SPA shell, not leak the file.
    assert "Augur React SPA" in r.text
