"""TDD: GET /api/coverage_gaps — viewer, closes over create_app scenarios + topology."""
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


def test_viewer_200_and_shape(client):
    _login(client)
    body = client.get("/api/coverage_gaps").json()
    assert set(body) == {"tactics", "os_families", "cells", "summary"}
    assert len(body["tactics"]) == 14
    assert body["os_families"] == ["windows", "linux", "macos"]  # standard topology
    assert set(body["cells"]) == {t["id"] for t in body["tactics"]}


def test_cell_payload_is_bounded(client):
    _login(client)
    cells = client.get("/api/coverage_gaps").json()["cells"]
    cell = cells["TA0001"]["windows"]
    assert set(cell) == {"covered", "count"}
    assert isinstance(cell["covered"], bool) and isinstance(cell["count"], int)


def test_summary_present(client):
    _login(client)
    s = client.get("/api/coverage_gaps").json()["summary"]
    assert set(s) == {"os_families", "total_cells", "covered_cells", "gap_cells", "coverage_pct"}
    assert s["total_cells"] == 42


def test_viewer_rbac_enforced(client):
    assert client.get("/api/coverage_gaps").status_code in (401, 403)


def test_stable_across_two_calls(client):
    _login(client)
    assert client.get("/api/coverage_gaps").json() == client.get("/api/coverage_gaps").json()
