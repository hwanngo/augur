"""TDD: GET /api/rarity route (viewer, deterministic, clamped, bad dimension -> 422)."""
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


@pytest.mark.parametrize("dim", ["process", "parent_child", "host_binary"])
def test_viewer_200_shape(client, dim):
    _login(client)
    r = client.get(f"/api/rarity?dimension={dim}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dimension"] == dim
    assert set(body) == {"dimension", "params", "summary", "rows"}
    assert "LEAD" in body["summary"]["honesty_note"]
    for row in body["rows"]:
        assert set(row) >= {"value", "occurrences", "host_count", "single_host", "unique",
                            "first_seen", "last_seen", "hosts", "samples"}
        for h in row["hosts"]:
            assert set(h) == {"hostname", "zone", "criticality", "count"}


def test_default_dimension_is_process(client):
    _login(client)
    assert client.get("/api/rarity").json()["dimension"] == "process"


def test_bad_dimension_422(client):
    _login(client)
    r = client.get("/api/rarity?dimension=banana")
    assert r.status_code == 422
    assert "banana" in r.text


def test_clamps_do_not_422(client):
    _login(client)
    assert client.get("/api/rarity?dimension=process&max_count=9999&limit=0").status_code == 200
    assert client.get("/api/rarity?dimension=process&max_count=-3&limit=99999").status_code == 200


def test_rbac_enforced(client):
    assert client.get("/api/rarity?dimension=process").status_code in (401, 403)


def test_deterministic(client):
    _login(client)
    a = client.get("/api/rarity?dimension=parent_child").json()
    b = client.get("/api/rarity?dimension=parent_child").json()
    assert a == b
