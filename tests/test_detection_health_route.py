"""TDD: GET /api/detection_health route (viewer, deterministic, JSON not index.html)."""
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


def test_rbac_enforced(client):
    assert client.get("/api/detection_health").status_code in (401, 403)


def test_viewer_200_shape(client):
    _login(client)
    r = client.get("/api/detection_health")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"summary", "scenarios"}
    s = body["summary"]
    assert set(s) == {"scenarios_total", "by_state", "corpus_span", "sweep_buckets", "honesty_note"}
    assert set(s["by_state"]) == {"FIRING", "PARTIAL", "SILENT", "NEVER"}
    assert sum(s["by_state"].values()) == s["scenarios_total"]
    assert "corpus" in s["honesty_note"].lower()
    assert isinstance(body["scenarios"], list) and body["scenarios"]
    for row in body["scenarios"]:
        assert set(row) == {"scenario_id", "name", "severity", "os_family", "tactics",
                            "state", "max_proximity", "fire_count", "last_fired",
                            "affected_host_count"}


def test_returns_json_not_index_html(client):
    """Guards Invariant: the route registers BEFORE the SPA catch-all."""
    _login(client)
    r = client.get("/api/detection_health")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")


def test_deterministic(client):
    _login(client)
    a = client.get("/api/detection_health").json()
    b = client.get("/api/detection_health").json()
    assert a == b

# Heavy full-corpus engine sweeps — skipped on per-push CI (-m 'not slow'); run weekly.
pytestmark = pytest.mark.slow
