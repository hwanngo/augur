"""TDD: GET /api/incidents route (viewer, deterministic, JSON not index.html)."""
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
    assert client.get("/api/incidents").status_code in (401, 403)


def test_viewer_200_shape(client):
    _login(client)
    r = client.get("/api/incidents")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"incidents", "rollup"}
    roll = body["rollup"]
    assert set(roll) == {"incidents", "clustered_detections", "singletons",
                         "largest_incident_size", "detections_total", "truncated", "honesty_note"}
    assert "CORRELATION" in roll["honesty_note"]
    assert isinstance(body["incidents"], list)
    for inc in body["incidents"]:
        assert set(inc) == {"incident_id", "size", "members", "members_truncated", "hosts",
                            "techniques", "first_ts", "last_ts", "top_severity", "max_proximity",
                            "score", "relations", "honesty_note"}
        assert inc["incident_id"].startswith("INC-")
        for m in inc["members"]:
            assert set(m) == {"scenario_id", "name", "severity", "proximity",
                              "affected_hosts", "latest_ts"}


def test_returns_json_not_index_html(client):
    """Guards Invariant: the route registers BEFORE the SPA catch-all."""
    _login(client)
    r = client.get("/api/incidents")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")


def test_deterministic(client):
    _login(client)
    a = client.get("/api/incidents").json()
    b = client.get("/api/incidents").json()
    assert a == b


def test_real_corpus_has_at_least_one_incident(client):
    _login(client)
    body = client.get("/api/incidents").json()
    # the enterprise-day corpus fires multiple scenarios -> at least one incident exists
    assert body["rollup"]["incidents"] >= 1
    assert body["rollup"]["detections_total"] >= 1
