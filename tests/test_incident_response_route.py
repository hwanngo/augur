"""TDD: GET /api/incident_response route (viewer, deterministic, JSON not index.html)."""
import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password
from augur.response.playbook import build_playbook
from augur.pipeline import default_scenarios

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
    assert client.get("/api/incident_response").status_code in (401, 403)


def test_returns_json_not_index_html(client):
    """Guards Invariant: the route registers BEFORE the SPA catch-all."""
    _login(client)
    r = client.get("/api/incident_response")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/json")


def test_viewer_200_shape(client):
    _login(client)
    body = client.get("/api/incident_response").json()
    assert set(body) == {"responses", "honesty_note"}
    assert "STANDARD" in body["honesty_note"]
    assert isinstance(body["responses"], list)
    for r in body["responses"]:
        assert set(r) == {"incident_id", "top_severity", "member_count", "driving_tactics",
                          "hosts", "sections", "unresolved_scenarios", "note", "honesty_note"}
        assert r["incident_id"].startswith("INC-")
        assert set(r["sections"]) == {"contain", "eradicate", "recover", "validate"}
        for sec in ("contain", "eradicate", "recover"):
            for a in r["sections"][sec]:
                assert set(a) == {"action", "from_scenarios"}
        for v in r["sections"]["validate"]:
            assert set(v) == {"engine", "query", "query_path", "from_scenarios"}
        assert r["honesty_note"] == body["honesty_note"]


def test_deterministic(client):
    _login(client)
    a = client.get("/api/incident_response").json()
    b = client.get("/api/incident_response").json()
    assert a == b


def test_cross_check_one_incident_against_build_playbook(client):
    _login(client)
    incidents = client.get("/api/incidents").json()["incidents"]
    responses = {r["incident_id"]: r for r in
                 client.get("/api/incident_response").json()["responses"]}
    scenarios = default_scenarios()
    by_id = {s.scenario_id: s for s in scenarios}
    inc = incidents[0]
    resp = responses[inc["incident_id"]]
    # every contain action in the plan must be a contain line of SOME member's playbook
    member_contain = set()
    for m in inc["members"]:
        scen = by_id.get(m["scenario_id"])
        if scen is not None:
            member_contain.update(build_playbook(scen)["sections"]["contain"])
    for a in resp["sections"]["contain"]:
        assert a["action"] in member_contain
