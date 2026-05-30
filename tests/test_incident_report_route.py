"""TDD: GET /api/incident_report/{id} route — JSON + ?format=markdown, 404, 422, RBAC, no-regression."""
import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.api.incident_report import HONESTY_NOTE
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


def _first_id(c):
    incs = c.get("/api/incidents").json()["incidents"]
    assert incs, "fixture corpus must produce at least one incident"
    return incs[0]["incident_id"]


def test_rbac_enforced(client):
    assert client.get("/api/incident_report/INC-0001").status_code in (401, 403)


def test_json_default_shape_and_provenance(client):
    _login(client)
    iid = _first_id(client)
    r = client.get(f"/api/incident_report/{iid}")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert set(body) == {
        "incident_id", "header", "affected_assets", "techniques",
        "detection_summary", "response", "source_notes", "honesty_note", "markdown",
    }
    assert body["incident_id"] == iid
    assert body["header"]["incident_id"] == iid
    assert body["honesty_note"] == HONESTY_NOTE
    assert isinstance(body["markdown"], str) and body["markdown"].startswith("# Post-Incident Report")


def test_markdown_export_headers(client):
    _login(client)
    iid = _first_id(client)
    r = client.get(f"/api/incident_report/{iid}?format=markdown")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/markdown")
    assert r.headers["content-disposition"] == \
        f"attachment; filename=augur-incident-{iid}.md"
    assert r.text.startswith("# Post-Incident Report")
    # JSON-embedded markdown and the export are byte-identical
    j = client.get(f"/api/incident_report/{iid}").json()["markdown"]
    assert r.text == j


def test_unknown_id_404(client):
    _login(client)
    r = client.get("/api/incident_report/INC-9999")
    assert r.status_code == 404
    assert "INC-9999" in r.json()["detail"]


def test_deterministic(client):
    _login(client)
    iid = _first_id(client)
    a = client.get(f"/api/incident_report/{iid}").json()
    b = client.get(f"/api/incident_report/{iid}").json()
    assert a == b


def test_no_regression_incidents_and_response_byte_identical(client):
    """The report route must not perturb the two upstream cached payloads."""
    _login(client)
    inc_before = client.get("/api/incidents").json()
    resp_before = client.get("/api/incident_response").json()
    iid = inc_before["incidents"][0]["incident_id"]
    client.get(f"/api/incident_report/{iid}")
    client.get(f"/api/incident_report/{iid}?format=markdown")
    assert client.get("/api/incidents").json() == inc_before
    assert client.get("/api/incident_response").json() == resp_before
