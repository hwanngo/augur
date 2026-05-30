import json

import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password


@pytest.fixture
def client():
    app = create_app(log_paths=["sample_data/acceptance/demo_multi_os.jsonl"])
    app.state.auth.users.create_user("analyst1", hash_password("password1234"), "analyst")
    app.state.auth.users.create_user("viewer1", hash_password("password1234"), "viewer")
    return TestClient(app)


def _auth(c, u):
    csrf = c.post("/api/auth/login",
                  data={"username": u, "password": "password1234"}).json()["csrf_token"]
    return {"X-CSRF-Token": csrf}


# --- Phase B: GET /api/playbook ------------------------------------------------

def test_get_playbook_viewer_ok(client):
    _auth(client, "viewer1")
    r = client.get("/api/playbook", params={"scenario_id": "SCEN-WIN-001"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scenario_id"] == "SCEN-WIN-001"
    assert set(body) == {"scenario_id", "derived_from", "label", "sections"}
    assert set(body["sections"]) == {"contain", "eradicate", "recover", "validate"}


def test_get_playbook_unknown_scenario_404(client):
    _auth(client, "viewer1")
    r = client.get("/api/playbook", params={"scenario_id": "SCEN-NOPE-999"})
    assert r.status_code == 404, r.text


def test_get_playbook_requires_auth(client):
    r = client.get("/api/playbook", params={"scenario_id": "SCEN-WIN-001"})
    assert r.status_code == 401, r.text


# --- Phase C: POST /api/dispatch ----------------------------------------------

def test_post_dispatch_preview_returns_stored_dict(client):
    h = _auth(client, "analyst1")
    dets = client.get("/api/detections", params={"min_proximity": 0.0}).json()
    stored = next(d for d in dets if d["scenario_id"] == "SCEN-WIN-001")
    r = client.post("/api/dispatch", json={"scenario_id": "SCEN-WIN-001"}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {"ok": True, "sink": "preview", "payload": stored}  # [AUDIT #1] byte-identical


def test_post_dispatch_unknown_scenario_404(client):
    h = _auth(client, "analyst1")
    r = client.post("/api/dispatch", json={"scenario_id": "SCEN-NOPE-999"}, headers=h)
    assert r.status_code == 404, r.text


def test_post_dispatch_viewer_forbidden(client):
    h = _auth(client, "viewer1")
    r = client.post("/api/dispatch", json={"scenario_id": "SCEN-WIN-001"}, headers=h)
    assert r.status_code == 403, r.text


def test_post_dispatch_no_csrf_forbidden(client):
    client.post("/api/auth/login", data={"username": "analyst1", "password": "password1234"})
    r = client.post("/api/dispatch", json={"scenario_id": "SCEN-WIN-001"})
    assert r.status_code == 403, r.text


def test_post_dispatch_extra_field_422(client):
    h = _auth(client, "analyst1")
    r = client.post("/api/dispatch",
                    json={"scenario_id": "SCEN-WIN-001", "bogus": 1}, headers=h)
    assert r.status_code == 422, r.text


def test_post_dispatch_jsonl_writes_and_closes(client, tmp_path, monkeypatch):
    import augur.api.app as appmod
    out = tmp_path / "dispatch.jsonl"
    monkeypatch.setattr(appmod, "_dispatch_jsonl_path", lambda: str(out))
    h = _auth(client, "analyst1")
    r = client.post("/api/dispatch",
                    json={"scenario_id": "SCEN-WIN-001", "sink": "jsonl"}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True and r.json()["sink"] == "jsonl"
    lines = out.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["scenario_id"] == "SCEN-WIN-001"
    # fh closed: file complete + flushed (trailing newline written by the sink)
    assert out.read_text().endswith("\n")


def test_post_dispatch_stdout_ok(client, capsys):
    h = _auth(client, "analyst1")
    r = client.post("/api/dispatch",
                    json={"scenario_id": "SCEN-WIN-001", "sink": "stdout"}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["sink"] == "stdout" and r.json()["ok"] is True
    out = capsys.readouterr().out
    assert "SCEN-WIN-001" in out                        # [AUDIT #2] StdoutSink printed the line


def test_post_dispatch_unknown_sink_422(client):
    h = _auth(client, "analyst1")
    r = client.post("/api/dispatch",
                    json={"scenario_id": "SCEN-WIN-001", "sink": "bogus"}, headers=h)
    assert r.status_code == 422, r.text


def test_post_dispatch_real_unconfigured_sink_422(client):
    # "slack" is a real network sink; with no AlertConfigStore entry it must 422 (never run)
    h = _auth(client, "analyst1")
    r = client.post("/api/dispatch",
                    json={"scenario_id": "SCEN-WIN-001", "sink": "slack"}, headers=h)
    assert r.status_code == 422, r.text
