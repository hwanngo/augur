"""TDD: /api/hunts router — RBAC, CSRF, scope validation, live evidence (mirrors alerting tests)."""
import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password

_LOGS = ["sample_data/corpus/enterprise_day.jsonl"]


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    a = create_app(log_paths=_LOGS)
    a.state.auth.users.create_user("ana", hash_password("password1234"), "analyst")
    a.state.auth.users.create_user("vee", hash_password("password1234"), "viewer")
    return a


def _client(app, user="ana"):
    c = TestClient(app)
    r = c.post("/api/auth/login", data={"username": user, "password": "password1234"})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def _create(c, **kw):
    body = {"hypothesis": "cred theft in DMZ", "scope": {"zone": "DMZ"}}
    body.update(kw)
    return c.post("/api/hunts", json=body)


def test_analyst_create_then_get_with_live_evidence(app):
    c = _client(app)
    r = _create(c)
    assert r.status_code == 201, r.text
    hid = r.json()["id"]
    d = c.get(f"/api/hunts/{hid}").json()
    assert d["hypothesis"] == "cred theft in DMZ" and d["status"] == "open" and d["owner"] == "ana"
    assert "evidence" in d and "honesty_note" in d and "events" in d


def test_viewer_can_read_not_write(app):
    hid = _create(_client(app)).json()["id"]
    v = _client(app, user="vee")
    assert v.get("/api/hunts").status_code == 200
    assert v.get(f"/api/hunts/{hid}").status_code == 200
    assert v.post("/api/hunts", json={"hypothesis": "x", "scope": {}}).status_code == 403


def test_scope_validation_422(app):
    c = _client(app)
    assert _create(c, scope={"zone": "NotAZone"}).status_code == 422
    assert _create(c, scope={"host": "no-such-host"}).status_code == 422
    assert _create(c, scope={"from": "not-a-date"}).status_code == 422
    assert _create(c, scope={"scenario_ids": ["NOPE-999"]}).status_code == 422


def test_patch_status_terminal_requires_note(app):
    c = _client(app); hid = _create(c).json()["id"]
    assert c.patch(f"/api/hunts/{hid}", json={"status": "confirmed"}).status_code == 422
    r = c.patch(f"/api/hunts/{hid}", json={"status": "confirmed", "verdict_note": "found it"})
    assert r.status_code == 200, r.text
    d = c.get(f"/api/hunts/{hid}").json()
    assert d["status"] == "confirmed" and d["verdict_evidence_at"]


def test_reopen_after_verdict_keeps_labeled_snapshot(app):
    # confirm -> investigating: the as-of-verdict snapshot must SURVIVE the reopen and stay labeled
    # (honesty contract: a historical, timestamped snapshot, never shown as current).
    c = _client(app); hid = _create(c).json()["id"]
    c.patch(f"/api/hunts/{hid}", json={"status": "confirmed", "verdict_note": "found it"})
    c.patch(f"/api/hunts/{hid}", json={"status": "investigating"})
    d = c.get(f"/api/hunts/{hid}").json()
    assert d["status"] == "investigating"
    assert d["verdict_evidence"] is not None and d["verdict_evidence_at"]   # snapshot preserved + labeled


def test_inverted_scope_bounds_422(app):
    c = _client(app)
    assert _create(c, scope={"from": "2026-02-01T00:00:00+00:00",
                             "to": "2026-01-01T00:00:00+00:00"}).status_code == 422


def test_csrf_required_on_mutation(app):
    c = TestClient(app)
    c.post("/api/auth/login", data={"username": "ana", "password": "password1234"})
    assert c.post("/api/hunts", json={"hypothesis": "x", "scope": {}}).status_code == 403


def test_owner_only_delete(app):
    hid = _create(_client(app, "ana")).json()["id"]
    app.state.auth.users.create_user("bob", hash_password("password1234"), "analyst")
    bob = _client(app, "bob")
    assert bob.delete(f"/api/hunts/{hid}").status_code == 403
    assert _client(app, "ana").delete(f"/api/hunts/{hid}").status_code == 200


def test_report_md_and_json(app):
    c = _client(app); hid = _create(c).json()["id"]
    assert c.get(f"/api/hunts/{hid}/report").status_code == 200
    j = c.get(f"/api/hunts/{hid}/report", params={"format": "json"}).json()
    assert "hypothesis" in j and "evidence" in j


def test_detail_evidence_deterministic(app):
    c = _client(app); hid = _create(c, scope={}).json()["id"]
    a = c.get(f"/api/hunts/{hid}").json()["evidence"]
    b = c.get(f"/api/hunts/{hid}").json()["evidence"]
    assert a == b
