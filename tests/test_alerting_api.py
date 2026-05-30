import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from augur.auth.router import attach_auth
from augur.auth.hashing import hash_password
from augur.alerting.router import attach_alerting


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "g.db"))
    app = FastAPI()
    state = attach_auth(app)
    state.users.create_user("admin1", hash_password("password1234"), "admin")
    state.users.create_user("analyst1", hash_password("password1234"), "analyst")
    state.users.create_user("viewer1", hash_password("password1234"), "viewer")
    # scan source = the true-positive fixture (fires SCEN-WIN-001 at 1.0)
    attach_alerting(app, state, scan_source_path="sample_data/acceptance/full_detection.jsonl")
    return TestClient(app)


def _auth(c, u):
    csrf = c.post("/api/auth/login", data={"username": u, "password": "password1234"}).json()["csrf_token"]
    return {"X-CSRF-Token": csrf}


def test_scan_creates_alert_then_list_and_summary(client):
    h = _auth(client, "admin1")
    r = client.post("/api/alerts/scan", headers=h)
    assert r.status_code == 200 and r.json()["created"] >= 1
    alerts = client.get("/api/alerts").json()
    assert len(alerts) >= 1 and any(a["scenario_id"] == "SCEN-WIN-001" for a in alerts)
    summ = client.get("/api/alerts/summary").json()
    assert summ["open_count"] >= 1 and summ["max_alert_id"] >= 1


def test_ack_transitions_state(client):
    h = _auth(client, "admin1")
    client.post("/api/alerts/scan", headers=h)
    # find SCEN-WIN-001 specifically
    alerts = client.get("/api/alerts").json()
    aid = next(a["id"] for a in alerts if a["scenario_id"] == "SCEN-WIN-001")
    ha = _auth(client, "analyst1")
    r = client.post(f"/api/alerts/{aid}/ack", headers=ha)
    assert r.status_code == 200
    assert any(a["id"] == aid for a in client.get("/api/alerts", params={"state": "acknowledged"}).json())
    detail = client.get(f"/api/alerts/{aid}").json()
    assert any(e["event"] == "ack" for e in detail["events"])


def test_config_rejects_ssrf_sink_url(client):
    """Admin cannot persist a sink pointing at cloud metadata / loopback (SSRF guard)."""
    h = _auth(client, "admin1")
    base = client.get("/api/alerts/config", headers=h).json()
    base["sinks"] = {"evil": {"type": "webhook", "url": "http://169.254.169.254/latest/meta-data/"}}
    r = client.put("/api/alerts/config", headers=h, json=base)
    assert r.status_code == 422, r.text
    # A legitimate https sink is still accepted.
    base["sinks"] = {"ok": {"type": "webhook", "url": "https://hooks.example.com/x"}}
    r2 = client.put("/api/alerts/config", headers=h, json=base)
    assert r2.status_code == 200, r2.text


def test_rbac_and_csrf(client):
    # viewer cannot list
    _auth(client, "viewer1")
    assert client.get("/api/alerts").status_code == 403
    # analyst cannot scan (admin only) or edit config
    ha = _auth(client, "analyst1")
    assert client.post("/api/alerts/scan", headers=ha).status_code == 403
    assert client.get("/api/alerts/config").status_code == 403
    # admin scan without CSRF -> 403
    client.post("/api/auth/login", data={"username": "admin1", "password": "password1234"})
    assert client.post("/api/alerts/scan").status_code == 403


def test_config_get_put_admin(client):
    h = _auth(client, "admin1")
    cfg = client.get("/api/alerts/config", headers=h).json()
    assert cfg["min_proximity"] == 0.6
    r = client.put("/api/alerts/config", json={**cfg, "min_proximity": 0.95}, headers=h)
    assert r.status_code == 200
    assert client.get("/api/alerts/config", headers=h).json()["min_proximity"] == 0.95


def test_ack_requires_csrf(client):
    h = _auth(client, "admin1")
    client.post("/api/alerts/scan", headers=h)
    alerts = client.get("/api/alerts").json()
    aid = alerts[0]["id"]
    client.post("/api/auth/login", data={"username": "analyst1", "password": "password1234"})
    assert client.post(f"/api/alerts/{aid}/ack").status_code == 403   # no CSRF header


# ── FIX 1: validate alert config at the API boundary ────────────────────────

def test_put_config_min_proximity_out_of_range_returns_422(client):
    """min_proximity=999 must be rejected with 422, not silently accepted."""
    h = _auth(client, "admin1")
    cfg = client.get("/api/alerts/config", headers=h).json()
    r = client.put("/api/alerts/config", json={**cfg, "min_proximity": 999}, headers=h)
    assert r.status_code == 422, f"expected 422 but got {r.status_code}: {r.text}"


def test_put_config_negative_min_proximity_returns_422(client):
    """min_proximity=-5 must be rejected with 422."""
    h = _auth(client, "admin1")
    cfg = client.get("/api/alerts/config", headers=h).json()
    r = client.put("/api/alerts/config", json={**cfg, "min_proximity": -5}, headers=h)
    assert r.status_code == 422, f"expected 422 but got {r.status_code}: {r.text}"


def test_put_config_negative_auto_resolve_cycles_returns_422(client):
    """auto_resolve_cycles=-1 must be rejected with 422."""
    h = _auth(client, "admin1")
    cfg = client.get("/api/alerts/config", headers=h).json()
    r = client.put("/api/alerts/config", json={**cfg, "auto_resolve_cycles": -1}, headers=h)
    assert r.status_code == 422, f"expected 422 but got {r.status_code}: {r.text}"


def test_put_config_invalid_rule_min_severity_returns_422(client):
    """A rule with min_severity='EXTREME' (not a valid Severity) must be rejected with 422."""
    h = _auth(client, "admin1")
    cfg = client.get("/api/alerts/config", headers=h).json()
    bad_rules = [{"min_severity": "EXTREME", "min_proximity": None, "sinks": ["x"]}]
    r = client.put("/api/alerts/config", json={**cfg, "rules": bad_rules}, headers=h)
    assert r.status_code == 422, f"expected 422 but got {r.status_code}: {r.text}"


def test_put_config_rule_sinks_not_list_returns_422(client):
    """A rule with sinks='not-a-list' must be rejected with 422."""
    h = _auth(client, "admin1")
    cfg = client.get("/api/alerts/config", headers=h).json()
    bad_rules = [{"min_severity": None, "min_proximity": None, "sinks": "not-a-list"}]
    r = client.put("/api/alerts/config", json={**cfg, "rules": bad_rules}, headers=h)
    assert r.status_code == 422, f"expected 422 but got {r.status_code}: {r.text}"


def test_put_config_rule_min_proximity_out_of_range_returns_422(client):
    """A rule with min_proximity=1.5 must be rejected with 422."""
    h = _auth(client, "admin1")
    cfg = client.get("/api/alerts/config", headers=h).json()
    bad_rules = [{"min_severity": None, "min_proximity": 1.5, "sinks": ["x"]}]
    r = client.put("/api/alerts/config", json={**cfg, "rules": bad_rules}, headers=h)
    assert r.status_code == 422, f"expected 422 but got {r.status_code}: {r.text}"


def test_put_config_valid_config_still_200(client):
    """A fully valid config must still be accepted (200)."""
    h = _auth(client, "admin1")
    cfg = client.get("/api/alerts/config", headers=h).json()
    valid = {**cfg, "min_proximity": 0.8, "auto_resolve_cycles": 2,
             "rules": [{"min_severity": "HIGH", "min_proximity": 0.7, "sinks": ["slack"]}]}
    r = client.put("/api/alerts/config", json=valid, headers=h)
    assert r.status_code == 200, f"expected 200 but got {r.status_code}: {r.text}"


# ── NIT: 404 for unknown alert id ────────────────────────────────────────────

def test_get_unknown_alert_id_returns_404(client):
    """GET /api/alerts/doesnotexist must return 404."""
    _auth(client, "analyst1")
    r = client.get("/api/alerts/doesnotexist")
    assert r.status_code == 404, f"expected 404 but got {r.status_code}"


def test_ack_unknown_alert_id_returns_404(client):
    """POST /api/alerts/doesnotexist/ack (analyst+CSRF) must return 404."""
    ha = _auth(client, "analyst1")
    r = client.post("/api/alerts/doesnotexist/ack", headers=ha)
    assert r.status_code == 404, f"expected 404 but got {r.status_code}"


# ── Phase B helpers ──────────────────────────────────────────────────────────

def _scan_and_get_aid(client):
    """Scan (admin) and return the SCEN-WIN-001 alert id."""
    h = _auth(client, "admin1")
    client.post("/api/alerts/scan", headers=h)
    alerts = client.get("/api/alerts").json()
    return next(a["id"] for a in alerts if a["scenario_id"] == "SCEN-WIN-001")


# ── Task 4: extended alert view + request models ─────────────────────────────

def test_alert_view_includes_triage_fields(client):
    """After a scan, list rows carry the five new triage keys with defaults."""
    h = _auth(client, "admin1")
    client.post("/api/alerts/scan", headers=h)
    alerts = client.get("/api/alerts").json()
    assert alerts, "expected at least one alert"
    a = alerts[0]
    for key in ("assignee", "status", "resolution_note", "assigned_at", "resolved_at"):
        assert key in a, f"missing key {key!r} in alert view"
    assert a["assignee"] == ""
    assert a["status"] == "open"
    assert a["resolution_note"] == ""


# ── Task 5: POST /assign ─────────────────────────────────────────────────────

def test_assign_analyst_with_csrf_200_and_event(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    r = client.post(f"/api/alerts/{aid}/assign", json={"assignee": "analyst1"}, headers=ha)
    assert r.status_code == 200, r.text
    assert r.json()["assignee"] == "analyst1"
    detail = client.get(f"/api/alerts/{aid}").json()
    assert any(e["event"] == "assigned" and e["detail"] == "analyst1" for e in detail["events"])


def test_assign_clears_when_empty(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    client.post(f"/api/alerts/{aid}/assign", json={"assignee": "analyst1"}, headers=ha)
    r = client.post(f"/api/alerts/{aid}/assign", json={"assignee": ""}, headers=ha)
    assert r.status_code == 200, r.text
    assert r.json()["assignee"] == ""


def test_assign_unknown_user_422(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    r = client.post(f"/api/alerts/{aid}/assign", json={"assignee": "ghost"}, headers=ha)
    assert r.status_code == 422, r.text


def test_assign_disabled_user_422(client):
    aid = _scan_and_get_aid(client)
    # disable viewer1 via admin user-admin endpoint
    h = _auth(client, "admin1")
    users = client.get("/api/users", headers=h).json()
    vid = next(u["id"] for u in users if u["username"] == "viewer1")
    client.patch(f"/api/users/{vid}", json={"disabled": True}, headers=h)
    ha = _auth(client, "analyst1")
    r = client.post(f"/api/alerts/{aid}/assign", json={"assignee": "viewer1"}, headers=ha)
    assert r.status_code == 422, r.text


def test_assign_unknown_alert_404(client):
    ha = _auth(client, "analyst1")
    r = client.post("/api/alerts/nope/assign", json={"assignee": "analyst1"}, headers=ha)
    assert r.status_code == 404, r.text


def test_assign_no_csrf_403(client):
    aid = _scan_and_get_aid(client)
    client.post("/api/auth/login", data={"username": "analyst1", "password": "password1234"})
    r = client.post(f"/api/alerts/{aid}/assign", json={"assignee": "analyst1"})
    assert r.status_code == 403, r.text


def test_assign_viewer_403(client):
    aid = _scan_and_get_aid(client)
    hv = _auth(client, "viewer1")
    r = client.post(f"/api/alerts/{aid}/assign", json={"assignee": "analyst1"}, headers=hv)
    assert r.status_code == 403, r.text


def test_assign_extra_field_422(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    r = client.post(f"/api/alerts/{aid}/assign",
                    json={"assignee": "analyst1", "bogus": 1}, headers=ha)
    assert r.status_code == 422, r.text


# ── Task 6: POST /status ─────────────────────────────────────────────────────

def test_status_valid_transition_200(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    r = client.post(f"/api/alerts/{aid}/status", json={"status": "in_progress"}, headers=ha)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "in_progress"
    detail = client.get(f"/api/alerts/{aid}").json()
    assert any(e["event"] == "status" for e in detail["events"])


def test_status_invalid_value_422(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    r = client.post(f"/api/alerts/{aid}/status", json={"status": "bogus"}, headers=ha)
    assert r.status_code == 422, r.text


def test_status_terminal_without_note_422(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    r = client.post(f"/api/alerts/{aid}/status", json={"status": "resolved"}, headers=ha)
    assert r.status_code == 422, r.text
    r2 = client.post(f"/api/alerts/{aid}/status",
                     json={"status": "closed", "note": "  "}, headers=ha)
    assert r2.status_code == 422, r2.text


def test_status_terminal_with_note_200_and_resolved_at(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    r = client.post(f"/api/alerts/{aid}/status",
                    json={"status": "resolved", "note": "benign, closed"}, headers=ha)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "resolved"
    assert body["resolution_note"] == "benign, closed"
    assert body["resolved_at"] != ""
    # mirrors legacy state -> resolved (visible in summary)
    summ = client.get("/api/alerts/summary").json()
    assert summ["resolved_count"] >= 1


def test_status_unknown_alert_404(client):
    ha = _auth(client, "analyst1")
    r = client.post("/api/alerts/nope/status", json={"status": "in_progress"}, headers=ha)
    assert r.status_code == 404, r.text


def test_status_no_csrf_403(client):
    aid = _scan_and_get_aid(client)
    client.post("/api/auth/login", data={"username": "analyst1", "password": "password1234"})
    r = client.post(f"/api/alerts/{aid}/status", json={"status": "in_progress"})
    assert r.status_code == 403, r.text


def test_status_viewer_403(client):
    aid = _scan_and_get_aid(client)
    hv = _auth(client, "viewer1")
    r = client.post(f"/api/alerts/{aid}/status", json={"status": "in_progress"}, headers=hv)
    assert r.status_code == 403, r.text


# ── Task 7: POST /comment ────────────────────────────────────────────────────

def test_comment_non_empty_201_in_detail(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    r = client.post(f"/api/alerts/{aid}/comment", json={"text": "looking into this"}, headers=ha)
    assert r.status_code == 201, r.text
    detail = client.get(f"/api/alerts/{aid}").json()
    assert any(e["event"] == "comment" and e["detail"] == "looking into this"
               for e in detail["events"])


def test_comment_empty_422(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    r = client.post(f"/api/alerts/{aid}/comment", json={"text": ""}, headers=ha)
    assert r.status_code == 422, r.text


def test_comment_unknown_alert_404(client):
    ha = _auth(client, "analyst1")
    r = client.post("/api/alerts/nope/comment", json={"text": "x"}, headers=ha)
    assert r.status_code == 404, r.text


def test_comment_no_csrf_403(client):
    aid = _scan_and_get_aid(client)
    client.post("/api/auth/login", data={"username": "analyst1", "password": "password1234"})
    r = client.post(f"/api/alerts/{aid}/comment", json={"text": "x"})
    assert r.status_code == 403, r.text


def test_comment_viewer_403(client):
    aid = _scan_and_get_aid(client)
    hv = _auth(client, "viewer1")
    r = client.post(f"/api/alerts/{aid}/comment", json={"text": "x"}, headers=hv)
    assert r.status_code == 403, r.text


# ── Task 8: list query params ────────────────────────────────────────────────

def test_list_filter_by_status(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    client.post(f"/api/alerts/{aid}/status", json={"status": "in_progress"}, headers=ha)
    rows = client.get("/api/alerts", params={"status": "in_progress"}).json()
    assert rows and all(a["status"] == "in_progress" for a in rows)
    assert any(a["id"] == aid for a in rows)
    none = client.get("/api/alerts", params={"status": "closed"}).json()
    assert all(a["id"] != aid for a in none)


def test_list_filter_assignee_me(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    client.post(f"/api/alerts/{aid}/assign", json={"assignee": "analyst1"}, headers=ha)
    rows = client.get("/api/alerts", params={"assignee": "me"}).json()
    assert rows and all(a["assignee"] == "analyst1" for a in rows)
    assert any(a["id"] == aid for a in rows)


def test_list_filter_assignee_verbatim(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    client.post(f"/api/alerts/{aid}/assign", json={"assignee": "analyst1"}, headers=ha)
    rows = client.get("/api/alerts", params={"assignee": "analyst1"}).json()
    assert any(a["id"] == aid for a in rows)


def test_list_filter_seen_window(client):
    _scan_and_get_aid(client)
    _auth(client, "analyst1")
    # a generous window includes everything
    wide = client.get("/api/alerts",
                      params={"seen_from": "1970-01-01T00:00:00+00:00",
                              "seen_to": "2999-01-01T00:00:00+00:00"}).json()
    assert len(wide) >= 1
    # a window entirely in the past excludes everything
    past = client.get("/api/alerts",
                      params={"seen_from": "1970-01-01T00:00:00+00:00",
                              "seen_to": "1971-01-01T00:00:00+00:00"}).json()
    assert past == []


def test_list_filter_by_dedup_key(client):
    aid = _scan_and_get_aid(client)
    ha = _auth(client, "analyst1")
    # discover the dedup_key for the SCEN-WIN-001 alert via the store-derived view
    alerts = client.get("/api/alerts").json()
    target = next(a for a in alerts if a["id"] == aid)
    key = f"{target['scenario_id']}|{','.join(sorted(target['affected_hosts']))}"
    rows = client.get("/api/alerts", params={"dedup_key": key}).json()
    assert len(rows) == 1 and rows[0]["id"] == aid
    # unknown key -> empty
    assert client.get("/api/alerts", params={"dedup_key": "SCEN-NONE|x"}).json() == []


def test_list_blank_dedup_key_ignored(client):
    _scan_and_get_aid(client)
    _auth(client, "analyst1")
    full = client.get("/api/alerts").json()
    blank = client.get("/api/alerts", params={"dedup_key": "   "}).json()
    assert len(blank) == len(full) and len(full) >= 1


def test_list_dedup_key_viewer_403(client):
    hv = _auth(client, "viewer1")
    r = client.get("/api/alerts", params={"dedup_key": "SCEN-1|x"}, headers=hv)
    assert r.status_code == 403, r.text


def test_list_unparseable_seen_bound_422(client):
    _auth(client, "analyst1")
    r = client.get("/api/alerts", params={"seen_from": "not-a-date"})
    assert r.status_code == 422, r.text
    r2 = client.get("/api/alerts", params={"seen_to": "garbage"})
    assert r2.status_code == 422, r2.text
