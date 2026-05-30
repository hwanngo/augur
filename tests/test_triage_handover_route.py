"""TDD: GET /api/triage_handover route (viewer, wall-clock, read-only)."""
import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password
from augur.alerting.store import Alert

_LOGS = ["sample_data/corpus/enterprise_day.jsonl"]


def _alert(**kw):
    base = dict(dedup_key="SCEN-1|h", scenario_id="SCEN-1", scenario_name="Cred Theft",
                severity="CRITICAL", affected_hosts=["h"], proximity=0.6, band="WATCH",
                created_at="2026-06-01T08:00:00+00:00", updated_at="2026-06-01T08:00:00+00:00")
    base.update(kw)
    return Alert(**base)


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    a = create_app(log_paths=_LOGS)
    a.state.auth.users.create_user("viewer1", hash_password("password1234"), "viewer")
    return a


@pytest.fixture
def client(app):
    return TestClient(app)


def _login(client):
    r = client.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"})
    assert r.status_code == 200, r.text


def _get(client, params=None):
    return client.get("/api/triage_handover", params=params or {})


def test_triage_handover_viewer_200_shape(client):
    _login(client)
    r = _get(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"window", "meta", "triage", "summary"}
    assert set(body["triage"]) == {"new_alerts", "assigned", "resolved", "reopened"}
    assert body["meta"]["basis"] == "alert-lifecycle-wallclock"


def test_triage_handover_empty_store_returns_empty(client):
    _login(client)
    body = _get(client).json()
    assert body["window"] == {"from": None, "to": None}
    assert body["summary"]["counts"] == {"new_alerts": 0, "assigned": 0, "resolved": 0, "reopened": 0}


def test_triage_handover_default_window_is_store_activity_span(app, client):
    app.state.alerting.alerts.create(_alert(dedup_key="d1", created_at="2026-06-01T08:00:00+00:00",
                                            assigned_at="2026-06-01T09:00:00+00:00", assignee="al"))
    _login(client)
    body = _get(client).json()
    assert body["window"]["from"] == "2026-06-01T08:00:00+00:00"
    assert [r["alert_id"] for r in body["triage"]["new_alerts"]]


def test_triage_handover_explicit_window_filters(app, client):
    app.state.alerting.alerts.create(_alert(dedup_key="d1", created_at="2026-06-01T07:00:00+00:00"))
    app.state.alerting.alerts.create(_alert(dedup_key="d2", scenario_id="SCEN-2",
                                            created_at="2026-06-01T10:00:00+00:00"))
    _login(client)
    body = _get(client, {"from": "2026-06-01T09:00:00+00:00", "to": "2026-06-01T18:00:00+00:00"}).json()
    ids = {r["scenario_id"] for r in body["triage"]["new_alerts"]}
    assert ids == {"SCEN-2"}


def test_triage_handover_inverted_bounds_is_422(client):
    _login(client)
    r = _get(client, {"from": "2026-06-02T00:00:00+00:00", "to": "2026-06-01T00:00:00+00:00"})
    assert r.status_code == 422, r.text


def test_triage_handover_rbac_enforced(client):
    assert _get(client).status_code in (401, 403)


def test_triage_handover_deterministic(app, client):
    app.state.alerting.alerts.create(_alert(dedup_key="d1", created_at="2026-06-01T10:00:00+00:00"))
    _login(client)
    p = {"from": "2026-06-01T00:00:00+00:00", "to": "2026-06-01T23:00:00+00:00"}
    assert _get(client, p).json() == _get(client, p).json()
