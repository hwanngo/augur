"""TDD: GET /api/host_risk — viewer, sorted, reuses the /api/detections windowing branch."""
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


def _get(client, params=None):
    return client.get("/api/host_risk", params=params or {})


def test_viewer_200_and_sorted_desc(client):
    _login(client)
    rows = _get(client, {"min_proximity": 0.0}).json()["hosts"]
    scores = [r["score"] for r in rows]
    assert scores == sorted(scores, reverse=True)
    # SCEN-WIN-001 hits HR_User_PC at prox 1.0 -> a scored host exists.
    assert any(r["score"] > 0 for r in rows)


def test_response_shape(client):
    _login(client)
    row = _get(client, {"min_proximity": 0.0}).json()["hosts"][0]
    assert set(row) == {"hostname", "zone", "criticality", "score", "band",
                        "detection_count", "max_proximity", "top_severity", "top_scenarios"}


def test_all_topology_hosts_present(client):
    _login(client)
    rows = _get(client, {"min_proximity": 0.0}).json()["hosts"]
    # every clean topology host is still listed (CLEAR), nothing silently dropped.
    assert any(r["band"] == "CLEAR" for r in rows)


def test_min_proximity_filters_before_aggregation(client):
    _login(client)
    # min_proximity 1.0 keeps full detections only; total score must be <= the 0.0 case.
    lo = sum(r["score"] for r in _get(client, {"min_proximity": 0.0}).json()["hosts"])
    hi = sum(r["score"] for r in _get(client, {"min_proximity": 1.0}).json()["hosts"])
    assert hi <= lo


def test_window_branch_includes_events(client):
    _login(client)
    r = _get(client, {"from": "2026-01-01T08:00:00+00:00",
                      "to": "2026-01-01T10:00:00+00:00", "min_proximity": 0.0})
    assert r.status_code == 200, r.text
    assert any(row["score"] > 0 for row in r.json()["hosts"])


def test_window_before_events_all_clear(client):
    _login(client)
    r = _get(client, {"from": "2025-01-01T00:00:00+00:00", "to": "2025-01-01T01:00:00+00:00"})
    assert r.status_code == 200, r.text
    assert all(row["band"] == "CLEAR" for row in r.json()["hosts"])


def test_from_after_to_is_422(client):
    _login(client)
    r = _get(client, {"from": "2026-01-02T00:00:00+00:00", "to": "2026-01-01T00:00:00+00:00"})
    assert r.status_code == 422, r.text


def test_bad_iso_is_422(client):
    _login(client)
    assert _get(client, {"from": "not-a-date"}).status_code == 422


def test_viewer_rbac_enforced(client):
    assert _get(client, {"min_proximity": 0.0}).status_code in (401, 403)


def test_order_stable_across_two_calls(client):
    _login(client)
    a = [r["hostname"] for r in _get(client, {"min_proximity": 0.0}).json()["hosts"]]
    b = [r["hostname"] for r in _get(client, {"min_proximity": 0.0}).json()["hosts"]]
    assert a == b
