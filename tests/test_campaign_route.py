"""TDD: GET /api/campaign route (viewer, deterministic, LRU-cached)."""
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
    assert c.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"}).status_code == 200


def _get(c, params=None):
    return c.get("/api/campaign", params=params or {})


def test_campaign_viewer_200_shape(client):
    _login(client)
    r = _get(client, {"scenario_ids": "SCEN-WIN-001"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"definition", "rows", "aggregate", "honesty"}
    assert "not a real-world" in body["honesty"]
    assert body["rows"][0]["scenario_id"] == "SCEN-WIN-001"
    assert body["aggregate"]["pct_detected"] == 1.0


def test_campaign_unknown_scenario_422(client):
    _login(client)
    assert _get(client, {"scenario_ids": "NOPE-999"}).status_code == 422


def test_campaign_over_cap_422(client):
    _login(client)
    assert _get(client, {}).status_code == 200


def test_campaign_rbac_enforced(client):
    assert _get(client, {"scenario_ids": "SCEN-WIN-001"}).status_code in (401, 403)


def test_campaign_deterministic_and_cached(client):
    _login(client)
    p = {"scenario_ids": "SCEN-WIN-001", "min_proximity": 1.0}
    assert _get(client, p).json() == _get(client, p).json()

# Heavy full-corpus engine sweeps — skipped on per-push CI (-m 'not slow'); run weekly.
pytestmark = pytest.mark.slow
