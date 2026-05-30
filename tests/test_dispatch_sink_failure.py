"""TDD: POST /api/dispatch returns 502 (not an unhandled 500) when a configured
real sink fails to deliver to its remote endpoint."""
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
    app.state.auth.users.create_user("analyst1", hash_password("password1234"), "analyst")
    # Configure a webhook sink (private host so the SSRF guard allows it) that will
    # be exercised; we force a delivery failure via monkeypatch below.
    cfg = app.state.alerting.cfg.get()
    cfg["sinks"] = {"hook": {"type": "webhook", "url": "http://10.0.0.9/in"}}
    app.state.alerting.cfg.put(cfg)
    return TestClient(app, raise_server_exceptions=False)


def _auth(c):
    return {"X-CSRF-Token": c.post("/api/auth/login",
            data={"username": "analyst1", "password": "password1234"}).json()["csrf_token"]}


def test_dispatch_sink_delivery_failure_is_502(client, monkeypatch):
    from augur.connectors import sinks
    from augur.connectors.sinks import SinkDeliveryError

    def boom(*a, **k):
        raise SinkDeliveryError("simulated network failure")

    monkeypatch.setattr(sinks, "_post_json", boom)
    h = _auth(client)
    r = client.post("/api/dispatch", headers=h, json={"scenario_id": "SCEN-WIN-001", "sink": "hook"})
    assert r.status_code == 502, r.text
    assert "deliver" in r.json()["detail"].lower() or "sink" in r.json()["detail"].lower()
