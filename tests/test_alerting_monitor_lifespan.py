from fastapi.testclient import TestClient
from augur.api.app import create_app


def test_app_starts_with_monitor_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "app.db"))
    monkeypatch.delenv("AUGUR_MONITOR_ENABLED", raising=False)
    app = create_app(log_paths=["sample_data/acceptance/full_detection.jsonl"])
    with TestClient(app) as c:                       # runs lifespan startup+shutdown
        assert c.get("/api/health").json() == {"status": "ok", "real_data": False}
    # no monitor task was created
    assert getattr(app.state, "monitor_task", None) is None


def test_app_starts_monitor_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "app2.db"))
    monkeypatch.setenv("AUGUR_MONITOR_ENABLED", "1")
    monkeypatch.setenv("AUGUR_MONITOR_INTERVAL", "999")   # long; we only check it started
    app = create_app(log_paths=["sample_data/acceptance/full_detection.jsonl"])
    with TestClient(app) as c:
        assert c.get("/api/health").status_code == 200
        assert app.state.monitor_task is not None     # task created under lifespan
    # after the context exits, the task is stopped/cancelled
    assert app.state.monitor_task is None or app.state.monitor_task.done()
