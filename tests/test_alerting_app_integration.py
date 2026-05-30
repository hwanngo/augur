from fastapi.testclient import TestClient
from augur.api.app import create_app


def test_app_mounts_alerts_endpoints(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "app.db"))
    app = create_app(log_paths=["sample_data/acceptance/full_detection.jsonl"])
    c = TestClient(app)
    # route exists + auth-gated (401, not 404)
    assert c.get("/api/alerts").status_code == 401
    assert c.get("/api/alerts/summary").status_code == 401
