import pytest
from fastapi.testclient import TestClient
from augur.api.app import create_app, _web_dir


@pytest.mark.skipif(
    _web_dir() is None,
    reason="frontend not built (no frontend/dist or legacy web/); the SPA build is exercised "
           "by the frontend CI job, not the Python test job",
)
def test_dashboard_index_served():
    """Root should serve the frontend (React SPA or legacy) with Augur branding."""
    client = TestClient(create_app(log_paths=["sample_data/acceptance/demo_multi_os.jsonl"]))
    r = client.get("/")
    assert r.status_code == 200
    assert "Augur" in r.text
