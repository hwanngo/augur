"""TDD: HTTP metrics registry + Prometheus rendering, JSON log formatter, and
the /metrics endpoint exposed by the app."""
import json
import logging

import pytest
from fastapi.testclient import TestClient

from augur.api.observability import MetricsRegistry, JsonLogFormatter
from augur.api.app import create_app
from augur.auth.hashing import hash_password

_LOGS = ["sample_data/acceptance/full_detection.jsonl"]


def test_registry_counts_and_renders_prometheus():
    reg = MetricsRegistry()
    reg.observe("GET", "/api/detections", 200, 0.01)
    reg.observe("GET", "/api/detections", 200, 0.03)
    reg.observe("GET", "/api/detections", 422, 0.001)
    text = reg.render()
    assert 'augur_http_requests_total{method="GET",route="/api/detections",status="200"} 2' in text
    assert 'augur_http_requests_total{method="GET",route="/api/detections",status="422"} 1' in text
    assert "augur_http_request_duration_seconds_count" in text
    # Prometheus format ends with a newline and carries HELP/TYPE lines.
    assert text.endswith("\n") and "# TYPE augur_http_requests_total counter" in text


def test_json_formatter_emits_structured_record():
    fmt = JsonLogFormatter()
    rec = logging.LogRecord("augur.test", logging.WARNING, __file__, 1, "hello %s", ("world",), None)
    rec.request_id = "abc"          # an extra
    obj = json.loads(fmt.format(rec))
    assert obj["level"] == "WARNING"
    assert obj["logger"] == "augur.test"
    assert obj["message"] == "hello world"
    assert obj["request_id"] == "abc"
    assert "ts" in obj


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    app = create_app(log_paths=_LOGS)
    return TestClient(app, raise_server_exceptions=False)


def test_metrics_endpoint_exposes_request_counts(client):
    client.get("/api/health")
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    body = r.text
    assert "augur_http_requests_total" in body
    # The /api/health hit must be counted under its route template.
    assert 'route="/api/health"' in body
