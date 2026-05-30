from augur.connectors.base import Source, Sink, SinkBase
from augur.engine.scoring import Detection


def _det(sid="SCEN-X", prox=1.0):
    return Detection(scenario_id=sid, name="n", severity="HIGH", proximity=prox,
                     matched_steps=[{"step_id": 1}], missing_steps=[], affected_hosts=["H"],
                     affected_zones=["Z"], hunting_queries=[])


def test_sinkbase_emit_all_loops_emit():
    seen = []
    class Rec(SinkBase):
        def emit(self, d): seen.append(d.scenario_id)
    Rec().emit_all([_det("A"), _det("B")])
    assert seen == ["A", "B"]


def test_sinkbase_is_context_manager():
    closed = []
    class Rec(SinkBase):
        def emit(self, d): pass
        def close(self): closed.append(True)
    with Rec() as r:
        assert r is not None
    assert closed == [True]


def test_protocols_are_runtime_checkable():
    class S:
        def read(self): return []
    class K(SinkBase):
        def emit(self, d): pass
    assert isinstance(S(), Source)
    assert isinstance(K(), Sink)


import io, json, pytest
from augur.connectors.sources import JsonlSource, DirectorySource, StdinSource
from augur.ingest.jsonl import IngestError


def test_jsonl_source_reads_same_as_read_jsonl(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text('{"event_id":1,"host":"A"}\n{"event_id":7,"host":"B"}\n')
    assert [e["host"] for e in JsonlSource(str(p)).read()] == ["A", "B"]


def test_jsonl_source_propagates_ingest_error(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text("NOTJSON\n")
    with pytest.raises(IngestError):
        list(JsonlSource(str(p)).read())


def test_directory_source_concatenates_sorted(tmp_path):
    (tmp_path / "b.jsonl").write_text('{"event_id":1,"host":"B"}\n')
    (tmp_path / "a.jsonl").write_text('{"event_id":1,"host":"A"}\n')
    assert [e["host"] for e in DirectorySource(str(tmp_path)).read()] == ["A", "B"]


def test_stdin_source_parses_lines(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO('{"event_id":1,"host":"A"}\n\n{"event_id":7,"host":"B"}\n'))
    assert [e["host"] for e in StdinSource().read()] == ["A", "B"]


import json as _json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import contextmanager
from augur.connectors.sinks import StdoutSink, JsonlFileSink, WebhookSink, SlackSink


@contextmanager
def _capture_server():
    """In-process HTTP server on 127.0.0.1:0 that records POST bodies. Loopback only."""
    received = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            received.append(_json.loads(self.rfile.read(n)))
            self.send_response(200); self.end_headers()
        def log_message(self, *a): pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", received
    finally:
        srv.shutdown()


def test_stdout_sink_prints_scenario(capsys):
    StdoutSink().emit(_det("SCEN-Z", 0.6))
    assert "SCEN-Z" in capsys.readouterr().out


def test_jsonl_file_sink_roundtrips_without_private_fields(tmp_path):
    out = tmp_path / "out" / "d.jsonl"
    with JsonlFileSink(str(out)) as s:
        s.emit_all([_det("A"), _det("B")])
    lines = out.read_text().strip().splitlines()
    rows = [_json.loads(l) for l in lines]
    assert [r["scenario_id"] for r in rows] == ["A", "B"]
    assert all(not k.startswith("_") for r in rows for k in r)


def test_webhook_sink_posts_detection_json():
    with _capture_server() as (url, received):
        WebhookSink(url).emit(_det("SCEN-W"))
    assert received and received[0]["scenario_id"] == "SCEN-W"


def test_slack_sink_posts_text_payload():
    with _capture_server() as (url, received):
        SlackSink(url).emit(_det("SCEN-S"))
    assert received and "text" in received[0] and "SCEN-S" in received[0]["text"]


from augur.connectors import get_source, get_sink, run_hunt, SOURCES, SINKS


def test_registry_resolves_and_unknown_raises(tmp_path):
    p = tmp_path / "a.jsonl"; p.write_text('{"event_id":1,"host":"A"}\n')
    assert hasattr(get_source("jsonl", path=str(p)), "read")
    assert hasattr(get_sink("stdout"), "emit")
    with pytest.raises(KeyError):
        get_source("nope")


def test_run_hunt_delivers_true_positive_to_recording_sink():
    class Rec(SinkBase):
        def __init__(self): self.got = []
        def emit(self, d): self.got.append(d)
    rec = Rec()
    dets = run_hunt(JsonlSource("sample_data/acceptance/full_detection.jsonl"), [rec], min_proximity=0.3)
    ids = {d.scenario_id for d in rec.got}
    assert "SCEN-WIN-001" in ids
    assert {d.scenario_id for d in dets} == ids
    assert next(d for d in rec.got if d.scenario_id == "SCEN-WIN-001").proximity == 1.0


def test_validate_sink_url_blocks_metadata_and_loopback():
    from augur.connectors.sinks import validate_sink_url
    # Cloud metadata + loopback + non-http schemes are rejected (SSRF defense).
    for bad in ("http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:8000/admin",
                "http://localhost/x",
                "https://[::1]/x",
                "file:///etc/passwd",
                "ftp://example.com/x",
                "gopher://x",
                "http://[::ffff:127.0.0.1]/x"):  # IPv4-mapped loopback must not slip through
        with pytest.raises(ValueError):
            validate_sink_url(bad)


def test_validate_sink_url_allows_public_and_private_onprem():
    from augur.connectors.sinks import validate_sink_url
    # Public + on-prem RFC1918 (real Jira/Slack live here) are allowed.
    for good in ("https://hooks.slack.com/services/x",
                 "https://jira.corp.example.com/rest/api/2/issue",
                 "http://10.1.2.3/webhook",
                 "http://192.168.1.50:8443/in"):
        validate_sink_url(good)  # no raise


def test_webhook_sink_raises_sink_delivery_error_on_network_failure():
    from augur.connectors.sinks import SinkDeliveryError
    # Port 1 on loopback is allowed for this test via the explicit allow, but to
    # avoid the SSRF guard we point at a private host:port that refuses fast.
    sink = WebhookSink("http://10.255.255.1:9/none", timeout=0.25)
    with pytest.raises(SinkDeliveryError):
        sink.emit(_det("SCEN-X"))


def test_run_hunt_isolates_failing_sink():
    class Boom(SinkBase):
        def emit(self, d): raise RuntimeError("down")
    class Rec(SinkBase):
        def __init__(self): self.got = []
        def emit(self, d): self.got.append(d)
    rec = Rec()
    dets = run_hunt(JsonlSource("sample_data/acceptance/full_detection.jsonl"), [Boom(), rec], min_proximity=0.3)
    assert rec.got                      # second sink still received despite first failing
    assert dets                          # no exception propagated


# ---------------------------------------------------------------------------
# New connectors: JiraSink, CortexXsoarSink, HttpSource
# ---------------------------------------------------------------------------

from augur.connectors.sinks import CortexXsoarSink, JiraSink
from augur.connectors.sources import HttpSource


def _det_critical(sid="SCEN-CRIT"):
    return Detection(scenario_id=sid, name="Critical Attack", severity="CRITICAL", proximity=1.0,
                     matched_steps=[{"step_id": 1}], missing_steps=[{"step_id": 2}],
                     affected_hosts=["host1", "host2"], affected_zones=["Z1"],
                     hunting_queries=[])


@contextmanager
def _jsonl_get_server(body: str):
    """In-process HTTP server on 127.0.0.1:0 that serves body on GET. Loopback only."""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            encoded = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        def log_message(self, *a): pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()


def test_jira_sink_posts_summary_with_scenario_id():
    with _capture_server() as (url, received):
        JiraSink(url).emit(_det("SCEN-JIRA"))
    assert received
    summary = received[0]["fields"]["summary"]
    assert "SCEN-JIRA" in summary


def test_jira_sink_payload_shape():
    with _capture_server() as (url, received):
        JiraSink(url).emit(_det("SCEN-J2"))
    fields = received[0]["fields"]
    assert "description" in fields
    assert "labels" in fields
    assert "augur" in fields["labels"]
    assert "high" in fields["labels"]   # severity.lower()


def test_cortex_xsoar_sink_critical_severity():
    with _capture_server() as (url, received):
        CortexXsoarSink(url).emit(_det_critical("SCEN-XSOAR"))
    assert received
    payload = received[0]
    assert payload["severity"] == 4   # CRITICAL → 4
    labels = payload["labels"]
    assert any(lbl["type"] == "scenario_id" and lbl["value"] == "SCEN-XSOAR" for lbl in labels)


def test_cortex_xsoar_sink_incident_shape():
    with _capture_server() as (url, received):
        CortexXsoarSink(url).emit(_det("SCEN-XS2"))
    payload = received[0]
    assert "SCEN-XS2" in payload["name"]
    assert payload["type"] == "Augur Detection"
    assert "rawJSON" in payload


def test_cortex_xsoar_sink_severity_mapping():
    sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for sev, expected in sev_map.items():
        d = Detection(scenario_id="S", name="n", severity=sev, proximity=1.0,
                      matched_steps=[], missing_steps=[], affected_hosts=[], affected_zones=[],
                      hunting_queries=[])
        with _capture_server() as (url, received):
            CortexXsoarSink(url).emit(d)
        assert received[0]["severity"] == expected, f"Expected {expected} for {sev}"


def test_http_source_reads_jsonl():
    body = '{"host":"A"}\n{"host":"B"}\n'
    with _jsonl_get_server(body) as url:
        result = HttpSource(url).read()
    assert [r["host"] for r in result] == ["A", "B"]


def test_http_source_accepts_json_array():
    body = '[{"host":"X"},{"host":"Y"}]'
    with _jsonl_get_server(body) as url:
        result = HttpSource(url).read()
    assert [r["host"] for r in result] == ["X", "Y"]


def test_http_source_skips_blank_lines():
    body = '{"host":"C"}\n\n{"host":"D"}\n\n'
    with _jsonl_get_server(body) as url:
        result = HttpSource(url).read()
    assert len(result) == 2


def test_registry_includes_new_connectors(tmp_path):
    assert "http" in SOURCES
    assert "jira" in SINKS
    assert "xsoar" in SINKS
