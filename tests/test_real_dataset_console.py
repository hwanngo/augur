"""Real-OTRF-dataset-in-the-console increment: tagging, byte-identical create_app defaults,
tagged-fixture fire smoke, and the IOC real_data honesty flag."""
import importlib
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# ── Task 1: --tag mode in the fetcher ───────────────────────────────────────
def _load_fetcher():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import fetch_real_datasets
    return importlib.reload(fetch_real_datasets)


def test_tag_jsonl_injects_source_type(tmp_path):
    fetcher = _load_fetcher()
    src = tmp_path / "input.jsonl"
    src.write_text(
        '{"EventID":10,"Hostname":"H1"}\n'
        '{"EventID":1,"Hostname":"H1","source_type":null}\n'
    )
    out = tmp_path / "tagged.jsonl"
    n = fetcher.tag_jsonl(src, out)
    assert n == 2
    rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert all(r["source_type"] == "windows_sysmon_real" for r in rows)
    # other fields preserved
    assert rows[0]["EventID"] == 10 and rows[0]["Hostname"] == "H1"


# ── Task 2: byte-identical create_app defaults ──────────────────────────────
_DEMO_LOGS = ["sample_data/acceptance/demo_multi_os.jsonl"]


def _login_client(app) -> TestClient:
    """Create a viewer and return an authenticated TestClient (mirrors tests/test_api.py:6-13).

    Uses users.create_user(name, hash_password(pw), role) + form-encoded login (data=), exactly like
    the existing fixture. Viewer role suffices for all GET routes this test reads."""
    from augur.auth.hashing import hash_password
    app.state.auth.users.create_user("t", hash_password("password1234"), "viewer")
    client = TestClient(app)
    r = client.post("/api/auth/login", data={"username": "t", "password": "password1234"})
    assert r.status_code == 200, r.text
    return client


def test_create_app_defaults_byte_identical():
    from augur.api.app import create_app
    app = create_app(log_paths=_DEMO_LOGS)
    client = _login_client(app)

    scen = client.get("/api/scenarios")
    assert scen.status_code == 200, scen.text
    ids = sorted(s["scenario_id"] for s in scen.json())
    # All synthetic, no SCEN-REAL-* leaks into the default path.
    assert all(not i.startswith("SCEN-REAL-") for i in ids)
    assert len(ids) == 40  # the 40 synthetic scenarios (CLAUDE.local.md)

    topo = client.get("/api/topology")
    assert topo.status_code == 200, topo.text
    payload = topo.json()
    # The default (standard) topology hosts — not the OTRF theshire hosts.
    hostnames = {a["hostname"] for a in payload["assets"]}
    assert not any(h.endswith(".theshire.local") for h in hostnames)


# ── Task 3: optional topology/scenarios params ──────────────────────────────
def test_create_app_accepts_explicit_topology_and_scenarios():
    from augur.api.app import create_app
    from augur.pipeline import default_topology, default_scenarios
    from augur.scenarios.loader import load_scenarios
    from augur.topology.network import load_topology

    topo = load_topology("datasets/real/topology_otrf_theshire.yaml")
    scens = default_scenarios() + load_scenarios("scenarios_real")
    app = create_app(log_paths=_DEMO_LOGS, topology=topo, scenarios=scens)
    client = _login_client(app)

    ids = {s["scenario_id"] for s in client.get("/api/scenarios").json()}
    assert "SCEN-REAL-WIN-T1003-001" in ids          # real scenario visible
    # 40 synthetic + every scenarios_real/ scenario explicitly passed (grows with each Wave)
    n_real = len({s.scenario_metadata.scenario_id for s in load_scenarios("scenarios_real")})
    assert len(ids) == 40 + n_real

    hostnames = {a["hostname"] for a in client.get("/api/topology").json()["assets"]}
    assert "WORKSTATION5.theshire.local" in hostnames  # OTRF topology in effect


def test_create_app_env_fallback_for_factory_mode(monkeypatch):
    # --reload's factory calls create_app() with NO args; env vars must reconstruct the wiring.
    from augur.api import app as app_mod
    monkeypatch.setenv("AUGUR_TOPOLOGY", "datasets/real/topology_otrf_theshire.yaml")
    monkeypatch.setenv("AUGUR_SCENARIOS_DIR", "scenarios")
    monkeypatch.setenv("AUGUR_SCENARIOS_EXTRA_DIR", "scenarios_real")
    monkeypatch.setenv("AUGUR_LOGS", _DEMO_LOGS[0])
    app = app_mod.create_app()
    client = _login_client(app)
    ids = {s["scenario_id"] for s in client.get("/api/scenarios").json()}
    assert "SCEN-REAL-WIN-T1003-001" in ids
    hostnames = {a["hostname"] for a in client.get("/api/topology").json()["assets"]}
    assert "WORKSTATION5.theshire.local" in hostnames


# ── Task 4: tagged-fixture fire smoke via the web read-path ─────────────────
from datetime import datetime, timezone

_EPOCH_MIN = datetime(1970, 1, 1, tzinfo=timezone.utc)
_FAR_FUTURE = datetime(9999, 12, 31, tzinfo=timezone.utc)


def test_tagged_fixture_fires_through_windowed_detections(tmp_path):
    """Tag the UNTAGGED real fixture, then run the SAME windowed_detections the API uses over the OTRF
    topology + scenarios_real. SCEN-REAL-WIN-T1003-001 must fire at proximity 1.0 CRITICAL."""
    fetcher = _load_fetcher()
    tagged = tmp_path / "tagged.jsonl"
    fetcher.tag_jsonl(Path("tests/fixtures/real/lsass_dump_min.jsonl"), tagged)

    from augur.api.detections import windowed_detections
    from augur.topology.network import load_topology
    from augur.scenarios.loader import load_scenarios
    from augur.pipeline import default_scenarios

    topo = load_topology("datasets/real/topology_otrf_theshire.yaml")
    scens = default_scenarios() + load_scenarios("scenarios_real")
    dets = list(windowed_detections([str(tagged)], topo, scens, frm=_EPOCH_MIN, to=_FAR_FUTURE))

    real = [d for d in dets if d["scenario_id"] == "SCEN-REAL-WIN-T1003-001"]
    assert len(real) == 1, f"expected the real LSASS detection, got {[d['scenario_id'] for d in dets]}"
    d = real[0]
    assert d["proximity"] == 1.0
    assert d["severity"] == "CRITICAL"
    assert any(h.lower() == "workstation5.theshire.local" for h in d["affected_hosts"])


# ── Task 6: IOC real_data honesty flag + served health flag ─────────────────
def test_match_iocs_default_is_byte_identical():
    """Default real_data=False keeps the synthetic RFC-5737 honesty note verbatim."""
    from augur.api.ioc import match_iocs, HONESTY_NOTE
    from augur.pipeline import default_scenarios, default_topology
    res = match_iocs([{"type": "process_name", "value": "lsass.exe"}],
                     _DEMO_LOGS, default_scenarios(), default_topology(), [])
    assert res["summary"]["honesty_note"] == HONESTY_NOTE
    assert "RFC 5737" in res["summary"]["honesty_note"]


def test_match_iocs_real_data_rewrites_ip_clause():
    """real_data=True replaces the synthetic-IP clause with the real-telemetry statement."""
    from augur.api.ioc import match_iocs
    from augur.pipeline import default_scenarios, default_topology
    res = match_iocs([{"type": "process_name", "value": "lsass.exe"}],
                     _DEMO_LOGS, default_scenarios(), default_topology(), [],
                     real_data=True)
    note = res["summary"]["honesty_note"]
    assert "REAL captured telemetry" in note
    assert "RFC 5737" not in note


def test_health_real_data_flag_default_false():
    from augur.api.app import create_app
    app = create_app(log_paths=_DEMO_LOGS)
    client = TestClient(app)
    assert client.get("/api/health").json() == {"status": "ok", "real_data": False}


def test_health_real_data_flag_true_under_real_scenarios():
    from augur.api.app import create_app
    from augur.pipeline import default_scenarios
    from augur.scenarios.loader import load_scenarios
    from augur.topology.network import load_topology
    app = create_app(log_paths=_DEMO_LOGS,
                     topology=load_topology("datasets/real/topology_otrf_theshire.yaml"),
                     scenarios=default_scenarios() + load_scenarios("scenarios_real"))
    client = TestClient(app)
    assert client.get("/api/health").json()["real_data"] is True


# ── Task 5: demo --real wiring helper ───────────────────────────────────────
def test_demo_real_wiring_builds_real_app(tmp_path, monkeypatch):
    """demo._real_app(tagged_path) wires the OTRF topology + default∪real scenarios into create_app."""
    fetcher = _load_fetcher()
    tagged = tmp_path / "tagged.jsonl"
    fetcher.tag_jsonl(Path("tests/fixtures/real/lsass_dump_min.jsonl"), tagged)

    from augur import demo
    app = demo._real_app([str(tagged)])
    client = _login_client(app)
    ids = {s["scenario_id"] for s in client.get("/api/scenarios").json()}
    assert "SCEN-REAL-WIN-T1003-001" in ids
    health = client.get("/api/health").json()
    assert health["real_data"] is True   # served flag set (Task 6 adds the flag plumbing)
