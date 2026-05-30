"""replay_detection — pure helper that reads the precomputed dashboard detection list (no engine re-run).
Plus /api/drill replay-route + /api/scenarios synthesizable-field tests (added in later tasks)."""
from augur.api.drill import replay_detection


_FAKE_DETS = [
    {"scenario_id": "SCEN-REAL-WIN-T1548-002-001", "name": "UAC bypass", "severity": "HIGH",
     "proximity": 1.0, "affected_hosts": ["WORKSTATION5.theshire.local"],
     "affected_zones": ["User_Endpoint"], "matched_steps": [], "missing_steps": [],
     "hunting_queries": []},
    {"scenario_id": "SCEN-REAL-WIN-T1003-001", "name": "LSASS dump", "severity": "CRITICAL",
     "proximity": 1.0, "affected_hosts": ["WORKSTATION5.theshire.local"],
     "affected_zones": ["User_Endpoint"], "matched_steps": [], "missing_steps": [],
     "hunting_queries": []},
]


def test_replay_detection_returns_the_precomputed_detection():
    out = replay_detection("SCEN-REAL-WIN-T1548-002-001", "UAC bypass", _FAKE_DETS)
    assert out["mode"] == "replay"
    assert out["scenario_id"] == "SCEN-REAL-WIN-T1548-002-001"
    assert out["host"] is None                      # no host was chosen — the capture decided
    assert out["feed_summary"] is None              # nothing synthesized — honest absence
    assert out["detection"] is _FAKE_DETS[0]        # exact precomputed detection (no copy/re-run)
    assert out["replay_hosts"] == ["WORKSTATION5.theshire.local"]  # from detection.affected_hosts
    assert "Replayed against loaded real telemetry" in out["note"]
    assert "not present" not in out["note"]


def test_replay_detection_not_present_in_capture():
    out = replay_detection("SCEN-REAL-WIN-T1197-001", "BITS job", _FAKE_DETS)
    assert out["mode"] == "replay"
    assert out["detection"] is None
    assert out["replay_hosts"] == []
    assert out["host"] is None
    assert out["feed_summary"] is None
    assert "not present in the loaded capture" in out["note"]


def test_replay_detection_is_pure():
    a = replay_detection("SCEN-REAL-WIN-T1548-002-001", "UAC bypass", _FAKE_DETS)
    b = replay_detection("SCEN-REAL-WIN-T1548-002-001", "UAC bypass", _FAKE_DETS)
    assert a == b


import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password
from augur.pipeline import default_scenarios
from augur.scenarios.loader import load_scenarios
from augur.topology.network import load_topology

_OTRF_TOPOLOGY = "datasets/real/topology_otrf_theshire.yaml"


def _real_app(log_paths):
    """--real-style app: OTRF topology + default∪real scenarios (mirrors demo._real_app)."""
    topology = load_topology(_OTRF_TOPOLOGY)
    scenarios = default_scenarios() + load_scenarios("scenarios_real")
    return create_app(log_paths=log_paths, topology=topology, scenarios=scenarios)


def _login(app, role="analyst"):
    app.state.auth.users.create_user("u", hash_password("password1234"), role)
    c = TestClient(app)
    csrf = c.post("/api/auth/login",
                  data={"username": "u", "password": "password1234"}).json()["csrf_token"]
    return c, {"X-CSRF-Token": csrf}


def test_scenarios_synthesizable_field_normal_mode():
    app = create_app(log_paths=["sample_data/acceptance/demo_multi_os.jsonl"])
    c, _ = _login(app, role="viewer")
    rows = c.get("/api/scenarios").json()
    assert rows, "expected scenarios"
    # NORMAL mode: every scenario is synthesizable.
    assert all(r["synthesizable"] is True for r in rows)
    assert all(isinstance(r["synthesizable"], bool) for r in rows)


def test_scenarios_synthesizable_field_real_mode():
    app = _real_app(["sample_data/acceptance/demo_multi_os.jsonl"])
    c, _ = _login(app, role="viewer")
    rows = {r["scenario_id"]: r for r in c.get("/api/scenarios").json()}
    assert rows["SCEN-REAL-WIN-T1548-002-001"]["synthesizable"] is False  # non-synth real
    assert rows["SCEN-REAL-WIN-T1003-001"]["synthesizable"] is True       # synth real
    assert rows["SCEN-WIN-001"]["synthesizable"] is True                  # synthetic


import importlib
import sys
from pathlib import Path


def _load_fetcher():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import fetch_real_datasets
    return importlib.reload(fetch_real_datasets)


def _real_app_with_capture(tmp_path):
    """Tag tests/fixtures/real/lsass_dump_min.jsonl (fires non-synth SCEN-REAL-WIN-T1548-002-001
    AND synth SCEN-REAL-WIN-T1003-001 on WORKSTATION5.theshire.local) and wire a --real app on it."""
    fetcher = _load_fetcher()
    tagged = tmp_path / "tagged.jsonl"
    fetcher.tag_jsonl(Path("tests/fixtures/real/lsass_dump_min.jsonl"), tagged)
    return _real_app([str(tagged)])


def test_drill_replay_for_non_synth_scenario_present_in_capture(tmp_path):
    app = _real_app_with_capture(tmp_path)
    c, h = _login(app, role="analyst")
    r = c.post("/api/drill",
               json={"scenario_id": "SCEN-REAL-WIN-T1548-002-001", "host": ""}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mode"] == "replay"
    assert body["host"] is None
    assert body["feed_summary"] is None
    assert body["detection"] is not None
    assert body["detection"]["scenario_id"] == "SCEN-REAL-WIN-T1548-002-001"
    assert any(host.lower() == "workstation5.theshire.local"
               for host in body["replay_hosts"])
    assert "Replayed against loaded real telemetry" in body["note"]


def test_drill_replay_for_non_synth_scenario_absent_from_capture(tmp_path):
    # SCEN-REAL-WIN-T1197-001 is non-synth AND not present in lsass_dump_min.jsonl → honest empty replay.
    app = _real_app_with_capture(tmp_path)
    c, h = _login(app, role="analyst")
    r = c.post("/api/drill",
               json={"scenario_id": "SCEN-REAL-WIN-T1197-001", "host": ""}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mode"] == "replay"
    assert body["detection"] is None
    assert body["replay_hosts"] == []
    assert "not present in the loaded capture" in body["note"]


def test_drill_synth_for_synthesizable_real_scenario_still_injects(tmp_path):
    # A synthesizable real scenario takes the synth path (mode inject) — replay branch is capability-driven.
    app = _real_app_with_capture(tmp_path)
    c, h = _login(app, role="analyst")
    r = c.post("/api/drill",
               json={"scenario_id": "SCEN-REAL-WIN-T1003-001", "host": "WORKSTATION5.theshire.local"},
               headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mode"] == "inject"
    assert body["feed_summary"] is not None
    assert set(body["feed_summary"]) == {"total_events", "baseline_events", "injected_events"}
    assert body["host"] == "WORKSTATION5.theshire.local"


def test_drill_synth_validate_error_on_synthesizable_scenario_still_422(tmp_path):
    # A SYNTHESIZABLE scenario with a wrong host/OS must still 422 — the predicate branch does NOT swallow it.
    app = _real_app_with_capture(tmp_path)
    c, h = _login(app, role="analyst")
    # SCEN-WIN-001 (synthetic, windows) onto a bogus host → validate_injection raises → 422.
    r = c.post("/api/drill",
               json={"scenario_id": "SCEN-WIN-001", "host": "NO_SUCH_HOST"}, headers=h)
    assert r.status_code == 422, r.text
    assert "NO_SUCH_HOST" in r.json()["detail"]


def test_drill_unknown_scenario_still_422(tmp_path):
    # Unknown scenario falls through to run_drill → validate_injection ValueError → 422 (not 404).
    app = _real_app_with_capture(tmp_path)
    c, h = _login(app, role="analyst")
    r = c.post("/api/drill",
               json={"scenario_id": "SCEN-NOPE-999", "host": "WORKSTATION5.theshire.local"}, headers=h)
    assert r.status_code == 422, r.text
