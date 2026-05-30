"""TDD: detection_health.compute_detection_health — pure, deterministic, corpus-time only.

Events are sourced via feed.load_normalized (for the corpus span) and detections via the
windowed_detections helper. Both are patched in tests to avoid touching disk / the engine.
"""
import ast
from datetime import datetime, timezone
from pathlib import Path

import pytest

from augur.api.detection_health import (
    compute_detection_health, HEALTH_STATES, SWEEP_BUCKETS, HONESTY_NOTE,
)
from augur.normalize.model import NormalizedEvent
from augur.topology.network import Topology
from augur.enums import Zone, Criticality, Severity
from augur.scenarios.schema import Scenario


# ── tiny in-memory topology ──────────────────────────────────────────────────
def _topo():
    return Topology(zones=[Zone.User_Endpoint], assets=[
        {"hostname": "HOST-A", "zone": Zone.User_Endpoint, "criticality": Criticality.CRITICAL,
         "os": "windows", "ip": "10.0.0.1"},
    ])


def _ev(ts):
    return NormalizedEvent(
        timestamp=datetime.fromisoformat(ts), kind="process_create", host="HOST-A",
        event_id="e", process_name="p.exe",
    )


def _scenario(scenario_id, *, name="S", severity="HIGH", os_family="windows",
              tactic="TA0002", technique="T1059", steps=2):
    """Build a minimal valid Scenario object for join/shape tests."""
    step_dicts = []
    for i in range(1, steps + 1):
        s = {"step_id": i, "name": f"step{i}",
             "matching_criteria": {"Node_Type": "Process", "process_name": {"equals": "p.exe"}}}
        if i > 1:
            s["temporal_link"] = {"previous_step": i - 1, "max_time_delta_seconds": 3600}
        step_dicts.append(s)
    return Scenario(
        scenario_metadata={"scenario_id": scenario_id, "name": name, "description": "d",
                           "severity": severity,
                           "mitre_mappings": [{"tactic": tactic, "technique": technique}],
                           "os_family": os_family},
        spatial_constraints={"applicable_zones": ["User_Endpoint"]},
        attack_sequence_flow={"steps": step_dicts},
        actionable_hunting_outputs={"validation_queries": [{"engine": "kql", "query": "x"}]},
    )


@pytest.fixture
def patched(monkeypatch):
    """Patch the two collaborators detection_health imports: load_normalized + windowed_detections.

    bag["events"]   -> list[NormalizedEvent] returned by load_normalized (for span).
    bag["windows"]  -> dict[str (to.isoformat()) -> list[public detection dict]] returned per call.
                       A missing bound returns [].
    """
    bag = {"events": [], "windows": {}}
    monkeypatch.setattr("augur.api.detection_health.load_normalized",
                        lambda _paths: list(bag["events"]))
    monkeypatch.setattr(
        "augur.api.detection_health.windowed_detections",
        lambda log_paths, topology, scenarios, *, frm, to: list(bag["windows"].get(to.isoformat(), [])),
    )
    return bag


def test_empty_feed_all_never(patched):
    scens = [_scenario("SCEN-WIN-001"), _scenario("SCEN-LNX-001")]
    out = compute_detection_health(["x.jsonl"], _topo(), scens)
    assert out["summary"]["scenarios_total"] == 2
    assert out["summary"]["by_state"] == {"FIRING": 0, "PARTIAL": 0, "SILENT": 0, "NEVER": 2}
    assert out["summary"]["corpus_span"] == {"from": None, "to": None}
    assert out["summary"]["sweep_buckets"] == SWEEP_BUCKETS
    assert out["summary"]["honesty_note"] == HONESTY_NOTE
    for row in out["scenarios"]:
        assert row["state"] == "NEVER"
        assert row["last_fired"] is None
        assert row["fire_count"] == 0
        assert row["max_proximity"] == 0.0
        assert row["affected_host_count"] == 0


def test_constants():
    assert HEALTH_STATES == ("FIRING", "PARTIAL", "SILENT", "NEVER")
    assert SWEEP_BUCKETS == 6
    assert "corpus" in HONESTY_NOTE.lower()
    assert "broken" in HONESTY_NOTE.lower()


def _det(scenario_id, proximity, *, hosts=("HOST-A",), ts="2026-01-01T10:00:00+00:00", steps=2):
    """A public detection dict (matched_steps carry the timestamp; no _latest_ts in public dicts)."""
    matched = []
    n = round(proximity * steps)
    for i in range(1, n + 1):
        matched.append({"step_id": i, "name": f"step{i}", "element_id": f"e{i}",
                        "host": hosts[0], "timestamp": ts})
    return {
        "scenario_id": scenario_id, "name": "S", "severity": "HIGH",
        "proximity": proximity, "matched_steps": matched, "missing_steps": [],
        "affected_hosts": list(hosts), "affected_zones": ["User_Endpoint"], "hunting_queries": [],
    }


def _span_events():
    # span = [10:00, 12:00]; SWEEP_BUCKETS bounds are evenly spaced inclusive of max.
    return [_ev("2026-01-01T10:00:00+00:00"), _ev("2026-01-01T12:00:00+00:00")]


def _final_to(events):
    """Replicate the module's max-bound (== max event ts, tz-aware)."""
    return max(e.timestamp.replace(tzinfo=timezone.utc) if e.timestamp.tzinfo is None
               else e.timestamp for e in events).isoformat()


def test_firing_classification(patched):
    patched["events"] = _span_events()
    final = _final_to(patched["events"])
    # every bound returns the same full detection (growing window from fixed frm)
    det = _det("SCEN-WIN-001", 1.0, hosts=("HOST-A", "HOST-B"),
               ts="2026-01-01T11:30:00+00:00")
    patched["windows"] = {final: [det]}
    # also register the det for ALL bounds so fire_count counts every bucket:
    # the module asks for SWEEP_BUCKETS distinct bounds; we make every bound return the det
    # by defaulting missing bounds via a dict subclass.
    class _All(dict):
        def get(self, k, default=None): return [det]
    patched["windows"] = _All()
    out = compute_detection_health(["x"], _topo(), [_scenario("SCEN-WIN-001")])
    row = out["scenarios"][0]
    assert row["state"] == "FIRING"
    assert row["max_proximity"] == 1.0
    assert row["fire_count"] == SWEEP_BUCKETS
    assert row["last_fired"] == "2026-01-01T11:30:00+00:00"
    assert row["affected_host_count"] == 2
    assert out["summary"]["corpus_span"] == {
        "from": "2026-01-01T10:00:00+00:00", "to": "2026-01-01T12:00:00+00:00"}


def test_partial_classification(patched):
    patched["events"] = _span_events()
    det = _det("SCEN-WIN-001", 0.5, ts="2026-01-01T11:00:00+00:00", steps=2)

    class _All(dict):
        def get(self, k, default=None): return [det]
    patched["windows"] = _All()
    out = compute_detection_health(["x"], _topo(), [_scenario("SCEN-WIN-001")])
    row = out["scenarios"][0]
    assert row["state"] == "PARTIAL"
    assert 0.0 < row["max_proximity"] < 1.0
    assert row["last_fired"] == "2026-01-01T11:00:00+00:00"


def test_never_when_absent_from_all_windows(patched):
    patched["events"] = _span_events()
    patched["windows"] = {}   # every bound -> []
    out = compute_detection_health(["x"], _topo(),
                                   [_scenario("SCEN-WIN-001"), _scenario("SCEN-LNX-001")])
    for row in out["scenarios"]:
        assert row["state"] == "NEVER"
        assert row["fire_count"] == 0
        assert row["last_fired"] is None


def test_silent_when_decayed_out_of_final(patched):
    """Fired in an earlier bucket (proximity>0) but proximity==0 in the final window."""
    patched["events"] = _span_events()
    final = _final_to(patched["events"])
    early = _det("SCEN-WIN-001", 0.5, ts="2026-01-01T10:30:00+00:00", steps=2)

    class _Sweep(dict):
        def get(self, k, default=None):
            return [] if k == final else [early]
    patched["windows"] = _Sweep()
    out = compute_detection_health(["x"], _topo(), [_scenario("SCEN-WIN-001")])
    row = out["scenarios"][0]
    assert row["state"] == "SILENT"
    assert row["fire_count"] >= 1
    assert row["max_proximity"] == 0.5


def test_sort_problems_first(patched):
    patched["events"] = _span_events()
    final = _final_to(patched["events"])
    firing = _det("SCEN-WIN-001", 1.0, steps=2)
    partial = _det("SCEN-WIN-002", 0.5, steps=2)

    class _Sweep(dict):
        def get(self, k, default=None): return [firing, partial]
    patched["windows"] = _Sweep()
    scens = [_scenario("SCEN-WIN-001"), _scenario("SCEN-WIN-002"),
             _scenario("SCEN-LNX-009"), _scenario("SCEN-MAC-003")]  # last two NEVER
    out = compute_detection_health(["x"], _topo(), scens)
    states = [r["state"] for r in out["scenarios"]]
    # NEVER rows first (sorted by scenario_id), then PARTIAL, then FIRING
    assert states == ["NEVER", "NEVER", "PARTIAL", "FIRING"]
    assert out["scenarios"][0]["scenario_id"] == "SCEN-LNX-009"
    assert out["scenarios"][1]["scenario_id"] == "SCEN-MAC-003"


def test_rollup_sums_to_total(patched):
    patched["events"] = _span_events()
    firing = _det("SCEN-WIN-001", 1.0, steps=2)

    class _Sweep(dict):
        def get(self, k, default=None): return [firing]
    patched["windows"] = _Sweep()
    scens = [_scenario("SCEN-WIN-001"), _scenario("SCEN-LNX-001")]
    out = compute_detection_health(["x"], _topo(), scens)
    by = out["summary"]["by_state"]
    assert sum(by.values()) == out["summary"]["scenarios_total"] == 2
    assert by["FIRING"] == 1 and by["NEVER"] == 1


def test_determinism_byte_identical(patched):
    patched["events"] = _span_events()
    det = _det("SCEN-WIN-001", 1.0, steps=2)

    class _Sweep(dict):
        def get(self, k, default=None): return [det]
    patched["windows"] = _Sweep()
    a = compute_detection_health(["x"], _topo(), [_scenario("SCEN-WIN-001")])
    b = compute_detection_health(["x"], _topo(), [_scenario("SCEN-WIN-001")])
    assert a == b


def test_purity_no_engine_now_random():
    src = Path("src/augur/api/detection_health.py").read_text()
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    # may import augur.api.detections (the blessed wrapper) but NOT engine internals
    assert not any(m.startswith("augur.engine") for m in imported), \
        "detection_health must not import engine internals"
    assert not any(m.startswith("augur.normalize") for m in imported), \
        "detection_health must not import a normalizer"
    assert "random" not in imported
    assert ".now(" not in src and "utcnow" not in src


def test_integration_real_corpus():
    """End-to-end against the bundled corpus + real scenario library + topology."""
    from augur.pipeline import default_topology, default_scenarios
    logs = ["sample_data/corpus/enterprise_day.jsonl"]
    out = compute_detection_health(logs, default_topology(), default_scenarios())
    s = out["summary"]
    assert s["scenarios_total"] == len(default_scenarios())
    assert sum(s["by_state"].values()) == s["scenarios_total"]
    assert set(s["by_state"]) == set(HEALTH_STATES)
    assert s["corpus_span"]["from"] is not None and s["corpus_span"]["to"] is not None
    assert s["honesty_note"] == HONESTY_NOTE
    # at least some scenarios should be firing over the enterprise-day corpus
    assert s["by_state"]["FIRING"] >= 1
    # row shape
    for r in out["scenarios"]:
        assert set(r) == {"scenario_id", "name", "severity", "os_family", "tactics",
                          "state", "max_proximity", "fire_count", "last_fired",
                          "affected_host_count"}
        assert r["state"] in HEALTH_STATES
    # sort: NEVER/SILENT/PARTIAL before FIRING
    order = {"NEVER": 0, "SILENT": 1, "PARTIAL": 2, "FIRING": 3}
    keys = [(order[r["state"]], r["scenario_id"]) for r in out["scenarios"]]
    assert keys == sorted(keys)

# Heavy full-corpus engine sweeps — skipped on per-push CI (-m 'not slow'); run weekly.
pytestmark = pytest.mark.slow
