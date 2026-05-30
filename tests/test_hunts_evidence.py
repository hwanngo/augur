"""TDD: compute_hunt_evidence — live, deterministic engine reuse (no persistence, no engine change)."""
from augur.hunts.evidence import compute_hunt_evidence, scenario_ids_for_scope


class _Mitre:
    def __init__(self, tactic): self.tactic = tactic
class _Meta:
    def __init__(self, tactic): self.mitre_mappings = [_Mitre(tactic)]
class _Scen:
    def __init__(self, sid, tactic): self.scenario_id = sid; self.scenario_metadata = _Meta(tactic)


_SCENS = [_Scen("S-A", "TA0006"), _Scen("S-B", "Credential Access"), _Scen("S-C", "TA0008")]


def _det(sid, prox, zones, hosts):
    return {"scenario_id": sid, "name": sid, "severity": "HIGH", "proximity": prox,
            "affected_zones": zones, "affected_hosts": hosts,
            "matched_steps": [{"step_id": 1}], "missing_steps": [{"step_id": 2, "matching_criteria": {}}],
            "hunting_queries": []}


def _windowed_at(frm_iso, to_iso):
    return (_det("S-A", 0.66, ["DMZ"], ["WEB01"]), _det("S-C", 0.5, ["Internal_Server"], ["APP01"]))


def test_scope_scenario_id_filter():
    out = compute_hunt_evidence({"scenario_ids": ["S-A"]}, windowed_at=_windowed_at,
                                scenarios=_SCENS, topology=None)
    assert [e["scenario_id"] for e in out["evidence"]] == ["S-A"]


def test_scope_tactic_filter_case_insensitive_or_across_mappings():
    ids = scenario_ids_for_scope({"tactic": "ta0008"}, _SCENS)
    assert ids == {"S-C"}
    ids2 = scenario_ids_for_scope({"tactic": "credential access"}, _SCENS)
    assert ids2 == {"S-B"}


def test_scope_zone_host_filter():
    out = compute_hunt_evidence({"zone": "DMZ"}, windowed_at=_windowed_at, scenarios=_SCENS, topology=None)
    assert [e["scenario_id"] for e in out["evidence"]] == ["S-A"]
    out2 = compute_hunt_evidence({"host": "APP01"}, windowed_at=_windowed_at, scenarios=_SCENS, topology=None)
    assert [e["scenario_id"] for e in out2["evidence"]] == ["S-C"]


def test_empty_scope_returns_all():
    out = compute_hunt_evidence({}, windowed_at=_windowed_at, scenarios=_SCENS, topology=None)
    assert {e["scenario_id"] for e in out["evidence"]} == {"S-A", "S-C"}


def test_evidence_shape_has_next_step_and_honesty():
    out = compute_hunt_evidence({"scenario_ids": ["S-A"]}, windowed_at=_windowed_at,
                                scenarios=_SCENS, topology=None)
    e = out["evidence"][0]
    assert e["proximity"] == 0.66 and e["matched_count"] == 1
    assert e["next_step_to_hunt"]["step_id"] == 2
    assert "recomputed live" in out["honesty_note"]


def test_determinism_recompute_identical():
    a = compute_hunt_evidence({}, windowed_at=_windowed_at, scenarios=_SCENS, topology=None)
    b = compute_hunt_evidence({}, windowed_at=_windowed_at, scenarios=_SCENS, topology=None)
    assert a["evidence"] == b["evidence"]
