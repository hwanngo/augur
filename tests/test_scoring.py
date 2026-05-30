import json
from datetime import datetime, timezone
from augur.engine.scoring import build_detection, rank, Detection
from augur.engine.matcher import Candidate
from augur.graph.models import HostNode
from augur.enums import Zone, Criticality
from augur.scenarios.loader import load_scenarios

SCN = {s.scenario_id: s for s in load_scenarios("scenarios")}
H = HostNode(id="hr", hostname="HR_User_PC", ip="1", os="o", zone=Zone.User_Endpoint, criticality=Criticality.MEDIUM)
T = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)


def test_build_detection_full():
    s = SCN["SCEN-WIN-001"]  # 3-step Windows LSASS chain
    chain = [Candidate(element_id=f"e{i}", timestamp=T, host=H) for i in range(3)]
    d = build_detection(s, 3, chain)
    assert d.proximity == 1.0
    assert len(d.matched_steps) == 3 and d.missing_steps == []
    assert d.affected_hosts == ["HR_User_PC"]
    assert d.affected_zones == ["User_Endpoint"]
    assert d.hunting_queries[0]["engine"] in ("KQL", "Sigma")


def test_build_detection_partial():
    s = SCN["SCEN-WIN-001"]
    chain = [Candidate(element_id=f"e{i}", timestamp=T, host=H) for i in range(2)]
    d = build_detection(s, 2, chain)
    assert d.proximity == 0.6667
    assert [m["step_id"] for m in d.missing_steps] == [3]


def test_missing_steps_carry_matching_criteria_and_temporal():
    s = SCN["SCEN-WIN-001"]  # 3-step chain; partial leaves steps 2,3 missing
    d = build_detection(s, 1, [Candidate("e0", T, H)])
    miss = {m["step_id"]: m for m in d.missing_steps}
    assert set(miss) == {2, 3}
    # additive keys present alongside the originals
    for m in d.missing_steps:
        assert set(m) >= {"step_id", "name", "matching_criteria", "temporal"}
        assert isinstance(m["matching_criteria"], dict)
        assert "Node_Type" in m["matching_criteria"]
    # step 2 has a temporal_link → serialized dict with window + link_scope
    assert miss[2]["temporal"] is not None
    assert set(miss[2]["temporal"]) >= {
        "previous_step", "link_scope", "min_time_delta_seconds", "max_time_delta_seconds"}
    # LinkScope (str,Enum) round-trips as a plain string (JSON-native) — [AUDIT #4]
    assert isinstance(json.loads(json.dumps(miss[2]["temporal"]))["link_scope"], str)


def test_step_one_missing_has_null_temporal():
    s = SCN["SCEN-WIN-001"]
    d = build_detection(s, 0, [])           # nothing matched → step 1 is missing
    first = next(m for m in d.missing_steps if m["step_id"] == 1)
    assert first["temporal"] is None        # step 1 never has a temporal_link


def test_proximity_and_matched_unchanged_by_enrichment():
    s = SCN["SCEN-WIN-001"]
    d = build_detection(s, 2, [Candidate(f"e{i}", T, H) for i in range(2)])
    assert d.proximity == 0.6667            # byte-identical to pre-change value
    assert [m["step_id"] for m in d.matched_steps] == [1, 2]


def test_rank_filters_and_orders():
    s = SCN["SCEN-WIN-001"]
    full = build_detection(s, 3, [Candidate(f"e{i}", T, H) for i in range(3)])
    weak = build_detection(s, 1, [Candidate("e0", T, H)])  # 0.3333 ~ filtered below
    ranked = rank([weak, full], min_proximity=0.50)
    assert [d.proximity for d in ranked] == [1.0]
