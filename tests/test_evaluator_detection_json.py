import json
from datetime import datetime, timezone

from augur.alerting.evaluator import _detection_json
from augur.engine.scoring import build_detection
from augur.engine.matcher import Candidate
from augur.graph.models import HostNode
from augur.enums import Zone, Criticality
from augur.scenarios.loader import load_scenarios

# NB: any FUTURE top-level F1/F3 field must be added to _detection_json's whitelist explicitly.
SCN = {s.scenario_id: s for s in load_scenarios("scenarios")}
H = HostNode(id="h", hostname="HR_User_PC", ip="1", os="o",
             zone=Zone.User_Endpoint, criticality=Criticality.MEDIUM)
T = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)


def test_enriched_missing_steps_survive_detection_json_whitelist():
    s = SCN["SCEN-WIN-001"]
    d = build_detection(s, 1, [Candidate("e0", T, H)])
    payload = json.loads(_detection_json(d))           # the alert whitelist
    assert "missing_steps" in payload                  # whitelisted ⇒ survives
    for m in payload["missing_steps"]:
        assert "matching_criteria" in m and "temporal" in m
    # the temporal sub-dict round-tripped through JSON intact
    step2 = next(m for m in payload["missing_steps"] if m["step_id"] == 2)
    assert step2["temporal"]["max_time_delta_seconds"] >= 0
