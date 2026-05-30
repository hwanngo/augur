"""TDD: incident consolidated response — pure fold over public incident dicts + build_playbook."""
import ast
from pathlib import Path

import pytest

from augur.api.incident_response import (
    HONESTY_NOTE,
    _validate,
    build_incident_response,
    build_all_incident_responses,
)
from augur.pipeline import default_scenarios, default_topology
from augur.response.playbook import build_playbook


@pytest.fixture(scope="module")
def scenarios():
    return default_scenarios()


@pytest.fixture(scope="module")
def topology():
    return default_topology()


def _inc(incident_id, member_ids, *, top_severity="HIGH", hosts=None):
    """Build a minimal public-incident-shaped dict for tests."""
    return {
        "incident_id": incident_id,
        "size": len(member_ids),
        "members": [{"scenario_id": sid, "name": sid, "severity": top_severity,
                     "proximity": 1.0, "affected_hosts": [], "latest_ts": None}
                    for sid in member_ids],
        "members_truncated": False,
        "hosts": hosts or [],
        "techniques": [],
        "first_ts": None, "last_ts": None,
        "top_severity": top_severity, "max_proximity": 1.0, "score": 1.0,
        "relations": [],
        "honesty_note": "incident note",
    }


def test_honesty_note_is_a_nonempty_standard_template_string():
    assert isinstance(HONESTY_NOTE, str)
    assert "STANDARD" in HONESTY_NOTE
    assert "NOT a bespoke" in HONESTY_NOTE


def test_validate_rejects_non_dict():
    with pytest.raises(ValueError):
        _validate("not a dict")


def test_validate_rejects_missing_incident_id():
    with pytest.raises(ValueError):
        _validate({"members": []})


def test_validate_rejects_missing_members():
    with pytest.raises(ValueError):
        _validate({"incident_id": "INC-0001"})


def test_validate_rejects_member_without_scenario_id():
    with pytest.raises(ValueError):
        _validate({"incident_id": "INC-0001", "members": [{"name": "x"}]})


def test_validate_accepts_well_formed_incident():
    inc = _inc("INC-0001", ["SCEN-WIN-001"])
    assert _validate(inc) is inc


def _payload(p):
    """Convenience: assert a per-incident payload has the expected top-level keys."""
    assert set(p) >= {"incident_id", "top_severity", "member_count", "driving_tactics",
                      "hosts", "sections", "unresolved_scenarios", "note", "honesty_note"}
    assert set(p["sections"]) == {"contain", "eradicate", "recover", "validate"}
    return p


def test_single_member_sections_match_build_playbook(scenarios, topology):
    sid = "SCEN-WIN-001"
    inc = _inc("INC-0001", [sid], top_severity="HIGH")
    p = _payload(build_incident_response(inc, scenarios, topology))
    scen = next(s for s in scenarios if s.scenario_id == sid)
    pb = build_playbook(scen)
    # every contain line from the playbook appears as an action, attributed to this member
    pb_contain = pb["sections"]["contain"]
    got_contain = [a["action"] for a in p["sections"]["contain"]]
    assert got_contain == pb_contain
    for a in p["sections"]["contain"]:
        assert a["from_scenarios"] == [sid]


def test_identical_contain_line_collapses_with_merged_provenance(scenarios, topology):
    # Two members whose driving tactic is identical share contain lines -> collapse, both attributed.
    # SCEN-WIN-001 + a second scenario with the same lowest TA-id would share lines; to be robust,
    # use the same scenario id twice (the fold keys on the exact action string).
    sid = "SCEN-WIN-001"
    inc = _inc("INC-0001", [sid, sid], top_severity="HIGH")
    p = build_incident_response(inc, scenarios, topology)
    for a in p["sections"]["contain"]:
        # collapsed: action listed once, provenance de-duped + sorted
        assert a["from_scenarios"] == [sid]
    actions = [a["action"] for a in p["sections"]["contain"]]
    assert len(actions) == len(set(actions))  # no duplicate action rows


def test_escalate_line_dedups_to_single_top_contain_action(scenarios, topology):
    # Two HIGH/CRITICAL members -> exactly ONE _ESCALATE contain action listing both members.
    a, b = "SCEN-WIN-001", "SCEN-LNX-001"
    inc = _inc("INC-0001", [a, b], top_severity="CRITICAL")
    p = build_incident_response(inc, scenarios, topology)
    escalates = [act for act in p["sections"]["contain"]
                 if act["action"].startswith("Escalate: page on-call IR")]
    assert len(escalates) == 1
    assert escalates[0]["from_scenarios"] == sorted([a, b])
    # it is the FIRST contain action (top)
    assert p["sections"]["contain"][0]["action"].startswith("Escalate:")


def test_driving_tactics_union_unique_sorted_by_ta_id(scenarios, topology):
    a, b = "SCEN-WIN-001", "SCEN-LNX-001"
    inc = _inc("INC-0001", [a, b])
    p = build_incident_response(inc, scenarios, topology)
    dts = p["driving_tactics"]
    tactics = [d["tactic"] for d in dts]
    assert tactics == sorted(set(tactics))         # unique + sorted by TA-id
    for d in dts:
        assert set(d) == {"tactic", "tactic_name"}
        assert isinstance(d["tactic_name"], str) and d["tactic_name"]


def test_validate_triple_dedups_with_merged_provenance(scenarios, topology):
    sid = "SCEN-WIN-001"
    inc = _inc("INC-0001", [sid, sid])
    p = build_incident_response(inc, scenarios, topology)
    seen = set()
    for v in p["sections"]["validate"]:
        assert set(v) == {"engine", "query", "query_path", "from_scenarios"}
        key = (v["engine"], v["query"], v["query_path"])
        assert key not in seen          # each triple appears once
        seen.add(key)
        assert v["from_scenarios"] == sorted(set(v["from_scenarios"]))


def test_hosts_echoed_verbatim_from_incident(scenarios, topology):
    hosts = [{"hostname": "HOST-A", "zone": "User_Endpoint", "criticality": "CRITICAL"}]
    inc = _inc("INC-0001", ["SCEN-WIN-001"], hosts=hosts)
    p = build_incident_response(inc, scenarios, topology)
    assert p["hosts"] == hosts


def test_per_incident_honesty_note_verbatim(scenarios, topology):
    inc = _inc("INC-0001", ["SCEN-WIN-001"])
    p = build_incident_response(inc, scenarios, topology)
    assert p["honesty_note"] == HONESTY_NOTE


def test_top_severity_and_member_count_echoed(scenarios, topology):
    inc = _inc("INC-0007", ["SCEN-WIN-001", "SCEN-LNX-001"], top_severity="CRITICAL")
    p = build_incident_response(inc, scenarios, topology)
    assert p["incident_id"] == "INC-0007"
    assert p["top_severity"] == "CRITICAL"
    assert p["member_count"] == 2


def test_unresolved_member_recorded_and_skipped(scenarios, topology):
    inc = _inc("INC-0001", ["SCEN-WIN-001", "SCEN-DOES-NOT-EXIST"])
    p = build_incident_response(inc, scenarios, topology)
    assert "SCEN-DOES-NOT-EXIST" in p["unresolved_scenarios"]
    # the resolvable member still produced sections
    assert p["sections"]["contain"]
    # no resolvable -> empty sections + note
    inc2 = _inc("INC-0002", ["SCEN-NOPE-1", "SCEN-NOPE-2"])
    p2 = build_incident_response(inc2, scenarios, topology)
    assert p2["sections"]["contain"] == []
    assert p2["note"]
    assert set(p2["unresolved_scenarios"]) == {"SCEN-NOPE-1", "SCEN-NOPE-2"}


def test_malformed_incident_raises_valueerror(scenarios, topology):
    with pytest.raises(ValueError):
        build_incident_response({"members": []}, scenarios, topology)


def test_build_all_preserves_incident_rank_order(scenarios, topology):
    incs = [_inc("INC-0001", ["SCEN-WIN-001"]),
            _inc("INC-0002", ["SCEN-LNX-001"]),
            _inc("INC-0003", ["SCEN-MAC-001"])]
    out = build_all_incident_responses(incs, scenarios, topology)
    assert set(out) == {"responses", "honesty_note"}
    assert out["honesty_note"] == HONESTY_NOTE
    assert [r["incident_id"] for r in out["responses"]] == ["INC-0001", "INC-0002", "INC-0003"]


def test_build_all_empty_input():
    out = build_all_incident_responses([], default_scenarios(), default_topology())
    assert out == {"responses": [], "honesty_note": HONESTY_NOTE}


def test_determinism_member_order_invariant(scenarios, topology):
    a, b = "SCEN-WIN-001", "SCEN-LNX-001"
    inc1 = _inc("INC-0001", [a, b], top_severity="CRITICAL")
    inc2 = _inc("INC-0001", [b, a], top_severity="CRITICAL")  # reversed member order
    p1 = build_incident_response(inc1, scenarios, topology)
    p2 = build_incident_response(inc2, scenarios, topology)
    assert p1 == p2  # byte-identical: member sort + first-seen-order stable


def test_purity_no_engine_graph_networkx_now_random():
    src = Path("src/augur/api/incident_response.py").read_text()
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not any(m.startswith("augur.engine") for m in imported), \
        "incident_response must not import engine internals (scoring/matcher/runner)"
    assert not any(m.startswith("augur.graph") for m in imported), \
        "incident_response must not import a graph backend"
    assert not any(m.startswith("augur.normalize") for m in imported), \
        "incident_response must not import a normalizer"
    assert "networkx" not in imported and not any(m.startswith("networkx") for m in imported), \
        "incident_response must not import networkx"
    assert "random" not in imported
    assert ".now(" not in src and "utcnow" not in src
