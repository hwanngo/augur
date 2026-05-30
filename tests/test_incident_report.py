"""TDD: incident post-incident report — pure fold over a public incident dict + a response dict."""
import ast
from pathlib import Path

import pytest

from augur.api.incident_report import (
    HONESTY_NOTE,
    _validate,
    build_incident_report,
    report_to_markdown,
)


def _inc(incident_id="INC-0001"):
    """A realistic public incident dict (shape from incidents.py::cluster_incidents)."""
    return {
        "incident_id": incident_id,
        "size": 2,
        "members": [
            {"scenario_id": "SCEN-LNX-001", "name": "Linux thing", "severity": "HIGH",
             "proximity": 1.0, "affected_hosts": ["HOST-B"], "latest_ts": "2026-01-01T01:00:00+00:00"},
            {"scenario_id": "SCEN-WIN-001", "name": "Win thing", "severity": "CRITICAL",
             "proximity": 0.75, "affected_hosts": ["HOST-A"], "latest_ts": "2026-01-01T02:00:00+00:00"},
        ],
        "members_truncated": False,
        "hosts": [
            {"hostname": "HOST-A", "zone": "User_Endpoint", "criticality": "CRITICAL"},
            {"hostname": "HOST-B", "zone": "Server", "criticality": "HIGH"},
        ],
        "techniques": ["T1059", "T1078"],
        "first_ts": "2026-01-01T01:00:00+00:00",
        "last_ts": "2026-01-01T02:00:00+00:00",
        "top_severity": "CRITICAL",
        "max_proximity": 1.0,
        "score": 5.0,
        "relations": ["shared_host", "shared_technique"],
        "honesty_note": "INCIDENT NOTE about correlation not campaign.",
    }


def _resp(incident_id="INC-0001"):
    """A realistic response dict (shape from incident_response.py::build_incident_response)."""
    return {
        "incident_id": incident_id,
        "top_severity": "CRITICAL",
        "member_count": 2,
        "driving_tactics": [{"tactic": "TA0002", "tactic_name": "Execution"}],
        "hosts": [
            {"hostname": "HOST-A", "zone": "User_Endpoint", "criticality": "CRITICAL"},
            {"hostname": "HOST-B", "zone": "Server", "criticality": "HIGH"},
        ],
        "sections": {
            "contain": [{"action": "Escalate: page on-call IR", "from_scenarios": ["SCEN-LNX-001", "SCEN-WIN-001"]}],
            "eradicate": [{"action": "Remove persistence", "from_scenarios": ["SCEN-WIN-001"]}],
            "recover": [{"action": "Restore from backup", "from_scenarios": ["SCEN-LNX-001"]}],
            "validate": [{"engine": "augur", "query": "rerun scenario", "query_path": "scenarios/x.yaml",
                          "from_scenarios": ["SCEN-WIN-001"]}],
        },
        "unresolved_scenarios": [],
        "note": "",
        "honesty_note": "RESPONSE NOTE about standard template not bespoke.",
    }


def test_honesty_note_combines_both_and_adds_what_this_is_not():
    assert isinstance(HONESTY_NOTE, str)
    assert "NOT a confirmed adversary campaign" in HONESTY_NOTE
    assert "NOT a causal attribution" in HONESTY_NOTE
    assert "NOT a bespoke incident-response plan" in HONESTY_NOTE
    assert "NOT a containment guarantee" in HONESTY_NOTE
    assert "no narrative is invented" in HONESTY_NOTE


def test_validate_rejects_non_dict_incident():
    with pytest.raises(ValueError):
        _validate("nope", _resp())


def test_validate_rejects_non_dict_response():
    with pytest.raises(ValueError):
        _validate(_inc(), "nope")


def test_validate_rejects_id_mismatch():
    with pytest.raises(ValueError):
        _validate(_inc("INC-0001"), _resp("INC-9999"))


def test_validate_rejects_missing_incident_id():
    with pytest.raises(ValueError):
        _validate({"size": 1}, _resp())


def test_validate_accepts_matching_ids():
    inc, resp = _inc(), _resp()
    assert _validate(inc, resp) == ("INC-0001",)


def test_build_six_sections_present_with_real_field_provenance():
    rep = build_incident_report(_inc(), _resp())
    assert set(rep) == {
        "incident_id", "header", "affected_assets", "techniques",
        "detection_summary", "response", "source_notes", "honesty_note",
    }
    # header SELECTS real incident fields (no recompute)
    h = rep["header"]
    assert h == {
        "incident_id": "INC-0001",
        "top_severity": "CRITICAL",
        "max_proximity": 1.0,
        "score": 5.0,
        "member_count": 2,
        "host_count": 2,
        "technique_count": 2,
        "first_ts": "2026-01-01T01:00:00+00:00",
        "last_ts": "2026-01-01T02:00:00+00:00",
        "relations": ["shared_host", "shared_technique"],
        "members_truncated": False,
    }
    # affected assets echoed verbatim from the incident payload (topology authoritative)
    assert rep["affected_assets"] == _inc()["hosts"]
    # techniques echoed verbatim
    assert rep["techniques"] == ["T1059", "T1078"]
    # detection summary echoed verbatim from incident members
    assert rep["detection_summary"] == _inc()["members"]
    # response embedded verbatim (no re-fold)
    assert rep["response"] == _resp()
    # both upstream notes carried verbatim for the footer/UI
    assert rep["source_notes"] == {
        "incident": "INCIDENT NOTE about correlation not campaign.",
        "response": "RESPONSE NOTE about standard template not bespoke.",
    }
    # combined honesty note
    assert rep["honesty_note"] == HONESTY_NOTE


def test_build_id_mismatch_raises():
    with pytest.raises(ValueError):
        build_incident_report(_inc("INC-0001"), _resp("INC-0002"))


def test_build_is_a_pure_fold_no_mutation_of_inputs():
    inc, resp = _inc(), _resp()
    import copy
    inc_before, resp_before = copy.deepcopy(inc), copy.deepcopy(resp)
    build_incident_report(inc, resp)
    assert inc == inc_before
    assert resp == resp_before


def test_markdown_is_deterministic_and_total():
    rep = build_incident_report(_inc(), _resp())
    md1 = report_to_markdown(rep)
    md2 = report_to_markdown(rep)
    assert md1 == md2                       # deterministic
    assert isinstance(md1, str) and md1     # total, non-empty


def test_markdown_contains_all_six_sections_and_key_fields():
    md = report_to_markdown(build_incident_report(_inc(), _resp()))
    assert "# Post-Incident Report — INC-0001" in md
    assert "## Header" in md
    assert "## Affected Assets" in md
    assert "## MITRE Technique Coverage" in md
    assert "## Detection Summary" in md
    assert "## Consolidated Response" in md
    assert "## Honesty" in md
    # selected fields appear
    assert "CRITICAL" in md
    assert "HOST-A" in md
    assert "T1059" in md
    assert "SCEN-WIN-001" in md
    assert "Escalate: page on-call IR" in md
    # honesty footer lifts BOTH upstream notes verbatim + the combined note
    assert "INCIDENT NOTE about correlation not campaign." in md
    assert "RESPONSE NOTE about standard template not bespoke." in md
    assert HONESTY_NOTE in md


def test_markdown_truncation_line_present_when_members_truncated():
    inc = _inc()
    inc["members_truncated"] = True
    inc["size"] = 99          # TRUE count larger than the 2 shown members
    md = report_to_markdown(build_incident_report(inc, _resp()))
    assert "2 of 99 members shown" in md


def test_markdown_no_truncation_line_when_not_truncated():
    md = report_to_markdown(build_incident_report(_inc(), _resp()))
    assert "members shown" not in md


def test_markdown_golden_snapshot():
    md = report_to_markdown(build_incident_report(_inc(), _resp()))
    expected = (Path(__file__).parent / "golden" / "incident_report_INC-0001.md").read_text()
    assert md == expected


def test_purity_no_engine_graph_networkx_now_random():
    src = Path("src/augur/api/incident_report.py").read_text()
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not any(m.startswith("augur.engine") for m in imported), \
        "incident_report must not import engine internals (scoring/matcher/runner)"
    assert not any(m.startswith("augur.graph") for m in imported), \
        "incident_report must not import a graph backend"
    assert not any(m.startswith("augur.normalize") for m in imported), \
        "incident_report must not import a normalizer"
    assert "networkx" not in imported and not any(m.startswith("networkx") for m in imported), \
        "incident_report must not import networkx"
    assert "random" not in imported
    assert ".now(" not in src and "utcnow" not in src
    assert "run_engine" not in src and "build_graph" not in src
