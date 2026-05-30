import ast
import pathlib

from augur.metrics.coverage import TACTIC_NAMES
from augur.pipeline import default_scenarios
from augur.response.playbook import TACTIC_PLAYBOOKS, build_playbook
from augur.engine.scoring import Detection
from augur.api.app import _rebuild_detection


_SCEN = {s.scenario_id: s for s in default_scenarios()}


def test_playbook_module_does_not_import_engine():
    src = pathlib.Path("src/augur/response/playbook.py").read_text()
    tree = ast.parse(src)
    mods = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods += [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            mods.append(n.module or "")
    assert not any(m.startswith("augur.engine") for m in mods), mods


def test_table_covers_all_14_tactics_with_three_sections():
    assert set(TACTIC_PLAYBOOKS) == set(TACTIC_NAMES)
    for tid, steps in TACTIC_PLAYBOOKS.items():
        assert set(steps) == {"contain", "eradicate", "recover"}
        for k in ("contain", "eradicate", "recover"):
            assert isinstance(steps[k], list) and all(isinstance(s, str) and s for s in steps[k])


def test_driving_tactic_is_lowest_ta_id():
    for s in _SCEN.values():
        ids = sorted(m.tactic for m in s.scenario_metadata.mitre_mappings)
        pb = build_playbook(s)
        assert pb["derived_from"]["tactic"] == ids[0]


def test_high_or_critical_prepends_escalate_line():
    crit = next(s for s in _SCEN.values() if s.severity.value in ("HIGH", "CRITICAL"))
    low = next((s for s in _SCEN.values() if s.severity.value in ("LOW", "MEDIUM")), None)
    ESC = "Escalate: page on-call IR and open a major-incident bridge."
    assert build_playbook(crit)["sections"]["contain"][0] == ESC
    if low is not None:
        assert ESC not in build_playbook(low)["sections"]["contain"]


def test_validate_section_is_validation_queries():
    s = _SCEN["SCEN-WIN-001"]
    got = build_playbook(s)["sections"]["validate"]
    want = [{"engine": q.engine, "query": q.query, "query_path": q.query_path}
            for q in s.actionable_hunting_outputs.validation_queries]
    assert got == want


def test_honesty_label_and_derived_from():
    s = _SCEN["SCEN-WIN-001"]
    pb = build_playbook(s)
    assert pb["scenario_id"] == "SCEN-WIN-001"
    assert pb["label"].startswith("Standard playbook — ")
    df = pb["derived_from"]
    assert set(df) == {"tactic", "tactic_name", "severity"}
    assert df["tactic_name"] == pb["label"].split("— ", 1)[1]


def test_build_playbook_is_deterministic():
    s = _SCEN["SCEN-WIN-001"]
    assert build_playbook(s) == build_playbook(s)


def test_rebuild_detection_ignores_stall_and_private_keys():
    stored = {
        "scenario_id": "X", "name": "n", "severity": "HIGH", "proximity": 0.5,
        "matched_steps": [], "missing_steps": [], "affected_hosts": [],
        "affected_zones": [], "hunting_queries": [],
        "stall": {"kind": "temporal"},          # non-Detection key added by windowed_detections
    }
    d = _rebuild_detection(stored)
    assert isinstance(d, Detection)
    assert d.scenario_id == "X" and d.proximity == 0.5
