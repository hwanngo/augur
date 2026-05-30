import ast
import pathlib
from uuid import uuid5

import yaml

from augur.pipeline import default_scenarios
from augur.api.sigma import (
    HONESTY_NOTE,
    UNMAPPABLE_NOTE,
    SIGMA_NAMESPACE,
    SIGMA_EXPORT_DATE,
    _NONFIRING_SELECTION,
    step_to_sigma,
    scenario_to_sigma,
    to_yaml,
    pack_to_yaml,
)

_SCEN = {s.scenario_id: s for s in default_scenarios()}
_WIN1 = _SCEN["SCEN-WIN-001"]


def _step(scenario, step_id):
    return next(s for s in scenario.attack_sequence_flow.steps if s.step_id == step_id)


# ── purity guard ──────────────────────────────────────────────────────────────
def test_sigma_module_imports_no_engine_or_nondeterminism():
    src = pathlib.Path("src/augur/api/sigma.py").read_text()
    tree = ast.parse(src)
    mods = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods += [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            mods.append(n.module or "")
    assert not any(m.startswith("augur.engine") for m in mods), mods
    assert not any(m.startswith("augur.graph") for m in mods), mods
    # no wall-clock / randomness anywhere in the source (belt-and-suspenders)
    assert "uuid4" not in src
    assert "datetime.now" not in src
    assert "time.time" not in src
    assert "random" not in src
    assert "import datetime" not in src
    assert "import time" not in src
    assert "import random" not in src
    assert "from datetime" not in src
    assert "date.today" not in src


# ── operator mapping ──────────────────────────────────────────────────────────
def test_operator_literal_scalar():
    sel = step_to_sigma(_WIN1, _step_lit())["detection"]["selection"]
    assert sel["IntegrityLevel"] == "System"


def _step_lit():
    # synthesize a tiny Step-like via the real schema for a literal scalar
    from augur.scenarios.schema import Step
    return Step(step_id=1, name="lit",
                matching_criteria={"Node_Type": "Process", "IntegrityLevel": "System"})


def test_operator_equals_bool():
    from augur.scenarios.schema import Step
    st = Step(step_id=1, name="eq",
              matching_criteria={"Node_Type": "File", "IsSigned": {"equals": False}})
    sel = step_to_sigma(_WIN1, st)["detection"]["selection"]
    assert sel["Signed"] is False


def test_operator_in_is_list():
    sel = step_to_sigma(_WIN1, _step(_WIN1, 1))["detection"]["selection"]
    # ProcessName {in: [rundll32.exe]} → Image|endswith list (single-element list, NOT collapsed)
    assert sel["Image|endswith"] == ["\\rundll32.exe"]


def test_operator_regex():
    sel = step_to_sigma(_WIN1, _step(_WIN1, 1))["detection"]["selection"]
    assert sel["CommandLine|re"] == ".*comsvcs.*"


def test_operator_exists_true_and_false():
    from augur.scenarios.schema import Step
    st = Step(step_id=1, name="ex",
              matching_criteria={"Node_Type": "Process", "CommandLine": {"exists": True}})
    sel = step_to_sigma(_WIN1, st)["detection"]["selection"]
    assert sel["CommandLine|exists"] is True
    st2 = Step(step_id=1, name="ex2",
               matching_criteria={"Node_Type": "File", "Path": {"exists": False}})
    sel2 = step_to_sigma(_WIN1, st2)["detection"]["selection"]
    assert sel2["ImageLoaded|exists"] is False


def test_unknown_operator_raises():
    from augur.scenarios.schema import Step
    # schema forbids unknown-regex only; an unknown operator key is a plain dict the exporter must reject
    st = Step(step_id=1, name="bad",
              matching_criteria={"Node_Type": "Process", "CommandLine": {"startswith": "x"}})
    import pytest
    with pytest.raises(ValueError):
        step_to_sigma(_WIN1, st)


# ── field / logsource mapping ─────────────────────────────────────────────────
def test_field_process_name_to_image_endswith():
    sel = step_to_sigma(_WIN1, _step(_WIN1, 1))["detection"]["selection"]
    assert "Image|endswith" in sel and "ProcessName" not in sel


def test_logsource_windows_process_creation():
    ls = step_to_sigma(_WIN1, _step(_WIN1, 1))["logsource"]
    assert ls == {"product": "windows", "category": "process_creation"}


def test_logsource_file_step_is_image_load():
    from augur.scenarios.schema import Step
    st = Step(step_id=1, name="img",
              matching_criteria={"Node_Type": "File", "FileName": {"in": ["evil.dll"]}})
    rule = step_to_sigma(_WIN1, st)
    assert rule["logsource"]["category"] == "image_load"
    assert rule["detection"]["selection"]["ImageLoaded|endswith"] == ["\\evil.dll"]


def test_logsource_os_families_map_to_product():
    for os_family, product in (("windows", "windows"), ("linux", "linux"), ("macos", "macos")):
        st = _fake_scenario(os_family)
        ls = step_to_sigma(st, _step(st, 1))["logsource"]
        assert ls["product"] == product


def test_cloud_stub_maps_to_windows_with_comment():
    sc = _SCEN.get("SCEN-CLD-001")
    if sc is None:
        return
    rule = step_to_sigma(sc, _step(sc, 1))
    assert rule["logsource"]["product"] == "windows"
    # cloud-stub honesty comment carried in x-augur
    assert "cloud" in rule["x-augur"].get("note", "").lower()


def _fake_scenario(os_family):
    """Clone SCEN-WIN-001 with a different os_family via model_copy (read-only)."""
    sc = _WIN1.model_copy(deep=True)
    sc.scenario_metadata.os_family = os_family
    return sc


# ── deterministic id ──────────────────────────────────────────────────────────
def test_deterministic_id_stable_and_golden():
    a = step_to_sigma(_WIN1, _step(_WIN1, 1))["id"]
    b = step_to_sigma(_WIN1, _step(_WIN1, 1))["id"]
    assert a == b
    assert a == str(uuid5(SIGMA_NAMESPACE, "SCEN-WIN-001:1"))


def test_id_stable_under_scenario_reorder():
    rules1 = scenario_to_sigma(_WIN1)
    rules2 = scenario_to_sigma(_WIN1.model_copy(deep=True))
    assert [r["id"] for r in rules1] == [r["id"] for r in rules2]


# ── MITRE tags / refs / level ─────────────────────────────────────────────────
def test_mitre_tags_and_refs():
    rule = step_to_sigma(_WIN1, _step(_WIN1, 1))
    assert "attack.credential-access" in rule["tags"]
    assert "attack.t1003.001" in rule["tags"]
    assert "https://attack.mitre.org/techniques/T1003/001/" in rule["references"]
    assert rule["tags"] == sorted(rule["tags"])  # sorted + de-duped


def test_level_from_severity():
    assert step_to_sigma(_WIN1, _step(_WIN1, 1))["level"] == "critical"


# ── behavior / degraded step ──────────────────────────────────────────────────
def test_behavior_step_degraded_process_access():
    rule = step_to_sigma(_WIN1, _step(_WIN1, 3))  # TargetProcess/GrantedAccess
    assert rule["logsource"]["category"] == "process_access"
    sel = rule["detection"]["selection"]
    assert sel["TargetImage|endswith"] == "\\lsass.exe"
    assert sel["GrantedAccess"] == "0x1410"
    # behavior caveat present, no fabricated clean field
    assert any("EDR" in fp for fp in rule["falsepositives"])


# ── valid YAML round-trip ─────────────────────────────────────────────────────
def test_to_yaml_round_trips_required_keys():
    text = to_yaml(step_to_sigma(_WIN1, _step(_WIN1, 1)))
    assert text.startswith("# Augur Sigma export")
    doc = yaml.safe_load(text)
    for k in ("title", "id", "status", "description", "logsource", "detection", "level"):
        assert k in doc
    assert doc["detection"]["condition"] == "selection"


def test_pack_to_yaml_multi_doc():
    text = pack_to_yaml([_WIN1])
    docs = list(yaml.safe_load_all(text))
    assert len(docs) == _WIN1.step_count == 3


# ── golden whole-scenario shape ───────────────────────────────────────────────
def test_golden_scen_win_001_step1():
    rules = scenario_to_sigma(_WIN1)
    assert len(rules) == 3
    r = rules[0]
    assert r["title"] == "Augur SCEN-WIN-001 step1 Rundll32_Launch"
    assert r["id"] == str(uuid5(SIGMA_NAMESPACE, "SCEN-WIN-001:1"))
    assert r["status"] == "experimental"
    assert r["date"] == SIGMA_EXPORT_DATE
    assert r["author"] == "Augur (deterministic export)"
    assert r["logsource"] == {"product": "windows", "category": "process_creation"}
    assert r["detection"]["selection"] == {
        "Image|endswith": ["\\rundll32.exe"],
        "CommandLine|re": ".*comsvcs.*",
    }
    assert r["detection"]["condition"] == "selection"
    assert r["level"] == "critical"
    assert r["x-augur"] == {"scenario_id": "SCEN-WIN-001", "step_id": 1, "total_steps": 3}
    # honesty caveat is in the description + a falsepositives entry
    assert HONESTY_NOTE.split(".")[0] in r["description"]
    assert any("full Augur scenario chain" in fp for fp in r["falsepositives"])


def test_honesty_note_is_nonempty_constant():
    assert isinstance(HONESTY_NOTE, str) and len(HONESTY_NOTE) > 80


# ── Fix 1: unmappable step emits non-firing rule (SCEN-LNX-004 step 3) ────────
def test_unmappable_step_emits_nonfiring_rule():
    """SCEN-LNX-004 step 3 has only Behavior_Markers (no Sigma field) — must NEVER fire."""
    sc = _SCEN["SCEN-LNX-004"]
    st = _step(sc, 3)
    # confirm this step is indeed the behavior-only one
    assert list(st.matching_criteria.keys()) == ["Node_Type", "Behavior_Markers"]

    rule = step_to_sigma(sc, st)

    # must be unsupported, not experimental
    assert rule["status"] == "unsupported", f"expected unsupported, got {rule['status']}"

    # condition must be the never-true form
    cond = rule["detection"]["condition"]
    assert cond == "selection and not selection", f"expected never-true condition, got {cond!r}"

    # selection must NOT be empty (an empty dict fires on all events)
    sel = rule["detection"]["selection"]
    assert sel, "selection must not be empty (empty dict would match everything)"
    assert sel == _NONFIRING_SELECTION

    # honesty caveat text must be present in description and falsepositives
    assert UNMAPPABLE_NOTE in rule["description"]
    assert any(UNMAPPABLE_NOTE in fp for fp in rule["falsepositives"])

    # x-augur must carry unmapped: True flag
    assert rule["x-augur"].get("unmapped") is True

    # the emitted YAML must be parseable and still non-firing
    text = to_yaml(rule)
    doc = yaml.safe_load(text)
    assert doc["status"] == "unsupported"
    assert doc["detection"]["condition"] == "selection and not selection"
    assert doc["detection"]["selection"]  # non-empty


# ── Fix 1 sweep: no shipped scenario emits an empty-firing selection ─────────
def test_no_scenario_emits_empty_firing_selection():
    """Sweep all 40 scenarios — assert no rule has selection={} with condition='selection'."""
    all_scenarios = default_scenarios()
    violations = []
    for sc in all_scenarios:
        for rule in scenario_to_sigma(sc):
            det = rule["detection"]
            if det.get("selection") == {} and det.get("condition") == "selection":
                violations.append(
                    f"{rule.get('title', '?')}: selection={{}} condition=selection"
                )
    assert not violations, "Always-true firing rules found:\n" + "\n".join(violations)


# ── Fix 3: OS-conditional path separator in endswith literals ─────────────────
def test_linux_endswith_uses_posix_separator():
    """Linux scenario ProcessName endswith literals must start with '/', not '\\'."""
    sc = _SCEN["SCEN-LNX-001"]
    # step 1: ProcessName {in: ["bash", "sh"]} → Image|endswith ['/bash', '/sh']
    rule = step_to_sigma(sc, _step(sc, 1))
    sel = rule["detection"]["selection"]
    vals = sel["Image|endswith"]
    assert isinstance(vals, list), f"expected list, got {vals!r}"
    assert all(v.startswith("/") for v in vals), (
        f"Linux endswith literals must start with '/': {vals}"
    )
    assert not any(v.startswith("\\") for v in vals), (
        f"Linux endswith literals must NOT start with '\\': {vals}"
    )
    # spot-check expected values
    assert "/bash" in vals and "/sh" in vals


def test_macos_endswith_uses_posix_separator():
    """macOS scenario ProcessName endswith literals must start with '/', not '\\'."""
    sc = _SCEN["SCEN-MAC-001"]
    # step 1: ProcessName {in: ["osascript"]} → Image|endswith ['/osascript']
    rule = step_to_sigma(sc, _step(sc, 1))
    sel = rule["detection"]["selection"]
    vals = sel["Image|endswith"]
    assert isinstance(vals, list)
    assert all(v.startswith("/") for v in vals), (
        f"macOS endswith literals must start with '/': {vals}"
    )
    assert "/osascript" in vals


def test_windows_endswith_uses_backslash():
    """Windows scenario endswith literals must use backslash (golden regression guard)."""
    # SCEN-WIN-001 step 1: ProcessName {in: ["rundll32.exe"]}
    sel = step_to_sigma(_WIN1, _step(_WIN1, 1))["detection"]["selection"]
    assert sel["Image|endswith"] == ["\\rundll32.exe"], (
        f"Windows endswith must use backslash: {sel['Image|endswith']}"
    )


def test_cloud_stub_endswith_uses_posix_separator():
    """Cloud-stub (SCEN-CLD-001, os_family=linux) endswith literals must use POSIX '/'."""
    sc = _SCEN.get("SCEN-CLD-001")
    if sc is None:
        return
    # step 1: ProcessName {in: ["cat", "grep"]} → Image|endswith ['/cat', '/grep']
    rule = step_to_sigma(sc, _step(sc, 1))
    sel = rule["detection"]["selection"]
    vals = sel.get("Image|endswith", [])
    assert vals, f"expected Image|endswith in cloud-stub step 1 selection: {sel}"
    assert all(v.startswith("/") for v in vals), (
        f"Cloud-stub (linux os_family) endswith literals must use '/': {vals}"
    )
    assert "/cat" in vals and "/grep" in vals


def test_endswith_separator_sweep_all_scenarios():
    """Every endswith literal in every scenario rule must use the correct separator for its os_family."""
    all_scenarios = default_scenarios()
    violations = []
    for sc in all_scenarios:
        expected_sep = "/" if sc.os_family in ("linux", "macos") else "\\"
        wrong_sep = "\\" if expected_sep == "/" else "/"
        for rule in scenario_to_sigma(sc):
            sel = rule["detection"]["selection"]
            for key, val in sel.items():
                if "|endswith" not in key:
                    continue
                items = val if isinstance(val, list) else [val]
                for item in items:
                    if not isinstance(item, str):
                        continue
                    if item.startswith(wrong_sep):
                        violations.append(
                            f"{sc.scenario_id} (os_family={sc.os_family}) rule "
                            f"'{rule.get('title','?')}' key={key}: {item!r} uses wrong separator"
                        )
    assert not violations, "Separator violations found:\n" + "\n".join(violations)


# ── Fix 2: inlined maps match criteria.py (drift guard) ──────────────────────
def test_inlined_maps_match_criteria():
    """sigma.py inlines BEHAVIOR_KEYS/_PROCESS_KEY_MAP/_FILE_KEY_MAP from criteria.py.
    This test imports from augur.engine.criteria (inside the test only, never the module)
    and asserts the copies are identical — so a criteria.py change breaks this test.
    """
    from augur.engine.criteria import (
        BEHAVIOR_KEYS as C_BEHAVIOR_KEYS,
        PROCESS_KEY_MAP as C_PROCESS_KEY_MAP,
        FILE_KEY_MAP as C_FILE_KEY_MAP,
    )
    from augur.api.sigma import (
        BEHAVIOR_KEYS as S_BEHAVIOR_KEYS,
        _PROCESS_KEY_MAP as S_PROCESS_KEY_MAP,
        _FILE_KEY_MAP as S_FILE_KEY_MAP,
    )

    # BEHAVIOR_KEYS: compare as sets (frozenset vs set is fine)
    assert set(S_BEHAVIOR_KEYS) == set(C_BEHAVIOR_KEYS), (
        f"BEHAVIOR_KEYS drift: sigma={S_BEHAVIOR_KEYS} criteria={C_BEHAVIOR_KEYS}"
    )

    # key maps: exact dict equality
    assert S_PROCESS_KEY_MAP == C_PROCESS_KEY_MAP, (
        f"_PROCESS_KEY_MAP drift:\n sigma={S_PROCESS_KEY_MAP}\n criteria={C_PROCESS_KEY_MAP}"
    )
    assert S_FILE_KEY_MAP == C_FILE_KEY_MAP, (
        f"_FILE_KEY_MAP drift:\n sigma={S_FILE_KEY_MAP}\n criteria={C_FILE_KEY_MAP}"
    )

    # Sigma field-map key universe must cover all criteria key-map keys.
    # This catches a newly-added criteria key that is silently dropped from export.
    from augur.api.sigma import _PROCESS_FIELD, _FILE_FIELD
    missing_process = set(C_PROCESS_KEY_MAP) - set(_PROCESS_FIELD)
    missing_file = set(C_FILE_KEY_MAP) - set(_FILE_FIELD)
    assert not missing_process, (
        f"criteria PROCESS_KEY_MAP keys not in sigma _PROCESS_FIELD: {missing_process}"
    )
    assert not missing_file, (
        f"criteria FILE_KEY_MAP keys not in sigma _FILE_FIELD: {missing_file}"
    )
