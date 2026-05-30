"""TDD: build_navigator_layer pure helper — deterministic, no engine import."""
from augur.api.navigator import build_navigator_layer, _TACTIC_SHORTNAMES


class FakeMapping:
    def __init__(self, tactic, technique):
        self.tactic, self.technique = tactic, technique


class FakeMeta:
    def __init__(self, mappings):
        self.mitre_mappings = mappings


class FakeScenario:
    """Mirrors Scenario: .scenario_id property + .scenario_metadata.mitre_mappings."""
    def __init__(self, scenario_id, mappings):
        self._id = scenario_id
        self.scenario_metadata = FakeMeta([FakeMapping(t, tech) for t, tech in mappings])

    @property
    def scenario_id(self):
        return self._id


def _by_id(layer):
    return {(e["techniqueID"], e["tactic"]): e for e in layer["techniques"]}


# --- shortname map -----------------------------------------------------------

def test_shortname_map_has_all_14_canonical_tactics():
    from augur.metrics.coverage import TACTIC_NAMES
    assert set(_TACTIC_SHORTNAMES) == set(TACTIC_NAMES)
    assert _TACTIC_SHORTNAMES["TA0001"] == "initial-access"
    assert _TACTIC_SHORTNAMES["TA0011"] == "command-and-control"


# --- coverage layer ----------------------------------------------------------

def test_coverage_every_mapped_technique_present_score_100_with_shortname():
    scs = [FakeScenario("SCEN-WIN-001", [("TA0001", "T1566")])]
    layer = build_navigator_layer(scs, layer_type="coverage")
    e = _by_id(layer)[("T1566", "initial-access")]
    assert e == {"techniqueID": "T1566", "tactic": "initial-access",
                 "score": 100, "comment": "SCEN-WIN-001", "enabled": True}


def test_coverage_subtechnique_emitted_as_is():
    scs = [FakeScenario("SCEN-WIN-002", [("TA0003", "T1547.001")])]
    layer = build_navigator_layer(scs, layer_type="coverage")
    assert ("T1547.001", "persistence") in _by_id(layer)


def test_coverage_dedup_same_pair_joins_comments_keeps_score_100():
    scs = [FakeScenario("SCEN-A", [("TA0001", "T1566")]),
           FakeScenario("SCEN-B", [("TA0001", "T1566")])]
    e = _by_id(build_navigator_layer(scs, layer_type="coverage"))[("T1566", "initial-access")]
    assert e["score"] == 100
    assert e["comment"] == "SCEN-A, SCEN-B"


def test_coverage_same_technique_distinct_tactics_are_distinct_entries():
    scs = [FakeScenario("SCEN-A", [("TA0001", "T1059"), ("TA0002", "T1059")])]
    keys = _by_id(build_navigator_layer(scs, layer_type="coverage"))
    assert ("T1059", "initial-access") in keys and ("T1059", "execution") in keys


def test_coverage_tactic_not_in_shortname_map_skipped_defensively():
    scs = [FakeScenario("SCEN-X", [("TA9999", "T1566")])]
    assert build_navigator_layer(scs, layer_type="coverage")["techniques"] == []


def test_techniques_sorted_by_tactic_then_id_deterministic():
    scs = [FakeScenario("SCEN-A", [("TA0002", "T1059"), ("TA0001", "T1566"), ("TA0001", "T1078")])]
    techs = build_navigator_layer(scs, layer_type="coverage")["techniques"]
    pairs = [(e["tactic"], e["techniqueID"]) for e in techs]
    assert pairs == sorted(pairs)
    assert build_navigator_layer(scs, layer_type="coverage") == build_navigator_layer(scs, layer_type="coverage")


# --- detections layer --------------------------------------------------------

def _det(scenario_id, proximity):
    return {"scenario_id": scenario_id, "proximity": proximity}


def test_detections_only_fired_techniques_score_round_maxprox_x100():
    scs = [FakeScenario("SCEN-A", [("TA0001", "T1566")])]
    layer = build_navigator_layer(scs, layer_type="detections", detections=[_det("SCEN-A", 0.5)])
    e = _by_id(layer)[("T1566", "initial-access")]
    assert e["score"] == 50  # round(0.5 * 100)


def test_detections_two_detections_same_technique_take_max():
    scs = [FakeScenario("SCEN-A", [("TA0001", "T1566")])]
    dets = [_det("SCEN-A", 0.4), _det("SCEN-A", 0.9)]
    e = _by_id(build_navigator_layer(scs, layer_type="detections", detections=dets))[("T1566", "initial-access")]
    assert e["score"] == 90


def test_detections_empty_yields_no_techniques():
    scs = [FakeScenario("SCEN-A", [("TA0001", "T1566")])]
    assert build_navigator_layer(scs, layer_type="detections", detections=[])["techniques"] == []


def test_detections_unmatched_scenario_id_skipped_defensively():  # [AUDIT #3]
    scs = [FakeScenario("SCEN-A", [("TA0001", "T1566")])]
    dets = [_det("SCEN-GHOST", 0.9)]
    assert build_navigator_layer(scs, layer_type="detections", detections=dets)["techniques"] == []


def test_detections_legend_and_gradient_match_spec():
    scs = [FakeScenario("SCEN-A", [("TA0001", "T1566")])]
    layer = build_navigator_layer(scs, layer_type="detections", detections=[_det("SCEN-A", 1.0)])
    assert layer["legendItems"][0]["label"].startswith("Low proximity")
    assert layer["gradient"] == {"colors": ["#e8eaf6", "#3949ab"], "minValue": 0, "maxValue": 100}


# --- schema guard [AUDIT #5] -------------------------------------------------

def test_emitted_layer_has_valid_navigator_v45_keys():  # [AUDIT #5]
    scs = [FakeScenario("SCEN-A", [("TA0001", "T1566")])]
    layer = build_navigator_layer(scs, layer_type="coverage")
    assert set(layer) >= {
        "name", "versions", "domain", "description",
        "techniques", "gradient", "legendItems", "sorting", "hideDisabled",
    }
    assert layer["versions"] == {"attack": "15", "navigator": "4.9.0", "layer": "4.5"}
    assert layer["domain"] == "enterprise-attack"
    for e in layer["techniques"]:
        assert set(e) == {"techniqueID", "tactic", "score", "comment", "enabled"}
        assert e["enabled"] is True and 0 <= e["score"] <= 100


# --- no-engine-import guard --------------------------------------------------

def test_no_engine_import_in_navigator_module():
    import augur.api.navigator as m
    import inspect
    src = inspect.getsource(m)
    assert "augur.engine" not in src and "from augur.engine" not in src
    assert "import engine" not in src
