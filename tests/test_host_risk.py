"""TDD: compute_host_risk pure helper (deterministic, no engine/scoring import)."""
from augur.api.host_risk import compute_host_risk, CRIT_WEIGHT, SEV_WEIGHT
from augur.enums import Criticality, Zone


def test_weight_tables_are_explicit_and_keyed_correctly():
    # AUDIT #1 — SEV_WEIGHT is an explicit STRING-keyed dict, NOT SEVERITY_RANK.
    assert SEV_WEIGHT == {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    # AUDIT #2 — CRIT_WEIGHT is keyed by the Criticality ENUM; UNKNOWN floored to 1.
    assert CRIT_WEIGHT == {
        Criticality.CRITICAL: 4, Criticality.HIGH: 3, Criticality.MEDIUM: 2,
        Criticality.LOW: 1, Criticality.UNKNOWN: 1,
    }


def test_empty_detections_returns_empty_when_no_topology():
    class _T:
        assets = []

        def enrich(self, h):
            return Zone.Unknown, Criticality.UNKNOWN

    assert compute_host_risk([], _T()) == []


# ---------------------------------------------------------------------------
# A2 — host set + union with case-normalization (AUDIT #4, #5)
# ---------------------------------------------------------------------------


class FakeAsset:
    def __init__(self, hostname, zone, criticality):
        self.hostname, self.zone, self.criticality = hostname, zone, criticality


class FakeTopology:
    """Mirrors Topology: enrich() matches case-insensitively and returns (Zone, Criticality)."""

    def __init__(self, assets):
        self.assets = assets

    def enrich(self, hostname):
        key = hostname.lower()
        for a in self.assets:
            if a.hostname.lower() == key:
                return a.zone, a.criticality
        return Zone.Unknown, Criticality.UNKNOWN


def _topo():
    return FakeTopology([
        FakeAsset("Web_Server_01", Zone.DMZ, Criticality.HIGH),
        FakeAsset("DC_01", Zone.Active_Directory, Criticality.CRITICAL),
        FakeAsset("HR_User_PC", Zone.User_Endpoint, Criticality.MEDIUM),
    ])


def _det(sid, name, severity, proximity, hosts):
    return {"scenario_id": sid, "name": name, "severity": severity,
            "proximity": proximity, "affected_hosts": hosts}


def test_all_topology_hosts_present_even_when_clean():
    rows = compute_host_risk([], _topo())
    assert {r["hostname"] for r in rows} == {"Web_Server_01", "DC_01", "HR_User_PC"}
    # AUDIT #5 — empty-host uniform defaults.
    for r in rows:
        assert r["score"] == 0.0 and r["band"] == "CLEAR"
        assert r["detection_count"] == 0 and r["max_proximity"] == 0
        assert r["top_severity"] is None and r["top_scenarios"] == []


def test_off_topology_host_included_as_unknown_and_case_normalized():
    # detection hostname differs in CASE from no topology asset -> off-topology, UNKNOWN, displayed raw.
    rows = compute_host_risk([_det("S1", "n", "HIGH", 1.0, ["laptop-x"])], _topo())
    row = next(r for r in rows if r["hostname"].lower() == "laptop-x")
    assert row["criticality"] == "UNKNOWN" and row["zone"] == "Unknown"


def test_topology_host_and_detection_hostname_do_not_split():
    # AUDIT #4 — detection carries 'web_server_01' (lowercased); must merge into the canonical row.
    rows = compute_host_risk([_det("S1", "n", "HIGH", 1.0, ["web_server_01"])], _topo())
    web = [r for r in rows if r["hostname"].lower() == "web_server_01"]
    assert len(web) == 1                       # not split into two rows
    assert web[0]["hostname"] == "Web_Server_01"   # canonical (topology) display name
    assert web[0]["detection_count"] == 1


# ---------------------------------------------------------------------------
# A3 — formula, sum-not-max, bands, top_scenarios cap/order, determinism
# ---------------------------------------------------------------------------


def test_score_is_sum_not_max_with_weights_and_proximity():
    # DC_01 = CRITICAL (CRIT_WEIGHT 4). Two detections both hit it.
    dets = [
        _det("S1", "alpha", "HIGH", 1.0, ["DC_01"]),     # 1.0 * 4 * 3 = 12
        _det("S2", "beta", "LOW", 0.5, ["DC_01"]),       # 0.5 * 4 * 1 = 2
    ]
    rows = compute_host_risk(dets, _topo())
    dc = next(r for r in rows if r["hostname"] == "DC_01")
    assert dc["score"] == 14.0                            # SUM, not max(12)
    assert dc["band"] == "CRITICAL"                       # >= 8
    assert dc["detection_count"] == 2
    assert dc["max_proximity"] == 1.0
    assert dc["top_severity"] == "HIGH"


def test_band_thresholds():
    # Web_Server_01 = HIGH (weight 3). Tune proximity/severity to land each band.
    def score_of(dets):
        rows = compute_host_risk(dets, _topo())
        return next(r for r in rows if r["hostname"] == "Web_Server_01")
    # CLEAR
    assert score_of([])["band"] == "CLEAR"
    # LOW band: 0<score<1.5  -> LOW sev (1) * HIGH crit (3) * prox 0.3333 = 1.0
    assert score_of([_det("S", "n", "LOW", 0.3333, ["Web_Server_01"])])["band"] == "LOW"
    # WATCH: >=1.5 -> MEDIUM(2)*3*0.3333 = 2.0
    assert score_of([_det("S", "n", "MEDIUM", 0.3333, ["Web_Server_01"])])["band"] == "WATCH"
    # HIGH: >=4 -> HIGH(3)*3*0.5 = 4.5
    assert score_of([_det("S", "n", "HIGH", 0.5, ["Web_Server_01"])])["band"] == "HIGH"
    # CRITICAL: >=8 -> CRITICAL(4)*3*1.0 = 12
    assert score_of([_det("S", "n", "CRITICAL", 1.0, ["Web_Server_01"])])["band"] == "CRITICAL"


def test_top_scenarios_capped_at_3_and_ordered():
    dets = [_det(f"S{i}", f"n{i}", "HIGH", p, ["DC_01"])
            for i, p in enumerate([0.2, 0.9, 0.5, 0.7, 0.3])]
    rows = compute_host_risk(dets, _topo())
    dc = next(r for r in rows if r["hostname"] == "DC_01")
    assert len(dc["top_scenarios"]) == 3                 # capped
    proxes = [s["proximity"] for s in dc["top_scenarios"]]
    assert proxes == sorted(proxes, reverse=True)        # contribution(=prox here) desc


def test_top_scenarios_tie_break_by_scenario_id_asc():
    dets = [_det("S2", "b", "HIGH", 0.5, ["DC_01"]), _det("S1", "a", "HIGH", 0.5, ["DC_01"])]
    dc = next(r for r in compute_host_risk(dets, _topo()) if r["hostname"] == "DC_01")
    assert [s["scenario_id"] for s in dc["top_scenarios"]] == ["S1", "S2"]


def test_row_order_tie_break_score_then_hostname():
    # Two hosts with equal score must order by hostname asc.
    dets = [_det("S1", "n", "HIGH", 1.0, ["DC_01"]),         # crit*4*3 = 12
            _det("S2", "n", "CRITICAL", 1.0, ["Web_Server_01"])]  # high*3*4 = 12
    rows = [r for r in compute_host_risk(dets, _topo()) if r["score"] == 12.0]
    assert [r["hostname"] for r in rows] == ["DC_01", "Web_Server_01"]   # alpha asc


def test_clean_hosts_sort_to_bottom():
    dets = [_det("S1", "n", "HIGH", 1.0, ["DC_01"])]
    rows = compute_host_risk(dets, _topo())
    assert rows[0]["hostname"] == "DC_01"                 # scored host first
    assert all(r["band"] == "CLEAR" for r in rows[1:])    # clean hosts trail


def test_deterministic_across_two_calls():
    dets = [_det("S1", "n", "HIGH", 1.0, ["DC_01"]), _det("S2", "n", "LOW", 0.5, ["HR_User_PC"])]
    a = compute_host_risk(dets, _topo())
    b = compute_host_risk(dets, _topo())
    assert a == b


def test_no_scoring_or_matcher_import_in_helper():
    # Invariant guard: the read-only helper must not pull the scoring/matcher path.
    import augur.api.host_risk as m
    import inspect
    src = inspect.getsource(m)
    assert "engine.scoring" not in src and "engine.matcher" not in src
