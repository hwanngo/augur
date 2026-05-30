"""TDD: Crown-Jewel Technique Paths pure builder (infra-free, deterministic, read-only)."""
from augur.enums import Zone, Criticality
from augur.api.attack_path import build_attack_paths, HONESTY_NOTE


class _Asset:
    def __init__(self, hostname, zone, crit):
        self.hostname = hostname; self.zone = zone; self.criticality = crit


class _Topo:
    def __init__(self, assets): self.assets = assets
    def lookup(self, h):
        return next((a for a in self.assets if a.hostname.lower() == h.lower()), None)
    def enrich(self, h):
        a = self.lookup(h)
        return (a.zone, a.criticality) if a else (Zone.Unknown, Criticality.UNKNOWN)


class _Mitre:
    def __init__(self, tactic): self.tactic = tactic
class _Meta:
    def __init__(self, tactic): self.mitre_mappings = [_Mitre(tactic)]
class _Spatial:
    def __init__(self, zones): self.applicable_zones = zones
class _Sev:
    def __init__(self, v): self.value = v
class _Scen:
    def __init__(self, sid, zones, tactic, steps, sev):
        self.scenario_id = sid; self.name = sid + "-name"
        self.spatial_constraints = _Spatial(zones)
        self.scenario_metadata = _Meta(tactic)
        self._steps = steps; self.severity = _Sev(sev)
    @property
    def step_count(self): return self._steps


def _det(sid, prox, zones, hosts, matched, total, sev="HIGH"):
    return {"scenario_id": sid, "name": sid + "-name", "severity": sev, "proximity": prox,
            "affected_zones": zones, "affected_hosts": hosts,
            "matched_steps": [{} for _ in range(matched)],
            "missing_steps": [{} for _ in range(total - matched)]}


def _topo():
    return _Topo([
        _Asset("WEB01", Zone.DMZ, Criticality.HIGH),
        _Asset("APP01", Zone.Internal_Server, Criticality.HIGH),
        _Asset("DC01", Zone.Active_Directory, Criticality.CRITICAL),
    ])


def _scens():
    return [
        _Scen("S-DMZ", ["DMZ"], "TA0001", 3, "HIGH"),
        _Scen("S-USR", ["User_Endpoint"], "TA0002", 3, "MEDIUM"),
        _Scen("S-INT", ["Internal_Server"], "TA0008", 3, "HIGH"),
        _Scen("S-AD", ["Active_Directory"], "TA0006", 4, "CRITICAL"),
    ]


def test_path_to_critical_with_observed_and_hypothetical_stops():
    dets = [_det("S-DMZ", 0.66, ["DMZ"], ["WEB01"], 2, 3)]
    paths = build_attack_paths(dets, _topo(), _scens(), min_proximity=0.30)
    assert len(paths) == 1
    p = paths[0]
    assert p["entry"]["zone"] == "DMZ"
    assert p["target"] == {"hostname": "DC01", "zone": "Active_Directory", "criticality": "CRITICAL"}
    assert [s["zone"] for s in p["stops"]] == ["DMZ", "User_Endpoint", "Internal_Server", "Active_Directory"]
    assert p["stops"][0]["status"] == "observed" and p["stops"][0]["matched_steps"] == 2
    assert p["stops"][1]["status"] == "hypothetical"
    assert p["stops"][-1]["host"] == "DC01"
    assert p["realized_pct"] == round(2 / 13, 4)
    assert p["observed_stop_count"] == 1 and p["total_stop_count"] == 4
    assert p["max_severity"] == "HIGH"
    assert p["honesty_note"] == HONESTY_NOTE


def test_no_critical_target_yields_no_paths():
    topo = _Topo([_Asset("WEB01", Zone.DMZ, Criticality.HIGH)])
    assert build_attack_paths([], topo, _scens(), min_proximity=0.30) == []


def test_empty_detections_still_emits_hypothetical_path():
    paths = build_attack_paths([], _topo(), _scens(), min_proximity=0.30)
    assert len(paths) == 1
    assert all(s["status"] == "hypothetical" for s in paths[0]["stops"])
    assert paths[0]["realized_pct"] == 0.0


def test_min_proximity_floor_moves_stop_to_hypothetical():
    dets = [_det("S-DMZ", 0.20, ["DMZ"], ["WEB01"], 1, 3)]
    paths = build_attack_paths(dets, _topo(), _scens(), min_proximity=0.30)
    assert paths[0]["stops"][0]["status"] == "hypothetical"


def test_zone_with_no_applicable_scenario_is_no_coverage():
    scens = [_Scen("S-AD", ["Active_Directory"], "TA0006", 4, "CRITICAL")]
    paths = build_attack_paths([], _topo(), scens, min_proximity=0.30)
    dmz = paths[0]["stops"][0]
    assert dmz["scenario_id"] is None and dmz["scenario_name"] == "(no library coverage)"
    assert dmz["total_steps"] == 0


def test_entry_zone_after_target_yields_no_path():
    # entry_zone at/deeper than the target on the spine -> forward-only guard (eidx >= tidx) drops it
    paths = build_attack_paths([], _topo(), _scens(), min_proximity=0.30, entry_zone="Active_Directory")
    assert paths == []


def test_deterministic_ordering():
    dets = [_det("S-DMZ", 0.66, ["DMZ"], ["WEB01"], 2, 3)]
    a = build_attack_paths(dets, _topo(), _scens(), min_proximity=0.30)
    b = build_attack_paths(dets, _topo(), _scens(), min_proximity=0.30)
    assert a == b
