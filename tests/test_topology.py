from pathlib import Path
from augur.enums import Zone, Criticality
from augur.topology.network import load_topology, Topology

TOPO = Path("src/augur/topology/standard_topology.yaml")


def test_loads_standard_topology():
    topo = load_topology(TOPO)
    assert isinstance(topo, Topology)
    names = {a.hostname for a in topo.assets}
    assert {"Domain_Controller", "Web_Server_01", "HR_User_PC"} <= names


def test_lookup_is_case_insensitive():
    topo = load_topology(TOPO)
    a = topo.lookup("domain_controller")
    assert a is not None
    assert a.zone == Zone.Active_Directory
    assert a.criticality == Criticality.CRITICAL


def test_unknown_host_fallback():
    topo = load_topology(TOPO)
    assert topo.lookup("nope") is None
    zone, crit = topo.enrich("nope")
    assert zone == Zone.Unknown
    assert crit == Criticality.UNKNOWN
