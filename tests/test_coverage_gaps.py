"""TDD: coverage_gap_matrix pure helper — deterministic, no engine import."""
from augur.metrics.coverage import coverage_gap_matrix, TACTIC_NAMES


class FakeMapping:
    def __init__(self, tactic, technique="T0000"):
        self.tactic, self.technique = tactic, technique


class FakeMeta:
    def __init__(self, mappings):
        self.mitre_mappings = mappings


class FakeScenario:
    """Mirrors Scenario: .os_family property + .scenario_metadata.mitre_mappings."""
    def __init__(self, os_family, tactics):
        self.os_family = os_family
        self.scenario_metadata = FakeMeta([FakeMapping(t) for t in tactics])


class FakeAsset:
    def __init__(self, os):
        self.os = os


class FakeTopology:
    def __init__(self, oses):
        self.assets = [FakeAsset(o) for o in oses]


def _topo_all():
    return FakeTopology(["Windows 11", "Linux", "macOS 14", "Cloud", "SaaS"])


# --- Task A1: columns from topology, clamped, cloud excluded -----------------

def test_columns_are_present_families_intersect_known_cloud_excluded():
    m = coverage_gap_matrix([], _topo_all())
    # Cloud/SaaS assets present but never create a column.
    assert m["os_families"] == ["windows", "linux", "macos"]


def test_single_family_topology_yields_one_column():
    m = coverage_gap_matrix([], FakeTopology(["Windows Server 2019"]))
    assert m["os_families"] == ["windows"]


def test_unknown_os_string_is_ignored():
    m = coverage_gap_matrix([], FakeTopology(["Solaris", "Windows 11"]))
    assert m["os_families"] == ["windows"]


# --- Task A3: cells, counts, gaps, multi-tactic, ignore cloud-stub ----------

def test_only_windows_scenario_leaves_linux_macos_gap():
    scs = [FakeScenario("windows", ["TA0001"])]
    m = coverage_gap_matrix(scs, _topo_all())
    assert m["cells"]["TA0001"]["windows"] == {"covered": True, "count": 1}
    assert m["cells"]["TA0001"]["linux"] == {"covered": False, "count": 0}
    assert m["cells"]["TA0001"]["macos"] == {"covered": False, "count": 0}


def test_count_accumulates_across_scenarios():
    scs = [FakeScenario("linux", ["TA0002"]), FakeScenario("Linux Server", ["TA0002"])]
    m = coverage_gap_matrix(scs, _topo_all())
    assert m["cells"]["TA0002"]["linux"] == {"covered": True, "count": 2}


def test_multi_tactic_scenario_counts_under_each_tactic():
    scs = [FakeScenario("windows", ["TA0003", "TA0004"])]
    m = coverage_gap_matrix(scs, _topo_all())
    assert m["cells"]["TA0003"]["windows"]["count"] == 1
    assert m["cells"]["TA0004"]["windows"]["count"] == 1


def test_cloud_stub_os_family_folds_into_windows_or_linux():
    # A cloud-stub scenario declares os_family "windows"/"linux" (endpoint telemetry).
    scs = [FakeScenario("windows", ["TA0040"]), FakeScenario("linux", ["TA0040"])]
    m = coverage_gap_matrix(scs, _topo_all())
    assert m["cells"]["TA0040"]["windows"]["count"] == 1
    assert m["cells"]["TA0040"]["linux"]["count"] == 1
    assert "cloud" not in m["cells"]["TA0040"]  # no cloud column at all


def test_unknown_scenario_os_family_ignored():
    scs = [FakeScenario("Solaris", ["TA0001"]), FakeScenario("windows", ["TA0001"])]
    m = coverage_gap_matrix(scs, _topo_all())
    assert m["cells"]["TA0001"]["windows"]["count"] == 1  # solaris one ignored


def test_fourteen_tactic_rows_in_canonical_order():
    m = coverage_gap_matrix([], _topo_all())
    assert [t["id"] for t in m["tactics"]] == list(TACTIC_NAMES.keys())
    assert len(m["cells"]) == 14


# --- Task A4: summary math, determinism, no-engine-import guard --------------

def test_summary_math_consistent():
    scs = [FakeScenario("windows", ["TA0001"]), FakeScenario("linux", ["TA0002"])]
    m = coverage_gap_matrix(scs, _topo_all())
    s = m["summary"]
    assert s["os_families"] == ["windows", "linux", "macos"]
    assert s["total_cells"] == 14 * 3
    assert s["covered_cells"] == 2  # exactly two covered cells
    assert s["gap_cells"] == s["total_cells"] - s["covered_cells"]
    assert s["coverage_pct"] == round(2 / 42, 4)


def test_empty_topology_yields_zero_grid():
    m = coverage_gap_matrix([], FakeTopology([]))
    assert m["os_families"] == []
    assert m["summary"]["total_cells"] == 0
    assert m["summary"]["coverage_pct"] == 0.0


def test_deterministic_across_two_calls():
    scs = [FakeScenario("windows", ["TA0001", "TA0005"]), FakeScenario("linux", ["TA0001"])]
    assert coverage_gap_matrix(scs, _topo_all()) == coverage_gap_matrix(scs, _topo_all())


def test_no_engine_import_in_coverage_module():
    # Invariant 2/6 guard: the read-only helper must not pull the engine path.
    import augur.metrics.coverage as m
    import inspect
    src = inspect.getsource(m)
    assert "augur.engine" not in src and "from augur.engine" not in src
    assert "import engine" not in src
