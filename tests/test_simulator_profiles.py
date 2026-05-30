from augur.simulator.profiles import MachineProfile, BENIGN_CATALOG, default_profiles


def test_benign_catalog_has_three_os():
    assert {"windows", "linux", "macos"} <= set(BENIGN_CATALOG)
    for procs in BENIGN_CATALOG.values():
        assert len(procs) >= 5
        for p in procs:
            assert "name" in p and "path" in p and "parent" in p


def test_default_profiles_cover_each_os():
    profs = default_profiles()
    assert {p.os_family for p in profs} == {"windows", "linux", "macos"}
    for p in profs:
        assert p.host and p.users and p.os_family in BENIGN_CATALOG
