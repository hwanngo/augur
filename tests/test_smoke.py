def test_package_imports():
    import augur
    assert augur.__version__ == "0.1.0"


def test_enums_values():
    from augur.enums import Severity, Criticality, Zone, LinkScope
    assert Severity.HIGH.value == "HIGH"
    assert Criticality.UNKNOWN.value == "UNKNOWN"
    assert Zone.Active_Directory.value == "Active_Directory"
    assert Zone.Unknown.value == "Unknown"
    assert LinkScope.same_host.value == "same_host"
