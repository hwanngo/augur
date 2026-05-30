import pytest
from datetime import datetime, timezone
from augur.simulator.config import SimConfig
from augur.simulator.baseline import generate_baseline
from augur.simulator.profiles import default_profiles

BASE = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


def _cfg(**kw):
    base = dict(seed=1337, duration_seconds=600, rate_per_minute=12)
    base.update(kw)
    return SimConfig(**base)


def test_config_rejects_unknown_field():
    with pytest.raises(Exception):
        SimConfig(seed=1, duration_seconds=10, rate_per_minute=1, bogus=True)


def test_baseline_is_deterministic_for_a_seed():
    profs = default_profiles()
    a = generate_baseline(profs, _cfg(), BASE)
    b = generate_baseline(profs, _cfg(), BASE)
    assert a == b and len(a) > 0


def test_baseline_events_are_ordered_and_native():
    profs = default_profiles()
    events = generate_baseline(profs, _cfg(), BASE)
    ts = [datetime.fromisoformat(r["timestamp"]) for r in events]
    assert ts == sorted(ts)                       # chronological
    assert {r["source_type"] for r in events} <= {"windows_sysmon", "linux_auditd", "macos_esf"}


def test_different_seed_changes_stream():
    profs = default_profiles()
    assert generate_baseline(profs, _cfg(seed=1), BASE) != generate_baseline(profs, _cfg(seed=2), BASE)
