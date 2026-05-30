"""TDD: rarity.compute_rarity — pure, deterministic counting (no engine, no now(), no random)."""
import ast
from datetime import datetime, timezone
from pathlib import Path

import pytest

from augur.api.rarity import (
    compute_rarity, DIMENSIONS, HONESTY_NOTE,
    MAX_RESULTS, MAX_COUNT_CAP, MAX_HOSTS_PER_ROW, MAX_SAMPLES_PER_ROW,
)
from augur.normalize.model import NormalizedEvent
from augur.topology.network import Topology
from augur.enums import Zone, Criticality


# ── a tiny in-memory topology (avoids touching the real corpus) ──────────────
def _topo():
    return Topology(zones=[Zone.User_Endpoint, Zone.Internal_Server], assets=[
        {"hostname": "HOST-A", "zone": Zone.User_Endpoint, "criticality": Criticality.CRITICAL,
         "os": "windows", "ip": "10.0.0.1"},
        {"hostname": "HOST-B", "zone": Zone.Internal_Server, "criticality": Criticality.MEDIUM,
         "os": "linux", "ip": "10.0.0.2"},
    ])


def _ev(host, pname, parent=None, ts="2026-01-01T10:00:00+00:00", kind="process_create", cmd=None):
    return NormalizedEvent(
        timestamp=datetime.fromisoformat(ts), kind=kind, host=host, event_id="e",
        process_name=pname, parent_process_name=parent, command_line=cmd,
    )


# compute_rarity gets its events from feed.load_normalized (cached read+normalize).
# Bypass disk + the cache by patching that loader the module imported.
@pytest.fixture
def events(monkeypatch):
    bag = {"evs": []}
    monkeypatch.setattr("augur.api.rarity.load_normalized", lambda _paths: list(bag["evs"]))
    return bag


def test_process_dimension_counts_and_flags(events):
    events["evs"] = [
        _ev("HOST-A", "powershell.exe"),
        _ev("HOST-B", "powershell.exe"),
        _ev("HOST-A", "rundll32.exe"),               # unique + single_host
    ]
    out = compute_rarity("process", ["x.jsonl"], _topo(), max_count=5, limit=100)
    assert out["dimension"] == "process"
    rows = {r["value"]: r for r in out["rows"]}
    assert rows["rundll32.exe"]["occurrences"] == 1
    assert rows["rundll32.exe"]["unique"] is True
    assert rows["rundll32.exe"]["single_host"] is True
    assert rows["powershell.exe"]["occurrences"] == 2
    assert rows["powershell.exe"]["host_count"] == 2
    assert rows["powershell.exe"]["single_host"] is False


def test_casefold_buckets_merge(events):
    events["evs"] = [_ev("HOST-A", "PowerShell.EXE"), _ev("HOST-B", "powershell.exe")]
    out = compute_rarity("process", ["x"], _topo())
    rows = {r["value"]: r for r in out["rows"]}
    assert "powershell.exe" in rows
    assert rows["powershell.exe"]["occurrences"] == 2


def test_non_process_create_excluded(events):
    events["evs"] = [
        _ev("HOST-A", "evil.dll", kind="image_load"),
        _ev("HOST-A", "good.exe", kind="process_create"),
    ]
    out = compute_rarity("process", ["x"], _topo())
    assert [r["value"] for r in out["rows"]] == ["good.exe"]


def test_null_process_name_skipped(events):
    events["evs"] = [_ev("HOST-A", None), _ev("HOST-A", "a.exe")]
    out = compute_rarity("process", ["x"], _topo())
    assert [r["value"] for r in out["rows"]] == ["a.exe"]


def test_parent_child_dimension(events):
    events["evs"] = [
        _ev("HOST-A", "rundll32.exe", parent="winword.exe"),
        _ev("HOST-A", "rundll32.exe", parent="explorer.exe"),
        _ev("HOST-A", "rundll32.exe", parent="explorer.exe"),
    ]
    out = compute_rarity("parent_child", ["x"], _topo())
    rows = {r["value"]: r for r in out["rows"]}
    assert rows["winword.exe → rundll32.exe"]["occurrences"] == 1
    assert rows["explorer.exe → rundll32.exe"]["occurrences"] == 2


def test_parent_child_null_parent_skipped(events):
    events["evs"] = [_ev("HOST-A", "a.exe", parent=None), _ev("HOST-A", "b.exe", parent="p.exe")]
    out = compute_rarity("parent_child", ["x"], _topo())
    assert [r["value"] for r in out["rows"]] == ["p.exe → b.exe"]


def test_host_binary_spread_single_host_first(events):
    # one.exe on 1 host (3 times), two.exe on 2 hosts (2 times). host_binary ranks by host_count first.
    events["evs"] = [
        _ev("HOST-A", "one.exe"), _ev("HOST-A", "one.exe"), _ev("HOST-A", "one.exe"),
        _ev("HOST-A", "two.exe"), _ev("HOST-B", "two.exe"),
    ]
    out = compute_rarity("host_binary", ["x"], _topo(), max_count=5)
    values = [r["value"] for r in out["rows"]]
    assert values[0] == "one.exe"          # host_count=1 floats to top despite occurrences=3
    rows = {r["value"]: r for r in out["rows"]}
    assert rows["one.exe"]["host_count"] == 1 and rows["one.exe"]["single_host"] is True
    assert rows["two.exe"]["host_count"] == 2 and rows["two.exe"]["single_host"] is False


def test_first_last_seen(events):
    events["evs"] = [
        _ev("HOST-A", "a.exe", ts="2026-01-01T09:00:00+00:00"),
        _ev("HOST-A", "a.exe", ts="2026-01-01T11:00:00+00:00"),
    ]
    r = compute_rarity("process", ["x"], _topo())["rows"][0]
    assert r["first_seen"] == "2026-01-01T09:00:00+00:00"
    assert r["last_seen"] == "2026-01-01T11:00:00+00:00"


def test_host_enrichment_and_off_topology(events):
    events["evs"] = [_ev("HOST-A", "a.exe"), _ev("OFF-GRID", "a.exe")]
    r = compute_rarity("process", ["x"], _topo())["rows"][0]
    by_host = {h["hostname"]: h for h in r["hosts"]}
    assert by_host["HOST-A"]["criticality"] == "CRITICAL"
    assert by_host["HOST-A"]["zone"] == Zone.User_Endpoint.value
    assert by_host["OFF-GRID"]["criticality"] == "UNKNOWN"
    assert by_host["OFF-GRID"]["zone"] == Zone.Unknown.value


def test_samples_capped_and_ordered(events):
    events["evs"] = [
        _ev("HOST-B", "a.exe", ts="2026-01-01T10:00:%02d+00:00" % i, cmd="run %d" % i)
        for i in range(MAX_SAMPLES_PER_ROW + 3)
    ]
    r = compute_rarity("process", ["x"], _topo(), max_count=99)["rows"][0]
    assert len(r["samples"]) == MAX_SAMPLES_PER_ROW
    # deterministic order: ascending (timestamp, host)
    ts = [s["timestamp"] for s in r["samples"]]
    assert ts == sorted(ts)
    assert all({"host", "timestamp", "command"} <= set(s) for s in r["samples"])
    # honest truncation flag
    assert r["samples_truncated"] is True


def test_rarest_first_with_value_tiebreak(events):
    # three single-occurrence binaries -> value asc tiebreak deterministic
    events["evs"] = [_ev("HOST-A", n) for n in ("c.exe", "a.exe", "b.exe")]
    out = compute_rarity("process", ["x"], _topo())
    assert [r["value"] for r in out["rows"]] == ["a.exe", "b.exe", "c.exe"]


def test_max_count_threshold(events):
    events["evs"] = [_ev("HOST-A", "common.exe") for _ in range(10)] + [_ev("HOST-B", "rare.exe")]
    out = compute_rarity("process", ["x"], _topo(), max_count=5)
    assert [r["value"] for r in out["rows"]] == ["rare.exe"]
    assert out["summary"]["total_values"] == 2
    assert out["summary"]["rare_values"] == 1
    assert out["summary"]["returned"] == 1
    assert out["summary"]["truncated"] is False


def test_limit_cap_and_truncated(events):
    events["evs"] = [_ev("HOST-%d" % i, "u%02d.exe" % i) for i in range(10)]
    out = compute_rarity("process", ["x"], _topo(), max_count=5, limit=3)
    assert len(out["rows"]) == 3
    assert out["summary"]["rare_values"] == 10
    assert out["summary"]["returned"] == 3
    assert out["summary"]["truncated"] is True


def test_hosts_capped(events):
    events["evs"] = [_ev("H%03d" % i, "a.exe") for i in range(MAX_HOSTS_PER_ROW + 5)]
    r = compute_rarity("process", ["x"], _topo(), max_count=999)["rows"][0]
    assert len(r["hosts"]) == MAX_HOSTS_PER_ROW
    # honest truncation flag — true count preserved, display capped
    assert r["hosts_truncated"] is True
    assert r["host_count"] == MAX_HOSTS_PER_ROW + 5


def test_per_row_truncation_flags(events):
    """hosts_truncated / samples_truncated are True iff sub-lists were capped; counts stay honest."""
    # Row A: touches MAX_HOSTS_PER_ROW + 2 distinct hosts → hosts_truncated True
    # Row B: touches MAX_HOSTS_PER_ROW - 1 distinct hosts → hosts_truncated False
    # Row A: has MAX_SAMPLES_PER_ROW + 1 events on same host → samples_truncated True
    # Row B: has MAX_SAMPLES_PER_ROW events → samples_truncated False
    evs = []
    # Row A ("over.exe") — more hosts than cap AND more samples than cap.
    # Give it MAX_HOSTS_PER_ROW+2 distinct hosts (one event each) plus extra events
    # on HOVA000 so total sample count = MAX_HOSTS_PER_ROW+2 + (MAX_SAMPLES_PER_ROW+1)
    # which is well over MAX_SAMPLES_PER_ROW.
    for i in range(MAX_HOSTS_PER_ROW + 2):
        evs.append(_ev("HOVA%03d" % i, "over.exe"))
    for i in range(MAX_SAMPLES_PER_ROW + 1):
        evs.append(_ev("HOVA000", "over.exe"))
    # Row B ("under.exe") — strictly below both caps.
    # Use exactly MAX_SAMPLES_PER_ROW total events across MAX_HOSTS_PER_ROW-1 distinct
    # hosts (so host_count < cap too). Spread 1 event per host for the first few hosts.
    under_host_count = min(MAX_HOSTS_PER_ROW - 1, MAX_SAMPLES_PER_ROW)
    for i in range(under_host_count):
        evs.append(_ev("HOVB%03d" % i, "under.exe"))
    events["evs"] = evs
    out = compute_rarity("process", ["x"], _topo(), max_count=9999, limit=100)
    rows = {r["value"]: r for r in out["rows"]}

    over = rows["over.exe"]
    assert over["hosts_truncated"] is True
    assert len(over["hosts"]) == MAX_HOSTS_PER_ROW      # display capped
    assert over["host_count"] == MAX_HOSTS_PER_ROW + 2  # true count intact
    assert over["samples_truncated"] is True
    assert len(over["samples"]) == MAX_SAMPLES_PER_ROW  # display capped

    under = rows["under.exe"]
    assert under["hosts_truncated"] is False
    assert under["host_count"] == under_host_count
    assert len(under["hosts"]) == under_host_count
    assert under["samples_truncated"] is False
    assert len(under["samples"]) == under_host_count  # one event per host


def test_unknown_dimension_raises(events):
    with pytest.raises(ValueError):
        compute_rarity("not_a_dim", ["x"], _topo())


def test_honesty_note_present(events):
    events["evs"] = [_ev("HOST-A", "a.exe")]
    out = compute_rarity("process", ["x"], _topo())
    assert out["summary"]["honesty_note"] == HONESTY_NOTE
    assert "LEAD" in HONESTY_NOTE or "lead" in HONESTY_NOTE.lower()


def test_determinism_byte_identical(events):
    events["evs"] = [_ev("HOST-A", "a.exe"), _ev("HOST-B", "a.exe"), _ev("HOST-A", "b.exe")]
    a = compute_rarity("parent_child", ["x"], _topo())
    events["evs"] = [_ev("HOST-A", "a.exe"), _ev("HOST-B", "a.exe"), _ev("HOST-A", "b.exe")]
    b = compute_rarity("parent_child", ["x"], _topo())
    assert a == b


def test_cross_os_buckets_by_name(events):
    events["evs"] = [
        _ev("HOST-A", "python3"),           # would come from windows-ish path; name only matters
        _ev("HOST-B", "python3"),           # linux
    ]
    out = compute_rarity("process", ["x"], _topo())
    assert out["rows"][0]["value"] == "python3"
    assert out["rows"][0]["occurrences"] == 2


def test_purity_no_engine_now_random():
    src = Path("src/augur/api/rarity.py").read_text()
    tree = ast.parse(src)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert not any(m.startswith("augur.engine") for m in imported), "rarity must not import the engine"
    assert "random" not in imported
    assert "datetime.now" not in src and ".now(" not in src and "utcnow" not in src
