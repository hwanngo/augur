"""TDD: pure apply_allowlist core + the invariant gates (identity, determinism, no engine import,
no wall-clock). Mirrors how detectability/graph-equality guard the engine."""
import ast
import pathlib

from augur.graph.models import ProcessNode
from augur.tuning.apply import apply_allowlist, dedup_key, HONESTY_NOTE
from augur.tuning.store import AllowlistEntry

_TUNING_DIR = pathlib.Path(__file__).resolve().parents[1] / "src" / "augur" / "tuning"


def _det(scenario_id="SCEN-WIN-001", hosts=("WS-1",), zones=("DMZ",), proximity=1.0,
         steps=None, name="PtH", severity="CRITICAL"):
    return {"scenario_id": scenario_id, "name": name, "severity": severity, "proximity": proximity,
            "affected_hosts": list(hosts), "affected_zones": list(zones),
            "matched_steps": steps if steps is not None else [
                {"step_id": 1, "name": "s1", "element_id": "p1", "host": hosts[0], "timestamp": "2026-06-03T10:00:00+00:00"}]}


def _entry(**kw):
    base = dict(action="SUPPRESS", reason="known good", author="alice")
    base.update(kw)
    return AllowlistEntry(**base)


# ── Identity / no-op ────────────────────────────────────────────────────────
def test_empty_allowlist_is_identity():
    dets = [_det(), _det(scenario_id="SCEN-WIN-002")]
    res = apply_allowlist(dets, [])
    assert res.kept is dets                       # same list object
    assert res.suppressed == [] and res.downgraded == []
    assert res.band_overrides == {}
    assert res.ledger["suppressed_count"] == 0 and res.ledger["active_entry_count"] == 0
    assert res.honesty_note == HONESTY_NOTE


# ── SUPPRESS ────────────────────────────────────────────────────────────────
def test_suppress_removes_and_is_counted_not_dropped():
    dets = [_det(), _det(scenario_id="SCEN-WIN-002")]
    e = _entry(id="e1", scenario_id="SCEN-WIN-001")
    res = apply_allowlist(dets, [e])
    assert [d["scenario_id"] for d in res.kept] == ["SCEN-WIN-002"]   # suppressed one gone from kept
    assert len(res.suppressed) == 1                                    # but recorded
    rec = res.suppressed[0]
    assert rec["entry_id"] == "e1" and rec["reason"] == "known good" and rec["action"] == "SUPPRESS"
    assert res.ledger["suppressed_count"] == 1
    assert res.ledger["per_entry"][0]["hit_count"] == 1


def test_and_semantics_all_predicates_must_match():
    dets = [_det(hosts=("WS-1",))]
    # scenario matches but host does not -> no match -> kept
    e = _entry(id="e1", scenario_id="SCEN-WIN-001", host="OTHER-HOST")
    res = apply_allowlist(dets, [e])
    assert len(res.kept) == 1 and res.suppressed == []


def test_technique_predicate_uses_index():
    dets = [_det()]
    e = _entry(id="e1", technique="T1003.001")
    idx = {"SCEN-WIN-001": {"T1003.001"}}
    assert len(apply_allowlist(dets, [e], technique_index=idx).suppressed) == 1
    assert apply_allowlist(dets, [e], technique_index={"SCEN-WIN-001": {"T1059"}}).suppressed == []


def test_zone_predicate():
    assert len(apply_allowlist([_det(zones=("DMZ",))], [_entry(id="e1", zone="DMZ")]).suppressed) == 1
    assert apply_allowlist([_det(zones=("DMZ",))], [_entry(id="e1", zone="CORE")]).suppressed == []


def test_time_window_overlap():
    d = _det(steps=[{"step_id": 1, "name": "s", "element_id": "p1", "host": "WS-1",
                     "timestamp": "2026-06-03T02:00:00+00:00"}])
    inside = _entry(id="e1", ts_from="2026-06-03T01:00:00+00:00", ts_to="2026-06-03T03:00:00+00:00")
    outside = _entry(id="e2", ts_from="2026-06-03T05:00:00+00:00", ts_to="2026-06-03T06:00:00+00:00")
    assert len(apply_allowlist([d], [inside]).suppressed) == 1
    assert apply_allowlist([d], [outside]).suppressed == []


def test_time_predicate_no_timestamps_does_not_match():
    d = _det(steps=[{"step_id": 1, "name": "s", "element_id": "p1", "host": "WS-1", "timestamp": None}])
    e = _entry(id="e1", ts_from="2026-06-03T01:00:00+00:00")
    assert apply_allowlist([d], [e]).suppressed == []


# ── regex predicate (read-only backend enrichment) ──────────────────────────
class _FakeBackend:
    def __init__(self, nodes):
        self._nodes = nodes
    def get_node(self, nid):
        return self._nodes.get(nid)


def test_process_regex_predicate_with_backend():
    backend = _FakeBackend({"p1": ProcessNode(id="p1", name="rundll32.exe",
                                              path="C:/Windows/System32/rundll32.exe",
                                              command_line="rundll32.exe foo", parent_guid=None,
                                              parent_process_name="x", host="WS-1", timestamp=None)})
    d = _det()
    assert len(apply_allowlist([d], [_entry(id="e1", process_regex=r"rundll32")], backend=backend).suppressed) == 1
    assert apply_allowlist([d], [_entry(id="e1", process_regex=r"notepad")], backend=backend).suppressed == []
    # without a backend the regex predicate can never be substantiated -> no match
    assert apply_allowlist([d], [_entry(id="e1", process_regex=r"rundll32")], backend=None).suppressed == []


# ── DOWNGRADE ───────────────────────────────────────────────────────────────
def test_downgrade_lowers_band_without_mutating_proximity():
    d = _det(proximity=1.0)                      # natural band CONFIRMED
    e = _entry(id="e1", action="DOWNGRADE", downgrade_to="WATCH", scenario_id="SCEN-WIN-001")
    res = apply_allowlist([d], [e])
    assert len(res.kept) == 1
    assert res.kept[0]["band_override"] == "WATCH"
    assert res.kept[0]["proximity"] == 1.0       # proximity untouched
    assert d.get("band_override") is None         # original dict not mutated
    assert res.band_overrides[dedup_key(d)] == "WATCH"
    assert res.downgraded[0]["from_band"] == "CONFIRMED" and res.downgraded[0]["to_band"] == "WATCH"


def test_downgrade_is_noop_when_target_not_below_natural():
    d = _det(proximity=0.5)                       # natural band WATCH already
    e = _entry(id="e1", action="DOWNGRADE", downgrade_to="WATCH")
    res = apply_allowlist([d], [e])
    assert res.downgraded == [] and "band_override" not in res.kept[0]


def test_suppress_wins_over_downgrade():
    d = _det(proximity=1.0)
    sup = _entry(id="e1", action="SUPPRESS", scenario_id="SCEN-WIN-001")
    dn = _entry(id="e2", action="DOWNGRADE", downgrade_to="WATCH", scenario_id="SCEN-WIN-001")
    res = apply_allowlist([d], [dn, sup])
    assert res.suppressed and res.downgraded == [] and res.kept == []


# ── determinism ─────────────────────────────────────────────────────────────
def test_determinism_under_shuffled_entry_order():
    d = _det(proximity=1.0)
    a = _entry(id="aaa", action="DOWNGRADE", downgrade_to="HIGH", scenario_id="SCEN-WIN-001")
    b = _entry(id="bbb", action="DOWNGRADE", downgrade_to="WATCH", scenario_id="SCEN-WIN-001")
    r1 = apply_allowlist([d], [a, b])
    r2 = apply_allowlist([d], [b, a])
    # most-aggressive downgrade wins (WATCH), attributed to its entry, regardless of input order
    assert r1.band_overrides == r2.band_overrides == {dedup_key(d): "WATCH"}
    assert r1.downgraded[0]["entry_id"] == r2.downgraded[0]["entry_id"] == "bbb"


# ── invariant gates (static) ────────────────────────────────────────────────
_FORBIDDEN_IMPORTS = ("run_engine", "augur.engine.scoring", "augur.engine.matcher",
                      "augur.graph.builder", "augur.normalize")


def test_no_engine_import_in_tuning_package():
    for py in _TUNING_DIR.glob("*.py"):
        src = py.read_text()
        tree = ast.parse(src)
        mods = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods.append(node.module or "")
        for forbidden in ("augur.engine.scoring", "augur.engine.matcher",
                          "augur.engine.runner", "augur.graph.builder"):
            assert not any(m == forbidden or m.startswith("augur.normalize") for m in mods), \
                f"{py.name} imports forbidden engine module {forbidden}"


def test_no_wallclock_or_randomness_in_apply_core():
    # AST-based so docstrings/comments don't trip it: forbid importing or calling clock/RNG sources.
    tree = ast.parse((_TUNING_DIR / "apply.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] not in {"random", "uuid", "secrets", "time"}, \
                    f"apply.py imports forbidden module {a.name}"
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in {"random", "uuid", "secrets", "time"}, \
                f"apply.py imports from forbidden module {node.module}"
        elif isinstance(node, ast.Attribute):
            assert node.attr != "now", "apply.py must not call .now() (no wall-clock)"
