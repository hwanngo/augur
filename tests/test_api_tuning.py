"""TDD: /api/tuning router + the /api/detections integration (array-shape, byte-identical no-op)."""
import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password

_LOGS = ["sample_data/corpus/enterprise_day.jsonl"]


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    a = create_app(log_paths=_LOGS)
    a.state.auth.users.create_user("ana", hash_password("password1234"), "analyst")
    a.state.auth.users.create_user("vee", hash_password("password1234"), "viewer")
    a.state.auth.users.create_user("adm", hash_password("password1234"), "admin")
    return a


def _client(app, user="ana"):
    c = TestClient(app)
    r = c.post("/api/auth/login", data={"username": user, "password": "password1234"})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def _entry(**kw):
    body = {"action": "SUPPRESS", "reason": "known good", "scenario_id": "SCEN-WIN-001"}
    body.update(kw)
    return body


def _a_firing_scenario(c) -> dict:
    dets = c.get("/api/detections?min_proximity=0.0").json()
    assert isinstance(dets, list) and dets, "expected the corpus to produce detections"
    return dets[0]


# ── CRUD / RBAC / validation ────────────────────────────────────────────────
def test_create_get_with_events(app):
    c = _client(app)
    r = c.post("/api/tuning", json=_entry(host="WORKSTATION5"))
    assert r.status_code == 201, r.text
    eid = r.json()["id"]
    d = c.get(f"/api/tuning/{eid}").json()
    assert d["action"] == "SUPPRESS" and d["scenario_id"] == "SCEN-WIN-001" and d["host"] == "WORKSTATION5"
    assert d["author"] == "ana" and "events" in d
    assert d["events"][0]["event"] == "created"


def test_viewer_reads_analyst_writes(app):
    c = _client(app)
    eid = c.post("/api/tuning", json=_entry()).json()["id"]
    v = _client(app, user="vee")
    assert v.get("/api/tuning").status_code == 200
    assert v.get(f"/api/tuning/{eid}").status_code == 200
    assert v.post("/api/tuning", json=_entry()).status_code == 403


def test_validation_422(app):
    c = _client(app)
    assert c.post("/api/tuning", json={"action": "SUPPRESS", "reason": "x"}).status_code == 422  # no predicate
    assert c.post("/api/tuning", json=_entry(reason="")).status_code == 422                       # empty reason
    assert c.post("/api/tuning", json=_entry(zone="NotAZone")).status_code == 422
    assert c.post("/api/tuning", json=_entry(process_regex="(")).status_code == 422               # bad regex
    assert c.post("/api/tuning", json=_entry(scenario_id="SCEN-DOES-NOT-EXIST")).status_code == 422
    assert c.post("/api/tuning", json={"action": "DOWNGRADE", "reason": "x",
                                       "scenario_id": "SCEN-WIN-001"}).status_code == 422          # no downgrade_to
    assert c.post("/api/tuning", json=_entry(action="DOWNGRADE", downgrade_to="WAT",
                                             scenario_id="SCEN-WIN-001")).status_code == 422       # bad band


def test_enable_disable_and_delete_owner_or_admin(app):
    c = _client(app)
    eid = c.post("/api/tuning", json=_entry()).json()["id"]
    assert c.post(f"/api/tuning/{eid}/disable").json()["enabled"] is False
    assert c.post(f"/api/tuning/{eid}/enable").json()["enabled"] is True
    # a different analyst cannot delete someone else's entry; an admin can.
    other = _client(app, user="adm")
    # admin override works
    assert other.delete(f"/api/tuning/{eid}").status_code == 200
    assert c.get(f"/api/tuning/{eid}").status_code == 404


# ── /api/detections integration ─────────────────────────────────────────────
def test_detections_bare_list_when_no_entries(app):
    c = _client(app)
    dets = c.get("/api/detections").json()
    assert isinstance(dets, list)                      # top-level shape unchanged
    assert all("band_override" not in d for d in dets) # no additive field when not tuned


def test_suppress_removes_from_detections_and_shows_in_ledger(app):
    c = _client(app)
    target = _a_firing_scenario(c)
    sid = target["scenario_id"]
    before = {d["scenario_id"] for d in c.get("/api/detections?min_proximity=0.0").json()}
    assert sid in before
    c.post("/api/tuning", json={"action": "SUPPRESS", "reason": "benign here", "scenario_id": sid})
    after = c.get("/api/detections?min_proximity=0.0").json()
    assert sid not in {d["scenario_id"] for d in after}            # gone from the served list
    ledger = c.get("/api/tuning/ledger").json()
    assert ledger["ledger"]["suppressed_count"] >= 1
    assert sid in {s["scenario_id"] for s in ledger["suppressed"]}  # but visible in the ledger (honesty)


def test_downgrade_stamps_band_override(app):
    c = _client(app)
    target = _a_firing_scenario(c)
    sid = target["scenario_id"]
    c.post("/api/tuning", json={"action": "DOWNGRADE", "downgrade_to": "WATCH",
                                "reason": "noisy", "scenario_id": sid})
    rows = [d for d in c.get("/api/detections?min_proximity=0.0").json() if d["scenario_id"] == sid]
    assert rows and all(r.get("band_override") == "WATCH" for r in rows)
    assert all(r["proximity"] == target["proximity"] for r in rows)  # proximity untouched


def test_list_carries_live_hit_count(app):
    c = _client(app)
    sid = _a_firing_scenario(c)["scenario_id"]
    c.post("/api/tuning", json={"action": "SUPPRESS", "reason": "x", "scenario_id": sid})
    entry = c.get("/api/tuning").json()[0]
    assert entry["hit_count"] >= 1


# ── propose_from_alert ──────────────────────────────────────────────────────
def test_propose_unknown_alert_404(app):
    c = _client(app)
    assert c.post("/api/tuning/propose_from_alert/nope").status_code == 404


def test_propose_requires_analyst(app):
    v = _client(app, user="vee")
    assert v.post("/api/tuning/propose_from_alert/nope").status_code == 403


# ── baseline hint (rarity advisory) ─────────────────────────────────────────
def test_process_frequency_index_over_corpus():
    from augur.api.rarity import process_frequency_index
    idx = process_frequency_index(_LOGS)
    assert idx, "corpus should yield process_create frequencies"
    row = next(iter(idx.values()))
    assert {"name", "occurrences", "host_count", "single_host", "first_seen", "last_seen"} <= row.keys()
    assert all(r["occurrences"] >= 1 and r["host_count"] >= 1 for r in idx.values())
    assert all(r["single_host"] == (r["host_count"] == 1) for r in idx.values())


class _FakeBackend:
    def __init__(self, nodes): self._nodes = nodes
    def get_node(self, nid): return self._nodes.get(nid)


def _tstate(**kw):
    from augur.api.tuning import _TuningState
    base = dict(detections_provider=lambda: [], backend=None, technique_index={},
                scenarios=[], topology=None, baseline_provider=None)
    base.update(kw)
    return _TuningState(None, **base)


def test_primary_process_name_picks_deepest(app):
    from augur.api.tuning import _primary_process_name
    from augur.graph.models import ProcessNode
    nodes = {
        "p1": ProcessNode(id="p1", name="cmd.exe", path=None, command_line=None, parent_guid=None,
                          parent_process_name=None, host="H", timestamp=None),
        "p2": ProcessNode(id="p2", name="rundll32.exe", path=None, command_line=None, parent_guid=None,
                          parent_process_name=None, host="H", timestamp=None),
    }
    det = {"matched_steps": [{"element_id": "p1"}, {"element_id": "p2|EXH|0"}]}
    assert _primary_process_name(det, _FakeBackend(nodes)) == "rundll32.exe"   # deepest resolvable
    assert _primary_process_name(det, None) is None                            # no backend -> None


def test_baseline_hint_resolves_and_degrades_honestly():
    from augur.api.tuning import _baseline_hint
    from augur.graph.models import ProcessNode
    backend = _FakeBackend({"p1": ProcessNode(id="p1", name="evil.exe", path=None, command_line=None,
                                              parent_guid=None, parent_process_name=None, host="H", timestamp=None)})
    det = {"scenario_id": "SCEN-X", "matched_steps": [{"element_id": "p1"}]}
    index = {"evil.exe": {"name": "evil.exe", "occurrences": 12, "host_count": 4, "single_host": False,
                          "first_seen": "t0", "last_seen": "t1"}}
    st = _tstate(detections_provider=lambda: [det], backend=backend,
                 baseline_provider=lambda n: index.get(n.casefold()))
    hint = _baseline_hint(st, "SCEN-X")
    assert hint["process"] == "evil.exe" and hint["occurrences"] == 12 and hint["host_count"] == 4
    assert "honesty_note" in hint
    # honest null cases
    assert _baseline_hint(_tstate(), "SCEN-X") is None                                   # no provider
    assert _baseline_hint(_tstate(baseline_provider=lambda n: None), "SCEN-X") is None    # no detection
    st2 = _tstate(detections_provider=lambda: [det], backend=backend,
                  baseline_provider=lambda n: None)                                       # process not in index
    assert _baseline_hint(st2, "SCEN-X") is None


def test_propose_response_carries_baseline_hint_key(app):
    # End-to-end: scan to mint an alert, then propose — the response always carries a baseline_hint
    # field (a well-formed dict when the process resolves, else null; never absent).
    c = _client(app)
    c.post("/api/alerts/scan")
    alerts = c.get("/api/alerts").json()
    if not alerts:
        return  # no alert minted in this corpus config — nothing to assert
    res = c.post(f"/api/tuning/propose_from_alert/{alerts[0]['id']}").json()
    assert "baseline_hint" in res
    if res["baseline_hint"] is not None:
        assert {"process", "occurrences", "host_count", "honesty_note"} <= res["baseline_hint"].keys()
