"""Real-Content Wave-1: fetcher registry shape (no network) + network-guarded per-scenario 1.0-fire.

The fire tests SKIP when a dataset's tagged.jsonl is absent so the default infra-free suite
(`uv run pytest -q`) stays green. Run them after `uv run python scripts/fetch_real_datasets.py
--suite wave1` to exercise the real captures.
"""
import importlib
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def _load_fetcher():
    sys.path.insert(0, str(_ROOT / "scripts"))
    import fetch_real_datasets
    return importlib.reload(fetch_real_datasets)


# Expected OTRF URL bases for the 6 new Wave-1 datasets (paths verified in spec §2.1).
_EXPECTED = {
    "cmd_dumping_ntds_dit_file_ntdsutil":
        "datasets/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil.zip",
    "cmd_sam_copy_esentutl":
        "datasets/atomic/windows/credential_access/host/cmd_sam_copy_esentutl.zip",
    "cmd_mshta_vbscript_execute_psh":
        "datasets/atomic/windows/defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip",
    "empire_uac_shellapi_fodhelper":
        "datasets/atomic/windows/privilege_escalation/host/empire_uac_shellapi_fodhelper.zip",
    "cmd_bitsadmin_download_psh_script":
        "datasets/atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script.zip",
    "empire_schtasks_creation_execution_elevated_user":
        "datasets/atomic/windows/persistence/host/empire_schtasks_creation_execution_elevated_user.zip",
}


def test_registry_has_six_new_wave1_datasets():
    fetcher = _load_fetcher()
    for name, tail in _EXPECTED.items():
        assert name in fetcher.REGISTRY, f"missing REGISTRY entry {name!r}"
        url = fetcher.REGISTRY[name]
        assert url.startswith("https://raw.githubusercontent.com/OTRF/Security-Datasets/master/")
        assert url.endswith(tail), f"{name}: URL tail mismatch -> {url}"


def test_wave1_list_is_seven_tags_in_order():
    fetcher = _load_fetcher()
    assert fetcher.WAVE1 == [
        "empire_mimikatz_logonpasswords",
        "cmd_dumping_ntds_dit_file_ntdsutil",
        "cmd_sam_copy_esentutl",
        "cmd_mshta_vbscript_execute_psh",
        "empire_uac_shellapi_fodhelper",
        "cmd_bitsadmin_download_psh_script",
        "empire_schtasks_creation_execution_elevated_user",
    ]
    # every WAVE1 tag must be resolvable in the registry
    for t in fetcher.WAVE1:
        assert t in fetcher.REGISTRY


# ── Task 2: combined Wave-1 topology ────────────────────────────────────────
def test_topology_wave1_validates_and_declares_both_ws5_forms():
    from augur.topology.network import load_topology
    from augur.enums import Zone, Criticality
    topo = load_topology(_ROOT / "datasets" / "real" / "topology_wave1.yaml")
    # both short + FQDN WORKSTATION5 are distinct declared assets (lookup does NOT fold)
    assert topo.lookup("WORKSTATION5") is not None
    assert topo.lookup("WORKSTATION5.theshire.local") is not None
    # the ntdsutil DC is in pandalab, Active_Directory + CRITICAL
    z, c = topo.enrich("DC01.pandalab.com")
    assert z == Zone.Active_Directory and c == Criticality.CRITICAL
    # superset of theshire: original 3 hosts still present
    for h in ("WORKSTATION6.theshire.local", "MORDORDC.theshire.local"):
        assert topo.lookup(h) is not None
    # User_Endpoint hosts enrich correctly
    z2, _ = topo.enrich("WORKSTATION5")
    assert z2 == Zone.User_Endpoint


# ── Tasks 3-8: network-guarded per-scenario 1.0-fire on the real captures ────
from augur.pipeline import build_backend
from augur.topology.network import load_topology
from augur.scenarios.loader import load_scenarios

_TOPO = _ROOT / "datasets" / "real" / "topology_wave1.yaml"


def _tagged(dataset: str) -> Path:
    return _ROOT / "datasets" / "real" / dataset / "tagged.jsonl"


def _fire(dataset: str, scenario_id: str):
    """Run committed code over a tagged real capture; return the matching Detection or None.

    SKIPS if the dataset hasn't been fetched+tagged (keeps the infra-free suite green)."""
    tagged = _tagged(dataset)
    if not tagged.exists():
        pytest.skip(f"dataset {dataset!r} not fetched; run "
                    f"`uv run python scripts/fetch_real_datasets.py --suite wave1`")
    be = build_backend([str(tagged)], load_topology(_TOPO))
    dets = run_engine_for(be)
    for d in dets:
        if d.scenario_id == scenario_id:
            return d
    return None


def run_engine_for(backend):
    from augur.engine.runner import run_engine
    return run_engine(backend, load_scenarios("scenarios_real"), min_proximity=0.30)


@pytest.mark.parametrize("dataset,scenario_id,severity", [
    ("cmd_dumping_ntds_dit_file_ntdsutil",              "SCEN-REAL-WIN-T1003-003-001", "CRITICAL"),
    ("cmd_sam_copy_esentutl",                           "SCEN-REAL-WIN-T1003-002-001", "HIGH"),
    ("cmd_mshta_vbscript_execute_psh",                  "SCEN-REAL-WIN-T1218-005-001", "HIGH"),
    ("empire_uac_shellapi_fodhelper",                   "SCEN-REAL-WIN-T1548-002-001", "HIGH"),
    ("cmd_bitsadmin_download_psh_script",               "SCEN-REAL-WIN-T1197-001",     "MEDIUM"),
    ("empire_schtasks_creation_execution_elevated_user","SCEN-REAL-WIN-T1053-005-001", "HIGH"),
])
def test_wave1_scenario_fires_at_1_0(dataset, scenario_id, severity):
    d = _fire(dataset, scenario_id)
    assert d is not None, f"{scenario_id} did not fire on {dataset}"
    assert d.proximity == 1.0, f"{scenario_id} proximity {d.proximity} != 1.0"
    assert str(d.severity) == severity or d.severity == severity


# ── Task 10: --real all suite wiring ────────────────────────────────────────
def test_demo_exposes_real_app_list_and_wave1():
    """_real_app + real-suite plumbing exist and use the combined topology for the suite."""
    import augur.demo as demo
    # the suite topology constant is wired
    assert demo._WAVE1_TOPOLOGY == "datasets/real/topology_wave1.yaml"
    # the real-suite tag list (Wave 1 + Wave 2) is importable from the fetcher via demo's helper
    tags = demo._wave1_tags()
    assert tags[0] == "empire_mimikatz_logonpasswords"
    assert len(tags) == 9   # 7 Wave-1 + 2 Wave-2 (injection EID-8 + run-key persistence EID-13)
    assert "empire_dllinjection_LoadLibrary_CreateRemoteThread" in tags
    assert "empire_persistence_registry_modification_run_keys_elevated_user" in tags


def test_real_all_suite_smoke(monkeypatch):
    """--real all builds the full real-suite feed + combined topology + default∪real scenarios.

    SKIPS unless all tagged captures are present (network-guarded)."""
    import augur.demo as demo
    missing = [t for t in demo._wave1_tags() if not _tagged(t).exists()]
    if missing:
        pytest.skip(f"suite datasets missing: {missing}; run --suite all")
    # run headless: must surface all 9 real detections (Wave 1's 7 + Wave 2's injection + persistence)
    served = {}
    monkeypatch.setattr(demo.uvicorn if hasattr(demo, "uvicorn") else demo, "run",
                        lambda *a, **k: served.setdefault("ran", True), raising=False)
    dets = demo.main(["--real", "all", "--no-serve"])
    # main() returns None but run_headless printed; re-derive deterministically:
    from augur.engine.runner import run_engine
    topo = load_topology(_TOPO)
    paths = [str(_tagged(t)) for t in demo._wave1_tags()]
    from augur.pipeline import default_scenarios
    be = build_backend(paths, topo)
    scens = default_scenarios() + load_scenarios("scenarios_real")
    real_ids = {d.scenario_id for d in run_engine(be, scens, 0.30) if d.scenario_id.startswith("SCEN-REAL-")}
    assert real_ids == {
        "SCEN-REAL-WIN-T1003-001", "SCEN-REAL-WIN-T1003-003-001", "SCEN-REAL-WIN-T1003-002-001",
        "SCEN-REAL-WIN-T1218-005-001", "SCEN-REAL-WIN-T1548-002-001", "SCEN-REAL-WIN-T1197-001",
        "SCEN-REAL-WIN-T1053-005-001",
        "SCEN-REAL-WIN-T1055-001", "SCEN-REAL-WIN-T1547-001",   # Wave 2: injection + run-key persistence
        "SCEN-REAL-WIN-T1059-001",                              # Wave 2.1: PowerShell ScriptBlock (EID 4104)
    }
