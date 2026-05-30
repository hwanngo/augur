"""Wave-2 real-behavior detections (EID 8 injection, EID 13 Run-key persistence) end-to-end.

Infra-free: uses inline real-OTRF-shape fixtures (the actual captures are gitignored), the COMMITTED
Wave-1 topology, and the COMMITTED scenarios_real. Proves the malicious instance fires at 1.0 AND that
the benign baseline (csrss->svchost CtrlRoutine, W32Time registry) does NOT fire — the honesty guard
that kept these out of Wave 1 in the first place.
"""
from augur.normalize.windows_sysmon_real import normalize_real_sysmon_events
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.engine.runner import run_engine
from augur.scenarios.loader import load_scenarios
from augur.topology.network import load_topology

_PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
_HOST = "WORKSTATION5.mordor.local"   # declared in the committed Wave-1 topology (User_Endpoint)
_TOPO = load_topology("datasets/real/topology_wave1.yaml")
_SCEN = {s.scenario_id: s for s in load_scenarios("scenarios_real")}


def _common(eid, ts):
    return {"EventID": eid, "@timestamp": ts, "Hostname": _HOST, "SourceName": "Microsoft-Windows-Sysmon"}


def _detections(raws):
    evs = sorted(normalize_real_sysmon_events(raws), key=lambda e: e.timestamp)
    b = NetworkXBackend(); build_graph(evs, _TOPO, b)
    return {d.scenario_id: d for d in run_engine(b, list(_SCEN.values()), min_proximity=0.0)}


# malicious instances (the actual technique in the OTRF captures)
_MAL_INJECTION = {**_common(8, "2026-06-03T10:00:06.000Z"), "SourceImage": _PS,
                  "SourceProcessGuid": "{aaaa-1}", "TargetImage": "C:\\Windows\\System32\\notepad.exe",
                  "StartFunction": "LoadLibraryA"}
_MAL_RUNKEY = {**_common(13, "2026-06-03T10:00:07.000Z"), "Image": _PS, "ProcessGuid": "{aaaa-2}",
               "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
               "Details": "\"powershell.exe\" -Win Hidden -enc ZQBjAGgA"}

# PowerShell ScriptBlock (EID 4104): the AMSI/script-block-logging bypass reflection = malicious.
_MAL_SCRIPTBLOCK = {"EventID": 4104, "@timestamp": "2026-06-03T10:00:08.000Z", "Hostname": _HOST,
                    "SourceName": "Microsoft-Windows-PowerShell", "ExecutionProcessID": 7820,
                    "ScriptBlockId": "{sb-1}",
                    "ScriptBlockText": "IF($PSVERSIOnTABlE.PSVERSioN.MAJOR -ge 3){[Ref].AsSEmBLy."
                                       "GETTYpE('System.Management.Automation.Utils')}"}

# benign baseline (present in the Wave-1 captures; MUST NOT fire)
_BENIGN_INJECTION = {**_common(8, "2026-06-03T10:00:01.000Z"),
                     "SourceImage": "C:\\Windows\\System32\\csrss.exe", "SourceProcessGuid": "{bbbb-1}",
                     "TargetImage": "C:\\Windows\\System32\\svchost.exe", "StartFunction": "CtrlRoutine"}
_BENIGN_RUNKEY = {**_common(13, "2026-06-03T10:00:02.000Z"),
                  "Image": "C:\\windows\\system32\\lsass.exe", "ProcessGuid": "{bbbb-2}",
                  "TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\W32Time\\SecureTimeLimits\\RunTime",
                  "Details": "QWORD (0x0-0x0)"}
# benign DSC/config script block (the kind also logged via 4104) — no AMSI-bypass reflection.
_BENIGN_SCRIPTBLOCK = {"EventID": 4104, "@timestamp": "2026-06-03T10:00:03.000Z", "Hostname": _HOST,
                       "SourceName": "Microsoft-Windows-PowerShell", "ExecutionProcessID": 4242,
                       "ScriptBlockId": "{sb-9}",
                       "ScriptBlockText": "# Localized MSFT_RoleResourceStrings.psd1\nConfiguration Demo { Node x {} }"}


def test_injection_fires_at_full_proximity():
    dets = _detections([_MAL_INJECTION])
    d = dets.get("SCEN-REAL-WIN-T1055-001")
    assert d is not None and d.proximity == 1.0
    assert d.affected_hosts == [_HOST]


def test_runkey_persistence_fires_at_full_proximity():
    dets = _detections([_MAL_RUNKEY])
    d = dets.get("SCEN-REAL-WIN-T1547-001")
    assert d is not None and d.proximity == 1.0
    assert d.affected_hosts == [_HOST]


def test_powershell_scriptblock_fires_at_full_proximity():
    dets = _detections([_MAL_SCRIPTBLOCK])
    d = dets.get("SCEN-REAL-WIN-T1059-001")
    assert d is not None and d.proximity == 1.0
    assert d.affected_hosts == [_HOST]


def test_benign_baseline_does_not_fire():
    # The honesty guard: benign CreateRemoteThread (csrss->svchost), benign registry writes (W32Time),
    # and benign DSC script blocks — all abundant in real captures — must produce NO Wave-2 detection.
    dets = _detections([_BENIGN_INJECTION, _BENIGN_RUNKEY, _BENIGN_SCRIPTBLOCK])
    assert "SCEN-REAL-WIN-T1055-001" not in dets
    assert "SCEN-REAL-WIN-T1547-001" not in dets
    assert "SCEN-REAL-WIN-T1059-001" not in dets


def test_malicious_and_benign_mixed_only_malicious_fires():
    dets = _detections([_BENIGN_INJECTION, _BENIGN_RUNKEY, _BENIGN_SCRIPTBLOCK,
                        _MAL_INJECTION, _MAL_RUNKEY, _MAL_SCRIPTBLOCK])
    assert dets["SCEN-REAL-WIN-T1055-001"].proximity == 1.0
    assert dets["SCEN-REAL-WIN-T1547-001"].proximity == 1.0
    assert dets["SCEN-REAL-WIN-T1059-001"].proximity == 1.0
