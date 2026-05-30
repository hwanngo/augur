"""Unit tests for the real-Sysmon-field normalizer (source_type='windows_sysmon_real')."""
from datetime import timezone

from augur.normalize.windows_sysmon_real import (
    normalize,
    normalize_real_sysmon,
    normalize_real_sysmon_events,
)
from augur.normalize.registry import normalize_event, normalize_events


_PS_IMAGE = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def _eid10_malicious():
    # genuine real-OTRF EID-10 shape: capital EventID, SourceProcessGUID/SourceImage/TargetImage,
    # NO ProcessGuid/Image (null on real EID-10). The accessor is Source*.
    return {
        "EventID": 10,
        "@timestamp": "2026-06-03T10:00:05.123Z",
        "Hostname": "CORP-WKS-0421",
        "host": "WEC-FORWARDER-01",  # forwarder; MUST be ignored
        "SourceProcessGUID": "{297bc33e-65d0-5f2d-8207-000000000400}",
        "SourceImage": _PS_IMAGE,
        "TargetProcessGUID": "{297bc33e-5c2e-5f2b-0c00-000000000400}",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1010",
        "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9c534|...",
    }


def test_eid10_maps_to_behavior_with_target_and_access():
    ev = normalize(_eid10_malicious())
    assert ev is not None
    assert ev.kind == "behavior"
    assert ev.behavior == "ProcessAccess"
    assert ev.process_guid == "{297bc33e-65d0-5f2d-8207-000000000400}"  # SourceProcessGUID (accessor)
    assert ev.process_name == _PS_IMAGE                                  # from SourceImage
    assert ev.process_path == _PS_IMAGE
    assert ev.target == "lsass.exe"                  # basename of TargetImage
    assert ev.granted_access == "0x1010"
    assert ev.reason == "C:\\Windows\\SYSTEM32\\ntdll.dll+9c534|..."
    assert ev.source_type == "windows_sysmon_real"
    assert ev.os_family == "windows"
    assert ev.raw_event_type == "10"


def test_eid_lowercase_event_id_fallback_still_works():
    # legacy/synthetic events tagged with lowercase event_id must still normalize
    raw = _eid10_malicious()
    del raw["EventID"]
    raw["event_id"] = 10
    ev = normalize(raw)
    assert ev is not None
    assert ev.kind == "behavior"
    assert ev.process_guid == "{297bc33e-65d0-5f2d-8207-000000000400}"


def test_host_uses_Hostname_not_forwarder_host():
    ev = normalize(_eid10_malicious())
    assert ev.host == "CORP-WKS-0421"


def test_timestamp_is_tz_aware_utc():
    ev = normalize(_eid10_malicious())
    assert ev.timestamp.tzinfo is not None
    assert ev.timestamp.utcoffset().total_seconds() == 0
    assert ev.timestamp.astimezone(timezone.utc).hour == 10


def test_timestamp_falls_back_to_UtcTime_when_no_at_timestamp():
    raw = _eid10_malicious()
    del raw["@timestamp"]
    raw["UtcTime"] = "2026-06-03 11:30:00.000"
    ev = normalize(raw)
    assert ev.timestamp.tzinfo is not None
    assert ev.timestamp.hour == 11 and ev.timestamp.minute == 30


def test_eid1_process_create_fields():
    raw = {
        "source_type": "windows_sysmon_real",
        "event_id": 1,
        "@timestamp": "2026-06-03T10:00:00.000Z",
        "Hostname": "CORP-WKS-0421",
        "ProcessGuid": "{guid-whoami}",
        "Image": "C:\\Windows\\System32\\whoami.exe",
        "CommandLine": "whoami /all",
        "ParentProcessGuid": "{guid-ps-1}",
        "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "IntegrityLevel": "High",
        "User": "CORP\\admin",
    }
    ev = normalize(raw)
    assert ev.kind == "process_create"
    assert ev.process_name == "C:\\Windows\\System32\\whoami.exe"
    assert ev.process_path == "C:\\Windows\\System32\\whoami.exe"
    assert ev.command_line == "whoami /all"
    assert ev.process_guid == "{guid-whoami}"
    assert ev.parent_process_guid == "{guid-ps-1}"
    assert ev.parent_process_name == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert ev.integrity_level == "High"
    assert ev.user == "CORP\\admin"


def test_hashes_string_parses_to_dict():
    raw = {
        "source_type": "windows_sysmon_real",
        "event_id": 1,
        "@timestamp": "2026-06-03T10:00:00.000Z",
        "Hostname": "CORP-WKS-0421",
        "ProcessGuid": "{g}",
        "Image": "x.exe",
        "Hashes": "SHA1=AAA,MD5=BBB,SHA256=CCC",
    }
    ev = normalize(raw)
    assert ev.hashes == {"SHA1": "AAA", "MD5": "BBB", "SHA256": "CCC"}


def test_unmodeled_eid_returns_none():
    # EID 11 (FileCreate) is not modeled — real captures are noisy, unmodeled EIDs are dropped (not raised).
    raw = {"source_type": "windows_sysmon_real", "event_id": 11,
           "@timestamp": "2026-06-03T10:00:00.000Z", "Hostname": "CORP-WKS-0421"}
    assert normalize(raw) is None


def _eid8_injection():
    # real OTRF EID-8 CreateRemoteThread: powershell -> notepad (DLL injection via LoadLibraryA).
    return {
        "EventID": 8, "@timestamp": "2026-06-03T10:00:06.000Z", "Hostname": "WORKSTATION5.mordor.local",
        "SourceName": "Microsoft-Windows-Sysmon", "SourceImage": _PS_IMAGE,
        "SourceProcessGuid": "{b59756a9-b239-5f17-5307-000000000400}",
        "TargetImage": "C:\\Windows\\System32\\notepad.exe", "StartFunction": "LoadLibraryA",
    }


def test_eid8_maps_to_createremotethread_behavior():
    ev = normalize(_eid8_injection())
    assert ev is not None and ev.kind == "behavior"
    assert ev.behavior == "CreateRemoteThread"
    assert ev.process_guid == "{b59756a9-b239-5f17-5307-000000000400}"   # SourceProcessGuid (injector)
    assert ev.process_name == _PS_IMAGE
    assert ev.target == "notepad.exe"                                    # basename of TargetImage
    assert ev.reason == "LoadLibraryA"                                   # StartFunction (context)


def _eid13_runkey():
    # real OTRF EID-13 RegistryEvent SetValue: powershell writes a CurrentVersion\Run autorun value.
    return {
        "EventID": 13, "@timestamp": "2026-06-03T10:00:07.000Z", "Hostname": "WORKSTATION5.mordor.local",
        "SourceName": "Microsoft-Windows-Sysmon", "Image": _PS_IMAGE,
        "ProcessGuid": "{b59756a9-aaaa-5f17-5307-000000000400}",
        "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "Details": "\"powershell.exe\" -Win Hidden -enc ZQBjAGgA",
    }


def test_eid13_maps_to_registrysetvalue_behavior():
    ev = normalize(_eid13_runkey())
    assert ev is not None and ev.kind == "behavior"
    assert ev.behavior == "RegistrySetValue"
    assert ev.process_guid == "{b59756a9-aaaa-5f17-5307-000000000400}"   # ProcessGuid (writer)
    assert ev.process_name == _PS_IMAGE
    assert ev.target == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
    assert "-enc" in ev.reason                                            # Details (the value written)


_AMSI_BYPASS = ("IF($PSVERSIOnTABlE.PSVERSioN.MAJOR -ge 3){[Ref].AsSEmBLy.GETTYpE("
                "'System.Management.Automation.Utils').GetField('amsiInitFailed')}")


def _eid4104_scriptblock():
    # real OTRF EID-4104 (PowerShell ScriptBlock logging): NOT a Sysmon record (PowerShell provider),
    # NO ProcessGuid — only an ExecutionProcessID. The script text carries the signal.
    return {
        "EventID": 4104, "@timestamp": "2026-06-03T10:00:08.000Z", "Hostname": "WORKSTATION5.mordor.local",
        "SourceName": "Microsoft-Windows-PowerShell", "ExecutionProcessID": 7820,
        "ScriptBlockId": "{sb-1}", "ScriptBlockText": _AMSI_BYPASS,
    }


def test_eid4104_maps_to_powershell_scriptblock_behavior():
    ev = normalize(_eid4104_scriptblock())
    assert ev is not None and ev.kind == "behavior"
    assert ev.behavior == "PowerShellScriptBlock"
    assert ev.process_guid == "psh:WORKSTATION5.mordor.local:7820"   # synthetic per-(host,PID) anchor
    assert ev.process_name == "powershell.exe"
    assert "System.Management.Automation.Utils" in ev.target          # the script text (matched directly)
    assert ev.raw_event_type == "4104"


def test_eid4104_requires_powershell_provider():
    # 4104 is gated on the PowerShell provider, NOT Sysmon — a wrong-provider 4104 is dropped.
    assert normalize({**_eid4104_scriptblock(), "SourceName": "Microsoft-Windows-Sysmon"}) is None
    # and a Sysmon EID (e.g. 10) tagged with the PowerShell provider is likewise dropped (gate is per-EID)
    assert normalize({**_eid10_malicious(), "SourceName": "Microsoft-Windows-PowerShell"}) is None


def _tagged(raw: dict) -> dict:
    # registry dispatch keys on source_type; tag the otherwise-untagged real-shape event
    return {**raw, "source_type": "windows_sysmon_real"}


def test_registry_dispatches_and_skips_none():
    raws = [_tagged(_eid10_malicious()),
            {"source_type": "windows_sysmon_real", "event_id": 11,   # FileCreate — unmodeled, dropped
             "@timestamp": "2026-06-03T10:00:00.000Z", "Hostname": "CORP-WKS-0421"}]
    out = normalize_events(raws)
    assert len(out) == 1                  # EID 11 dropped
    assert out[0].kind == "behavior"
    # direct dispatch path
    assert normalize_event(_tagged(_eid10_malicious())).kind == "behavior"


def test_explicit_real_entry_ingests_untagged_events():
    # the committed opt-in path: untagged real-shape events normalized directly
    out = normalize_real_sysmon_events([_eid10_malicious()])
    assert len(out) == 1
    assert out[0].kind == "behavior"
    assert normalize_real_sysmon(_eid10_malicious()).kind == "behavior"


def test_kernel_io_eid1_collision_returns_none():
    # Microsoft-Windows-Kernel-IO also emits EventID 1 (volume-mount; no ProcessGuid). It is NOT
    # Sysmon process_create and must be dropped, not mis-normalized to a null-guid process_create.
    raw = {"EventID": 1, "Hostname": "H1", "SourceName": "Microsoft-Windows-Kernel-IO",
           "Channel": "Microsoft-Windows-Kernel-IO/Operational", "VolumeName": "\\Device\\HarddiskVolume3"}
    assert normalize(raw) is None


def test_channel_only_non_sysmon_provider_returns_none():
    # robustness fallback: no SourceName, Channel names a non-Sysmon provider -> dropped
    raw = {"EventID": 1, "Hostname": "H1", "Channel": "Microsoft-Windows-Kernel-IO/Operational"}
    assert normalize(raw) is None


def test_real_sysmon_eid1_with_provider_still_normalizes():
    raw = {"EventID": 1, "@timestamp": "2026-06-03T10:00:00.000Z", "Hostname": "H1",
           "SourceName": "Microsoft-Windows-Sysmon", "Channel": "Microsoft-Windows-Sysmon/Operational",
           "ProcessGuid": "{g}", "Image": "x.exe"}
    ev = normalize(raw)
    assert ev is not None and ev.kind == "process_create" and ev.process_guid == "{g}"


def test_no_provider_hint_still_normalizes():
    # minimal fixtures carry no SourceName/Channel — must stay byte-identical (treated as Sysmon)
    raw = {"EventID": 1, "@timestamp": "2026-06-03T10:00:00.000Z", "Hostname": "H1",
           "ProcessGuid": "{g}", "Image": "x.exe"}
    assert normalize(raw) is not None


def test_mixed_provider_list_drops_only_foreign_no_null_guid():
    from augur.ingest.jsonl import read_jsonl
    raws = read_jsonl("tests/fixtures/real/kernel_io_eid1_collision.jsonl")
    out = normalize_real_sysmon_events(raws)
    assert len(out) == 1                                   # Kernel-IO dropped, Sysmon kept
    assert all(e.process_guid is not None for e in out)    # NO null-guid events reach build_graph
    assert out[0].kind == "process_create"
