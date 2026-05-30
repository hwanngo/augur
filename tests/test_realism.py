"""Tests for augur.simulator.realism — realistic process paths and command lines."""
import json
import pathlib
import re

import pytest


# ---------------------------------------------------------------------------
# realistic_path tests
# ---------------------------------------------------------------------------

def test_realistic_path_rundll32_windows():
    from augur.simulator.realism import realistic_path
    path = realistic_path("rundll32.exe", "windows")
    assert path is not None
    assert "System32" in path
    assert "proc.exe" not in path
    assert "rundll32.exe" in path


def test_realistic_path_powershell_windows():
    from augur.simulator.realism import realistic_path
    path = realistic_path("powershell.exe", "windows")
    assert path is not None
    assert "WindowsPowerShell" in path or "System32" in path


def test_realistic_path_curl_linux():
    from augur.simulator.realism import realistic_path
    path = realistic_path("curl", "linux")
    assert path is not None
    assert path.startswith("/")
    assert "curl" in path


def test_realistic_path_osascript_macos():
    from augur.simulator.realism import realistic_path
    path = realistic_path("osascript", "macos")
    assert path is not None
    assert path.startswith("/")
    assert "osascript" in path


def test_realistic_path_unknown_name_windows_fallback():
    from augur.simulator.realism import realistic_path
    path = realistic_path("weirdtool.exe", "windows")
    assert path is not None
    assert "System32" in path
    assert "weirdtool.exe" in path


def test_realistic_path_unknown_name_linux_fallback():
    from augur.simulator.realism import realistic_path
    path = realistic_path("weirdtool", "linux")
    assert path is not None
    assert path.startswith("/usr/bin/weirdtool")


def test_realistic_path_unknown_name_macos_fallback():
    from augur.simulator.realism import realistic_path
    path = realistic_path("weirdtool", "macos")
    assert path is not None
    assert path.startswith("/usr/bin/weirdtool")


def test_realistic_path_none_name_returns_none():
    from augur.simulator.realism import realistic_path
    assert realistic_path(None, "windows") is None
    assert realistic_path(None, "linux") is None


def test_realistic_path_aws_linux():
    from augur.simulator.realism import realistic_path
    path = realistic_path("aws", "linux")
    assert path is not None
    assert "aws" in path
    assert "proc.exe" not in path


def test_realistic_path_crontab_linux():
    from augur.simulator.realism import realistic_path
    path = realistic_path("crontab", "linux")
    assert path == "/usr/bin/crontab"


# ---------------------------------------------------------------------------
# REALISTIC_CMDLINES dict tests
# ---------------------------------------------------------------------------

def test_realistic_cmdlines_has_scen_win_001():
    from augur.simulator.realism import REALISTIC_CMDLINES
    assert "SCEN-WIN-001" in REALISTIC_CMDLINES
    # step 1 must satisfy comsvcs regex
    cmd_step1 = REALISTIC_CMDLINES["SCEN-WIN-001"][1]
    assert re.search(r".*comsvcs.*", cmd_step1)
    # step 2 must satisfy MiniDump regex
    cmd_step2 = REALISTIC_CMDLINES["SCEN-WIN-001"][2]
    assert re.search(r".*MiniDump.*", cmd_step2)


def test_realistic_cmdlines_lnx001_step2_contains_payload():
    from augur.simulator.realism import REALISTIC_CMDLINES
    assert "SCEN-LNX-001" in REALISTIC_CMDLINES
    cmd = REALISTIC_CMDLINES["SCEN-LNX-001"][2]
    assert re.search(r".*payload.*", cmd)


def test_realistic_cmdlines_no_junk_tokens():
    """No authored command line should contain the synth junk patterns."""
    from augur.simulator.realism import REALISTIC_CMDLINES
    for scen_id, steps in REALISTIC_CMDLINES.items():
        for step_id, cmd in steps.items():
            assert "proc" not in cmd or "process" in cmd.lower() or "proc.exe" not in cmd, (
                f"{scen_id} step {step_id}: suspicious 'proc' token in cmd: {cmd!r}"
            )
            # The synth regex replacement produces patterns like "xFOOx"
            import re as re2
            assert not re2.search(r"x[a-zA-Z]{3,}x", cmd), (
                f"{scen_id} step {step_id}: synth junk pattern found in cmd: {cmd!r}"
            )


# ---------------------------------------------------------------------------
# enrich_intent round-trip test
# ---------------------------------------------------------------------------

def test_enrich_intent_replaces_command_line_and_keeps_regex_match():
    """After enrichment, the command_line must still satisfy the original step regex."""
    from augur.simulator.realism import enrich_intent
    from augur.simulator.intents import EventIntent
    from augur.pipeline import default_scenarios
    from datetime import datetime, timezone

    scn_map = {s.scenario_id: s for s in default_scenarios()}
    scenario = scn_map["SCEN-WIN-001"]

    # Simulate what synth produces for step 1: the junk "xcomsvcsx"
    intent = EventIntent(
        kind="process_create",
        host="HR_User_PC",
        timestamp=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
        process_name="rundll32.exe",
        process_path="C:\\Windows\\proc.exe",
        command_line="xcomsvcsx",
    )

    enrich_intent(intent, scenario, "windows")

    # process_path must now be a real path
    assert intent.process_path is not None
    assert "System32" in intent.process_path

    # command_line must satisfy step 1's regex
    assert re.search(r".*comsvcs.*", intent.command_line)
    # and must not be the junk token
    assert intent.command_line != "xcomsvcsx"


def test_enrich_intent_replaces_junk_process_path_linux():
    from augur.simulator.realism import enrich_intent
    from augur.simulator.intents import EventIntent
    from augur.pipeline import default_scenarios
    from datetime import datetime, timezone

    scn_map = {s.scenario_id: s for s in default_scenarios()}
    scenario = scn_map["SCEN-LNX-001"]

    intent = EventIntent(
        kind="process_create",
        host="CORP-JENKINS01",
        timestamp=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
        process_name="curl",
        process_path="C:\\Windows\\proc.exe",   # the synth default
        command_line="xpayloadx",
    )

    enrich_intent(intent, scenario, "linux")

    assert intent.process_path is not None
    assert intent.process_path.startswith("/")
    assert "proc.exe" not in intent.process_path
    assert re.search(r".*payload.*", intent.command_line)


def test_enrich_intent_does_not_overwrite_real_path():
    """If process_path is already realistic (not the synth default), leave it alone."""
    from augur.simulator.realism import enrich_intent
    from augur.simulator.intents import EventIntent
    from augur.pipeline import default_scenarios
    from datetime import datetime, timezone

    scn_map = {s.scenario_id: s for s in default_scenarios()}
    scenario = scn_map["SCEN-WIN-001"]

    real_path = "C:\\Windows\\System32\\rundll32.exe"
    intent = EventIntent(
        kind="process_create",
        host="HR_User_PC",
        timestamp=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
        process_name="rundll32.exe",
        process_path=real_path,
        command_line="xcomsvcsx",
    )

    enrich_intent(intent, scenario, "windows")
    assert intent.process_path == real_path  # unchanged


# ---------------------------------------------------------------------------
# Post-regen fixture spot-check (runs against the regenerated files)
# These tests deliberately use the file-on-disk, so they pass only after regen.
# ---------------------------------------------------------------------------

def test_true_positive_no_junk_tokens():
    """After regen, full_detection.jsonl must have no xcomsvcsx or proc.exe."""
    p = pathlib.Path("sample_data/acceptance/full_detection.jsonl")
    if not p.exists():
        pytest.skip("fixture not found")
    content = p.read_text()
    assert "xcomsvcsx" not in content, "junk synth token 'xcomsvcsx' still present"
    assert '"C:\\\\Windows\\\\proc.exe"' not in content, "default synth path still present"


def test_true_positive_has_real_tokens():
    """After regen, full_detection.jsonl must have comsvcs + MiniDump tokens."""
    p = pathlib.Path("sample_data/acceptance/full_detection.jsonl")
    if not p.exists():
        pytest.skip("fixture not found")
    content = p.read_text()
    assert "comsvcs" in content, "comsvcs token not found in full_detection.jsonl"
    assert "MiniDump" in content, "MiniDump token not found in full_detection.jsonl"


def test_true_positive_has_real_process_path():
    """After regen, process events must have a real System32 path."""
    p = pathlib.Path("sample_data/acceptance/full_detection.jsonl")
    if not p.exists():
        pytest.skip("fixture not found")
    events = [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
    proc_events = [e for e in events if e.get("event_id") == 1]
    assert proc_events, "no process_create events in fixture"
    for e in proc_events:
        path = e.get("process_path", "")
        assert "System32" in path or path == "", (
            f"Expected real System32 path, got: {path!r}"
        )


def test_linux_fixture_no_windows_path():
    """Linux fixtures must have POSIX paths, not Windows paths."""
    p = pathlib.Path("sample_data/persistence/SCEN-LNX-001_tp.jsonl")
    if not p.exists():
        pytest.skip("fixture not found")
    content = p.read_text()
    assert "C:\\\\Windows\\\\proc.exe" not in content, "Windows path in Linux fixture"


def test_macos_fixture_has_realistic_cmdline():
    """macOS fixture must have recognizable shell/tool command args."""
    p = pathlib.Path("sample_data/execution/SCEN-MAC-001_tp.jsonl")
    if not p.exists():
        pytest.skip("fixture not found")
    content = p.read_text()
    # osascript step 1 should have "shell" in the args
    assert "shell" in content, "osascript 'shell' keyword not found in SCEN-MAC-001 fixture"
