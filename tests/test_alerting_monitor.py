import asyncio
from datetime import datetime, timezone
from fastapi import FastAPI
from augur.auth.router import attach_auth
from augur.alerting.router import attach_alerting
from augur.alerting.monitor import (monitor_enabled, monitor_interval, build_monitor_source,
                                          monitor_loop)


def _astate(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    app = FastAPI()
    state = attach_auth(app)
    return attach_alerting(app, state, scan_source_path="sample_data/acceptance/full_detection.jsonl")


def test_monitor_enabled_env_gate(monkeypatch):
    monkeypatch.delenv("AUGUR_MONITOR_ENABLED", raising=False)
    assert monitor_enabled() is False
    monkeypatch.setenv("AUGUR_MONITOR_ENABLED", "1")
    assert monitor_enabled() is True
    monkeypatch.setenv("AUGUR_MONITOR_ENABLED", "false")
    assert monitor_enabled() is False


def test_monitor_interval_default(monkeypatch):
    monkeypatch.delenv("AUGUR_MONITOR_INTERVAL", raising=False)
    assert monitor_interval() == 60.0


def test_build_monitor_source_prefers_dir(tmp_path, monkeypatch):
    astate = _astate(tmp_path, monkeypatch)
    monkeypatch.delenv("AUGUR_MONITOR_DIR", raising=False)
    from augur.connectors import JsonlSource
    assert isinstance(build_monitor_source(astate), JsonlSource)
    monkeypatch.setenv("AUGUR_MONITOR_DIR", str(tmp_path))
    from augur.connectors import DirectorySource
    assert isinstance(build_monitor_source(astate), DirectorySource)


def test_monitor_loop_scans_once_then_stops(tmp_path, monkeypatch):
    astate = _astate(tmp_path, monkeypatch)

    async def drive():
        stop = asyncio.Event()
        stop.set()                       # pre-set: loop scans exactly once then exits
        await monitor_loop(astate, interval=999, stop=stop)

    asyncio.run(drive())
    assert any(a.scenario_id == "SCEN-WIN-001" for a in astate.alerts.list())


def test_monitor_loop_survives_a_failing_scan(tmp_path, monkeypatch):
    astate = _astate(tmp_path, monkeypatch)
    astate.scan_source_path = "does/not/exist.jsonl"   # makes run_scan raise

    async def drive():
        stop = asyncio.Event()
        stop.set()
        await monitor_loop(astate, interval=999, stop=stop)   # must NOT raise

    asyncio.run(drive())                # completes without error
    assert astate.alerts.list() == []
