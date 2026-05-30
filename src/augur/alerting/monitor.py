import asyncio
import logging
import os
from datetime import datetime, timezone

from augur.connectors import DirectorySource, JsonlSource

_log = logging.getLogger("augur.alerting.monitor")


def monitor_enabled() -> bool:
    return os.environ.get("AUGUR_MONITOR_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")


def monitor_interval() -> float:
    return float(os.environ.get("AUGUR_MONITOR_INTERVAL", "60"))


def build_monitor_source(astate):
    """A DirectorySource over AUGUR_MONITOR_DIR if set, else the configured scan feed."""
    directory = os.environ.get("AUGUR_MONITOR_DIR")
    if directory:
        return DirectorySource(directory)
    return JsonlSource(astate.scan_source_path)


async def monitor_loop(astate, *, interval: float, stop: asyncio.Event) -> None:
    """Scan once per iteration (top of loop), then wait up to `interval` for the stop signal.

    Failure-isolated: a raising scan is logged and the loop continues. Scanning at the top makes the
    loop deterministically testable (pre-set the stop event -> exactly one scan, then exit).
    """
    from augur.alerting.router import scan_state
    while True:
        try:
            counts = scan_state(astate, now=datetime.now(timezone.utc), source=build_monitor_source(astate))
            _log.info("monitor scan: %s", counts)
        except Exception as exc:                      # a bad tick must never kill the loop
            _log.warning("monitor scan failed: %s", exc)
        if stop.is_set():
            return
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            return                                    # stop signalled during the wait
        except asyncio.TimeoutError:
            pass                                      # interval elapsed -> next iteration
