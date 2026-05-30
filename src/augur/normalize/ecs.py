"""Backward-compat shim. The Windows-Sysmon logic now lives in normalize/windows_sysmon.py and the
source_type dispatch in normalize/registry.py. Existing imports keep working unchanged."""
from augur.normalize.model import NormalizedEvent, _ext   # noqa: F401
from augur.normalize.registry import normalize_event, normalize_events   # noqa: F401
from augur.normalize.windows_sysmon import _KIND_BY_EVENT   # noqa: F401
