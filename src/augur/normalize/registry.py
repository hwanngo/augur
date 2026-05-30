from typing import Callable, Protocol, runtime_checkable

from augur.normalize.model import NormalizedEvent
from augur.normalize import windows_sysmon, linux_auditd, macos_esf, windows_sysmon_real


@runtime_checkable
class Normalizer(Protocol):
    def __call__(self, raw: dict) -> NormalizedEvent | None: ...


REGISTRY: dict[str, Callable[[dict], NormalizedEvent | None]] = {
    "windows_sysmon": windows_sysmon.normalize,
    "windows_sysmon_real": windows_sysmon_real.normalize,
    "linux_auditd": linux_auditd.normalize,
    "macos_esf": macos_esf.normalize,
}


def normalize_event(raw: dict) -> NormalizedEvent | None:
    st = raw.get("source_type")
    if st is None:
        return windows_sysmon.normalize(raw)        # legacy default: verbatim Windows behavior
    norm = REGISTRY.get(st)
    if norm is None:
        raise ValueError(f"unknown source_type: {st!r}")
    return norm(raw)


def normalize_events(raws: list[dict]) -> list[NormalizedEvent]:
    out: list[NormalizedEvent] = []
    for raw in raws:
        ev = normalize_event(raw)
        if ev is not None:
            out.append(ev)
    return out
