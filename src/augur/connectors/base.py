from abc import ABC, abstractmethod
from typing import Iterable, Protocol, runtime_checkable

from augur.engine.scoring import Detection


@runtime_checkable
class Source(Protocol):
    """Inbound connector: yields raw log dicts to feed normalize_events()."""
    def read(self) -> Iterable[dict]: ...


@runtime_checkable
class Sink(Protocol):
    """Outbound connector: delivers detections to an external system."""
    def emit(self, detection: Detection) -> None: ...
    def emit_all(self, detections: list[Detection]) -> None: ...


class SinkBase(ABC):
    """Base for sinks: implement emit(); get emit_all() + context-manager lifecycle free."""

    @abstractmethod
    def emit(self, detection: Detection) -> None: ...

    def emit_all(self, detections: list[Detection]) -> None:
        for d in detections:
            self.emit(d)

    def close(self) -> None:
        pass

    def __enter__(self) -> "SinkBase":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False
