import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AlertConfig:
    min_proximity: float
    auto_resolve_cycles: int


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def load_alert_config() -> AlertConfig:
    return AlertConfig(
        min_proximity=_clamp(float(os.environ.get("AUGUR_ALERT_MIN_PROXIMITY", "0.6")), 0.0, 1.0),
        auto_resolve_cycles=int(os.environ.get("AUGUR_ALERT_AUTO_RESOLVE_CYCLES", "0")),
    )
