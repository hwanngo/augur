from datetime import datetime

from augur.simulator.baseline import generate_baseline
from augur.simulator.inject import render_injection, validate_injection
from augur.simulator.timeline import merge


def generate_feed(config, profiles, scenarios, topology, base_time: datetime) -> list[dict]:
    """Benign baseline + validated attack injections (rendered in each host's native OS format), merged."""
    prof_by_host = {p.host: p for p in profiles}
    for inj in config.injections:
        validate_injection(inj, profiles, scenarios, topology)
    baseline = generate_baseline(profiles, config, base_time)
    injected: list[dict] = []
    for inj in config.injections:
        os_family = prof_by_host[inj.host].os_family
        injected.extend(render_injection(inj, scenarios, topology, base_time, os_family=os_family))
    return merge(baseline, injected)
