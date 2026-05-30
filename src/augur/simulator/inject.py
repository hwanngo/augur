from datetime import datetime, timedelta

from augur.generative.synth import synthesize_trace
from augur.simulator.emitters import emit
from augur.simulator.intents import EventIntent
from augur.simulator.realism import enrich_intent

_KIND = {1: "process_create", 7: "image_load", "edr": "behavior"}


def _scenario_map(scenarios):
    return {s.scenario_id: s for s in scenarios}


def is_synthesizable(scenario, topology) -> bool:
    """True iff the simulator can render this scenario's positive trace for injection.

    Pure, deterministic (synthesize_trace is deterministic). The robust predicate the drill route
    uses to choose synth-inject vs replay — NOT an id-prefix hack. render_injection keeps its own
    `synthesize_trace(...) is None` guard (defense in depth, unchanged)."""
    return synthesize_trace(scenario, topology) is not None


def validate_injection(inj, profiles, scenarios, topology) -> None:
    """Fail loud if an injection can't fire: unknown scenario/host, OS mismatch, or wrong zone."""
    scen = _scenario_map(scenarios)
    if inj.scenario_id not in scen:
        raise ValueError(f"unknown scenario_id: {inj.scenario_id}")
    prof = {p.host: p for p in profiles}.get(inj.host)
    if prof is None:
        raise ValueError(f"unknown host: {inj.host}")
    scen_os = scen[inj.scenario_id].os_family
    if prof.os_family != scen_os:
        raise ValueError(
            f"scenario {inj.scenario_id} (os_family={scen_os}) cannot be injected onto "
            f"{prof.os_family} host {inj.host}")
    zone, _crit = topology.enrich(inj.host)
    applicable = scen[inj.scenario_id].spatial_constraints.applicable_zones
    if zone.value not in applicable:
        raise ValueError(
            f"host {inj.host} (zone {zone.value}) is not in scenario {inj.scenario_id} "
            f"applicable_zones {applicable}")


def render_injection(inj, scenarios, topology, base_time: datetime, os_family: str = "windows") -> list[dict]:
    """Synthesize the scenario's positive trace, retarget to inj.host, offset to base+start_offset, and
    render each event in the target host's NATIVE OS format via the P2 emitters."""
    scenario = _scenario_map(scenarios)[inj.scenario_id]
    trace = synthesize_trace(scenario, topology)
    if trace is None:
        raise ValueError(f"scenario {inj.scenario_id} is not auto-synthesizable for injection")
    times = [datetime.fromisoformat(e["timestamp"]) for e in trace]
    delta = (base_time + timedelta(seconds=inj.start_offset_seconds)) - min(times)

    guid_to_pid: dict[str, int] = {}
    counter = [100000]  # start well above any baseline pid (baseline max ≈ rate*duration/60 + 1000)

    def pid_for(guid):
        if guid is None:
            return None
        if guid not in guid_to_pid:
            guid_to_pid[guid] = counter[0]
            counter[0] += 1
        return guid_to_pid[guid]

    out: list[dict] = []
    for e in trace:
        kind = _KIND[e["event_id"]]
        ts = datetime.fromisoformat(e["timestamp"]) + delta
        intent = EventIntent(
            kind=kind, host=inj.host, timestamp=ts,
            pid=pid_for(e.get("process_guid")), ppid=pid_for(e.get("parent_process_guid")),
            user=e.get("user"), process_name=e.get("process_name"), process_path=e.get("process_path"),
            command_line=e.get("command_line"), parent_process_name=e.get("parent_process_name"),
            integrity_level=e.get("integrity_level"), image_loaded=e.get("image_loaded"),
            signed=e.get("signed"), is_injected=bool(e.get("is_injected", False)),
            api_hooking_detected=bool(e.get("api_hooking_detected", False)),
            behavior=e.get("behavior"), target=e.get("target"), granted_access=e.get("granted_access"))
        enrich_intent(intent, scenario, os_family)
        out.append(emit(os_family, intent))
    return out
