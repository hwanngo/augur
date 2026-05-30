"""Pure trace mutators for detection-robustness validation.

Each function transforms the raw ``list[dict]`` produced by
``generative.synth.synthesize_trace`` and returns a NEW list — the input is never
mutated. NO engine import, NO ``datetime.now``, NO ``random``: these are
deterministic, side-effect-free transforms (Invariant 1 / purity).

Step membership is keyed on the synth's own tag: every event realizing step ``k``
(1-based) carries ``process_guid == f"syn-p{k}"`` and a shared timestamp. This is
the synth's construction contract — the same events that make the scenario fire at
proximity 1.0 in ``metrics/detectability.py``.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta

from augur.enums import Criticality
from augur.scenarios.schema import Scenario
from augur.topology.network import Topology


def _step_guid(step_id: int) -> str:
    return f"syn-p{step_id}"


def _validate_step_id(scenario: Scenario, step_id: int) -> None:
    if step_id < 1 or step_id > scenario.step_count:
        raise ValueError(
            f"step_id {step_id} out of range 1..{scenario.step_count} "
            f"for {scenario.scenario_id}"
        )


def drop_step(trace: list[dict], scenario: Scenario, step_id: int) -> list[dict]:
    """Return a copy of ``trace`` with every event realizing ``step_id`` removed.

    Pure; preserves order and all other events. Raises ``ValueError`` on a step_id
    outside ``1..step_count``.
    """
    _validate_step_id(scenario, step_id)
    guid = _step_guid(step_id)
    return [copy.deepcopy(e) for e in trace if e.get("process_guid") != guid]


def stretch_temporal(trace: list[dict], scenario: Scenario, step_id: int) -> list[dict]:
    """Shift events of ``step_id``..end forward so step ``step_id`` lands exactly one
    second past its ``temporal_link.max_time_delta_seconds`` relative to step
    ``step_id-1``.

    ``step_id`` must be >= 2 (step 1 has no temporal_link). Pure; deterministic
    offset. The matched prefix the engine produces is therefore ``step_id-1``.
    """
    _validate_step_id(scenario, step_id)
    if step_id < 2:
        raise ValueError("stretch_temporal requires step_id >= 2 (step 1 has no temporal_link)")

    step = scenario.attack_sequence_flow.steps[step_id - 1]
    max_delta = step.temporal_link.max_time_delta_seconds

    prev_guid = _step_guid(step_id - 1)
    cur_guid = _step_guid(step_id)

    prev_ts = _first_ts(trace, prev_guid)
    cur_ts = _first_ts(trace, cur_guid)
    if prev_ts is None or cur_ts is None:
        # Defensive: synth contract guarantees both exist; if not, leave unchanged.
        return [copy.deepcopy(e) for e in trace]

    # Target timestamp for step k: prev + (max_delta + 1) seconds (overshoot by 1s).
    target_ts = prev_ts + timedelta(seconds=max_delta + 1)
    shift = target_ts - cur_ts  # how much to push step_id..end forward

    shifted_guids = {_step_guid(sid) for sid in range(step_id, scenario.step_count + 1)}

    out: list[dict] = []
    for e in trace:
        e2 = copy.deepcopy(e)
        if e.get("process_guid") in shifted_guids:
            ts = datetime.fromisoformat(e2["timestamp"])
            e2["timestamp"] = (ts + shift).isoformat()
        out.append(e2)
    return out


def relocate_zone(
    trace: list[dict], scenario: Scenario, topology: Topology
) -> tuple[list[dict], str | None]:
    """Retarget every event's host to a deterministically chosen topology host whose
    zone is NOT in ``scenario.spatial_constraints.applicable_zones``.

    Returns ``(mutated_trace, host)`` or ``(copied_trace, None)`` when no off-zone
    host exists (caller records ``status='no_offzone_host'``). Pure.
    """
    applicable = set(scenario.spatial_constraints.applicable_zones)
    # Deterministic choice: first off-zone asset in topology order (stable sort by hostname).
    off_zone = sorted(
        (a for a in topology.assets if a.zone.value not in applicable),
        key=lambda a: a.hostname,
    )
    if not off_zone:
        return [copy.deepcopy(e) for e in trace], None
    target = off_zone[0].hostname

    out: list[dict] = []
    for e in trace:
        e2 = copy.deepcopy(e)
        e2["host"] = target
        out.append(e2)
    return out, target


def relink_host(
    trace: list[dict], scenario: Scenario, topology: Topology, step_id: int
) -> tuple[list[dict], str | None]:
    """Move every event realizing ``step_id``..end onto a SECOND applicable host
    (``h1``), breaking the ``same_host`` link between step ``step_id-1`` (on ``h0``)
    and step ``step_id`` (on ``h1``).

    ``step_id`` must be >= 2 (step 1 is the anchor — there is no prior link to break).
    Returns ``(mutated_trace, h1)`` or ``(copied_trace, None)`` when no distinct
    second eligible host exists (caller records ``status='no_distinct_host'``).

    Both ``h0`` and ``h1`` are inside ``applicable_zones`` and meet
    ``critical_assets_only`` (reusing the synth's eligibility filter), so the
    relocated candidates still clear ``_spatial_ok`` — the ONLY gate that can reject
    is ``_link_ok``. Pure; deterministic.
    """
    _validate_step_id(scenario, step_id)
    if step_id < 2:
        raise ValueError("relink_host requires step_id >= 2 (step 1 is the anchor)")

    sc = scenario.spatial_constraints
    # Eligibility filter copied (import-free) from synth._pick_hosts: applicable
    # zone ∩ criticality. Topology order (NOT sorted) so h0/h1 match the synth's
    # own pair (`_pick_hosts` uses `ok[:2]`): the synth emits the base trace on
    # h0, so relinking step k..end to h1 (the synth's distinct second host) is
    # GUARANTEED to straddle h0/h1 and break the same_host link. Deterministic.
    eligible: list[str] = []
    for a in topology.assets:
        if (
            a.zone.value in sc.applicable_zones
            and (not sc.critical_assets_only or a.criticality == Criticality.CRITICAL)
            and a.hostname not in eligible
        ):
            eligible.append(a.hostname)
    if len(eligible) < 2:
        return [copy.deepcopy(e) for e in trace], None
    h1 = eligible[1]

    relinked_guids = {_step_guid(sid) for sid in range(step_id, scenario.step_count + 1)}

    out: list[dict] = []
    for e in trace:
        e2 = copy.deepcopy(e)
        if e.get("process_guid") in relinked_guids:
            e2["host"] = h1
        out.append(e2)
    return out, h1


def _first_ts(trace: list[dict], guid: str) -> datetime | None:
    for e in trace:
        if e.get("process_guid") == guid:
            return datetime.fromisoformat(e["timestamp"])
    return None
