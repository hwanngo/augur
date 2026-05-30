"""The pure FP-tuning core: apply allowlist policy to a list of detections.

Operates on PUBLIC detection dicts (the `/api/detections` shape) so the same function serves both
human-facing call sites: the dashboard serve path (native dicts) and the alerting scan path (which
derives the same dicts from its `Detection` objects). It is a pure function of
(detections, active entries [, backend for regex predicates]).

INVARIANTS (gated by tests in test_tuning_apply.py):
  * Empty `entries` -> identity: `kept` is the input list unchanged, all-zero ledger.
  * No wall-clock / randomness here (no `now()`, no `random`, no `uuid`). Time predicates key on
    the detections' own corpus timestamps. Expiry is resolved in the store, never here.
  * No engine import (no run_engine / scoring / matcher / builder / normalize). We read ProcessNode
    *attributes* via the graph backend only when an active entry declares a regex predicate.
  * Suppression is never silent: every muted/downgraded detection is counted and attributed.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime

from augur.alerting.bands import band_for, band_rank
from augur.graph.models import ProcessNode

HONESTY_NOTE = (
    "This view is tuned. Detections shown here were suppressed or downgraded by active allowlist "
    "entries — the engine still detected every one of them; the SOC chose to mute or de-prioritize "
    "them. Each is attributed to the entry and reason that muted it. Nothing is deleted from the "
    "engine; clear the entry to see the raw detection again. Tuning reflects SOC policy over the "
    "live feed, not ground truth."
)


@dataclass
class AllowlistResult:
    kept: list[dict]                      # not suppressed (downgraded rows carry a "band_override" key)
    band_overrides: dict[str, str]        # dedup_key -> overridden band (downgraded detections only)
    suppressed: list[dict]                # SuppressionRecord dicts
    downgraded: list[dict]                # DowngradeRecord dicts
    ledger: dict
    honesty_note: str = HONESTY_NOTE


def dedup_key(det: dict) -> str:
    """Match the alerting evaluator's dedup key: scenario_id + sorted hosts."""
    return det["scenario_id"] + "|" + ",".join(sorted(det.get("affected_hosts", [])))


def _detection_summary(det: dict) -> dict:
    return {"scenario_id": det["scenario_id"], "name": det.get("name", ""),
            "severity": det.get("severity", ""), "proximity": det.get("proximity", 0.0),
            "affected_hosts": list(det.get("affected_hosts", []))}


def _resolve_process_id(element_id: str) -> str:
    # Behavior steps carry a synthetic `f'{proc.id}|EXH|{i}'` element id — resolve to the process.
    return element_id.split("|EXH|")[0] if "|EXH|" in element_id else element_id


def _process_strings(det: dict, backend) -> list[tuple[str, str, str]]:
    """(name, command_line, path) for each matched step's process, via read-only graph access.
    Empty if no backend. A missing/non-process node contributes nothing (we never claim a match
    we cannot substantiate)."""
    if backend is None:
        return []
    out: list[tuple[str, str, str]] = []
    for step in det.get("matched_steps", []):
        eid = step.get("element_id")
        if not eid:
            continue
        node = backend.get_node(_resolve_process_id(eid))
        if isinstance(node, ProcessNode):
            out.append((node.name or "", node.command_line or "", node.path or ""))
    return out


def _det_time_span(det: dict) -> tuple[datetime | None, datetime | None]:
    ts = [s["timestamp"] for s in det.get("matched_steps", []) if s.get("timestamp")]
    if not ts:
        return None, None
    parsed = [datetime.fromisoformat(t) for t in ts]
    return min(parsed), max(parsed)


def _entry_has_regex(e) -> bool:
    return bool(e.process_regex or e.command_regex or e.image_regex)


def _matches(det: dict, e, technique_index: dict, proc_strings: list[tuple[str, str, str]]) -> bool:
    """True iff EVERY present predicate on entry `e` is satisfied (AND). Absent predicates match anything."""
    if e.scenario_id and e.scenario_id != det["scenario_id"]:
        return False
    if e.technique and e.technique not in technique_index.get(det["scenario_id"], set()):
        return False
    if e.host and e.host.casefold() not in {h.casefold() for h in det.get("affected_hosts", [])}:
        return False
    if e.zone and e.zone not in det.get("affected_zones", []):
        return False
    if e.ts_from or e.ts_to:
        first, last = _det_time_span(det)
        if first is None:
            return False  # entry constrains time but the detection has no timestamps -> no match
        if e.ts_from and last < datetime.fromisoformat(e.ts_from):
            return False
        if e.ts_to and first > datetime.fromisoformat(e.ts_to):
            return False
    for pattern, idx in ((e.process_regex, 0), (e.command_regex, 1), (e.image_regex, 2)):
        if not pattern:
            continue
        try:
            rx = re.compile(pattern)
        except re.error:
            return False
        if not any(rx.search(vals[idx]) for vals in proc_strings):
            return False
    return True


def apply_allowlist(detections: list[dict], entries: list,
                    *, backend=None, technique_index: dict[str, set[str]] | None = None) -> AllowlistResult:
    """Apply ACTIVE allowlist entries to detections. Pure: same inputs -> same result."""
    # Identity short-circuit: empty allowlist is a provable no-op.
    if not entries:
        return AllowlistResult(
            kept=detections, band_overrides={}, suppressed=[], downgraded=[],
            ledger={"input_count": len(detections), "kept_count": len(detections),
                    "suppressed_count": 0, "downgraded_count": 0, "active_entry_count": 0,
                    "per_entry": [], "honesty_note": HONESTY_NOTE},
        )

    technique_index = technique_index or {}
    sorted_entries = sorted(entries, key=lambda e: e.id)
    any_regex = any(_entry_has_regex(e) for e in sorted_entries)
    hits: dict[str, int] = {e.id: 0 for e in sorted_entries}

    kept: list[dict] = []
    band_overrides: dict[str, str] = {}
    suppressed: list[dict] = []
    downgraded: list[dict] = []

    for det in detections:
        proc_strings = _process_strings(det, backend) if any_regex else []
        matching = [e for e in sorted_entries if _matches(det, e, technique_index, proc_strings)]
        if not matching:
            kept.append(det)
            continue

        sup = [e for e in matching if e.action == "SUPPRESS"]
        if sup:
            chosen = sup[0]  # lowest id (sorted_entries is id-ordered, matching preserves it)
            hits[chosen.id] += 1
            suppressed.append({**_detection_summary(det), "entry_id": chosen.id,
                               "reason": chosen.reason, "action": "SUPPRESS",
                               "matched_entry_ids": [e.id for e in matching]})
            continue

        # DOWNGRADE-only matches: take the most aggressive (lowest) target band that actually lowers.
        natural = band_for(det.get("proximity", 0.0))
        dn = [e for e in matching if e.action == "DOWNGRADE"]
        # effective band = the lowest rank among (natural, each downgrade target)
        best = chosen = None
        for e in dn:
            target = e.downgrade_to or "WATCH"
            if band_rank(target) < band_rank(natural) and (best is None or band_rank(target) < band_rank(best)):
                best, chosen = target, e
        if chosen is None:
            kept.append(det)  # downgrade target not below natural band -> no-op, keep as-is
            continue
        hits[chosen.id] += 1
        key = dedup_key(det)
        band_overrides[key] = best
        row = {**det, "band_override": best}
        kept.append(row)
        downgraded.append({**_detection_summary(det), "entry_id": chosen.id, "reason": chosen.reason,
                           "from_band": natural, "to_band": best,
                           "matched_entry_ids": [e.id for e in matching]})

    ledger = {
        "input_count": len(detections),
        "kept_count": len(kept),
        "suppressed_count": len(suppressed),
        "downgraded_count": len(downgraded),
        "active_entry_count": len(sorted_entries),
        "per_entry": [{"entry_id": e.id, "action": e.action, "reason": e.reason, "hit_count": hits[e.id]}
                      for e in sorted_entries],
        "honesty_note": HONESTY_NOTE,
    }
    return AllowlistResult(kept=kept, band_overrides=band_overrides, suppressed=suppressed,
                           downgraded=downgraded, ledger=ledger)
