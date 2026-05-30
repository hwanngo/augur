"""Triage-Handover helpers (additive, read-only, deterministic).

Pure partition of persisted alert lifecycle data into "what the team did this shift" buckets over an
explicit WALL-CLOCK window. Distinct from the corpus-event-time board diff in handover.py — the two
clocks are never mixed in one payload (meta.basis names this one "alert-lifecycle-wallclock"). No engine
import, no scoring touch.
"""

_TERMINAL = {"resolved", "closed"}
_NONTERMINAL = {"open", "acknowledged", "in_progress"}


def _row(a, ts: str, ts_field: str) -> dict:
    return {"alert_id": a.id, "scenario_id": a.scenario_id, "scenario_name": a.scenario_name,
            "severity": a.severity, "assignee": a.assignee, "status": a.status,
            "ts": ts, "ts_field": ts_field}


def _event_status(e) -> str | None:
    """Map an AlertEvent to the workflow status it represents (or None if irrelevant).

    Full alert-event vocabulary (sources: store.set_status/set_state, evaluator):
      "status"        manual workflow → detail "<status>" or "<status> — <note>"  → that status
      "resolved"      legacy set_state(resolved)                                   → resolved (terminal)
      "auto_resolved" engine auto-resolve (evaluator; sets state=resolved)         → resolved (terminal)
      "reopened"      legacy set_state(open) / engine reappearance-after-resolve   → open (non-terminal)
      "ack"           legacy set_state(acknowledged)                               → acknowledged
      "created", "escalated", "assigned", "comment"                                → None (not a transition)
    """
    if e.event == "status":                       # set_status: detail = "<status>" or "<status> — <note>"
        return e.detail.split(" — ")[0].strip()
    if e.event in ("resolved", "auto_resolved"):  # legacy set_state(resolved) / engine auto-resolve (terminal)
        return "resolved"
    if e.event == "reopened":                     # legacy set_state(open) / engine reappearance (non-terminal)
        return "open"
    if e.event == "ack":                          # legacy set_state(acknowledged)
        return "acknowledged"
    return None


def diff_triage(alerts: list, events_by_alert: dict, *, frm: str, to: str) -> dict:
    """Partition alerts into new_alerts / assigned / resolved / reopened over the window [frm, to].

    alerts: list[Alert]; events_by_alert: {alert_id: list[AlertEvent]} (chronological). All timestamps
    are ISO-8601 with a uniform +00:00 offset, so lexicographic == chronological. Window inclusive.
    """
    def in_window(ts: str) -> bool:
        return ts != "" and frm <= ts <= to

    new_alerts, assigned, resolved, reopened = [], [], [], []
    for a in alerts:
        if in_window(a.created_at):
            new_alerts.append(_row(a, a.created_at, "created_at"))
        if in_window(a.assigned_at):
            assigned.append(_row(a, a.assigned_at, "assigned_at"))
        if in_window(a.resolved_at):
            resolved.append(_row(a, a.resolved_at, "resolved_at"))
        was_terminal = False
        for e in sorted(events_by_alert.get(a.id, []), key=lambda e: (e.ts, e.id)):
            st = _event_status(e)
            if st in _TERMINAL:
                was_terminal = True
            elif st in _NONTERMINAL:
                if was_terminal and in_window(e.ts):
                    reopened.append(_row(a, e.ts, "reopened"))
                was_terminal = False

    for bucket in (new_alerts, assigned, resolved, reopened):
        bucket.sort(key=lambda r: (r["ts"], r["alert_id"]))
    return {"new_alerts": new_alerts, "assigned": assigned, "resolved": resolved, "reopened": reopened}


_BUCKETS = ("new_alerts", "assigned", "resolved", "reopened")


def build_triage_handover(alerts: list, events_by_alert: dict, *,
                          from_iso: str | None, to_iso: str | None) -> dict:
    """Assemble the triage-handover payload. Empty window (None bounds, e.g. empty store) yields a
    structurally-identical all-empty payload."""
    if from_iso is None or to_iso is None:
        triage = {k: [] for k in _BUCKETS}
    else:
        triage = diff_triage(alerts, events_by_alert, frm=from_iso, to=to_iso)
    return {
        "window": {"from": from_iso, "to": to_iso},
        "meta": {"basis": "alert-lifecycle-wallclock", "deterministic": True},
        "triage": triage,
        "summary": {"counts": {k: len(triage[k]) for k in _BUCKETS}},
    }
