"""Case Timeline — deterministic, read-only reconstruction of a detection's event narrative.

Matched scenario steps (from the cached detection's matched_steps backbone — no engine re-run) interleaved
with surrounding context events on the affected host(s), within an absolute band derived from the matched
timestamps. Re-reads the static feed via the established read_jsonl -> normalize_events path (like
windowed_detections); no engine import, no scoring, no persistence. The timeline is the literal ordered real
events — context rows are NOT necessarily attack-related (only matched rows are engine-tied).

Dedup edge: a context row is suppressed when it shares a matched step's exact (host, timestamp) — so a
matched event isn't duplicated as context. A genuinely-distinct context event landing at a matched step's
exact second on the same host is also suppressed (rare at 1s granularity; the matched row is authoritative).
"""
from datetime import datetime, timedelta, timezone

from augur.api.feed import load_normalized

PAD_SECONDS = 300
MAX_CONTEXT = 500
HONESTY_NOTE = (
    "Context events are simply all normalized events on the affected host(s) within the time band — shown "
    "for situational awareness, not necessarily related to the attack. Only the matched-step rows are events "
    "the engine tied to the scenario."
)


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)


def _label(ev) -> tuple[str, str]:
    k = ev.kind
    if k == "process_create":
        return k, ev.process_name or k
    if k == "image_load":
        return k, ev.image_loaded or k
    if k == "behavior":
        return k, (f"{ev.behavior} → {ev.target}" if ev.target else (ev.behavior or k))
    return k, k


def _sort_key(row: dict) -> tuple:
    return (row["timestamp"], row["host"], row["event_kind"], row["label"],
            row.get("_cmd") or "", row.get("element_id") or "")


def build_case_timeline(detection: dict, log_paths, topology, *, host=None, frm=None, to=None) -> dict:
    affected = detection["affected_hosts"]
    if host is not None:
        if host not in affected:
            raise ValueError(f"host {host!r} not in affected_hosts")
        hosts = [host]
    else:
        hosts = list(affected)
    hosts_lower = {h.lower() for h in hosts}

    matched_rows, matched_ts = [], []
    for st in detection["matched_steps"]:
        ts, h = st.get("timestamp"), st.get("host")
        if ts is None or h is None or h.lower() not in hosts_lower:
            continue
        matched_ts.append(ts)
        matched_rows.append({"timestamp": ts, "host": h, "kind": "matched_step", "event_kind": "matched",
                             "label": st["name"], "step_id": st["step_id"], "step_name": st["name"],
                             "element_id": st.get("element_id"), "_cmd": ""})

    if matched_ts:
        lo_dt = min(_aware(datetime.fromisoformat(t)) for t in matched_ts) - timedelta(seconds=PAD_SECONDS)
        hi_dt = max(_aware(datetime.fromisoformat(t)) for t in matched_ts) + timedelta(seconds=PAD_SECONDS)
    else:
        lo_dt = datetime(1970, 1, 1, tzinfo=timezone.utc)
        hi_dt = datetime(9999, 12, 31, tzinfo=timezone.utc)
    if frm is not None:
        lo_dt = _aware(frm)
    if to is not None:
        hi_dt = _aware(to)

    matched_keys = {(r["host"].lower(), r["timestamp"]) for r in matched_rows}
    context_rows = []
    for ev in load_normalized(log_paths):
        evt = _aware(ev.timestamp)
        if ev.host.lower() not in hosts_lower or not (lo_dt <= evt <= hi_dt):
            continue
        ts_iso = evt.isoformat()
        if (ev.host.lower(), ts_iso) in matched_keys:
            continue
        ek, lab = _label(ev)
        context_rows.append({"timestamp": ts_iso, "host": ev.host, "kind": "context", "event_kind": ek,
                             "label": lab, "step_id": None, "step_name": None, "element_id": None,
                             "_cmd": ev.command_line or ""})

    context_total = len(context_rows)
    context_rows.sort(key=_sort_key)
    context_truncated = context_total > MAX_CONTEXT
    context_rows = context_rows[:MAX_CONTEXT]

    rows = sorted(matched_rows + context_rows, key=_sort_key)
    for r in rows:
        r.pop("_cmd", None)
    return {
        "scenario_id": detection["scenario_id"], "name": detection["name"], "severity": detection["severity"],
        "hosts": hosts,
        "band": {"from": lo_dt.isoformat(), "to": hi_dt.isoformat(), "pad_seconds": PAD_SECONDS},
        "rows": rows, "matched_count": len(matched_rows),
        "context_shown": len(context_rows), "context_total": context_total,
        "context_truncated": context_truncated, "honesty_note": HONESTY_NOTE,
    }
