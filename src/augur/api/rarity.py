"""Rarity / Frequency-Stacking — deterministic least-frequency-of-occurrence ("stacking") over the feed.

Pure counting. One read-only pass over read_jsonl -> normalize_events (the ioc.py / timeline.py loader),
bucket-count per dimension on process_create events only, rank rarest-first, cap to the long tail, enrich
hosts via topology.enrich. No engine import, no scoring, no now(), no randomness, no ML.

A rare value is a LEAD for triage, NEVER a detection or verdict — most rare activity is benign. Counts are
over THIS loaded corpus only; "first seen" means first in this data, not first ever.
"""
from augur.api.feed import load_normalized

DIMENSIONS = ("process", "parent_child", "host_binary")
MAX_RESULTS = 500
MAX_COUNT_CAP = 50
MAX_HOSTS_PER_ROW = 25
MAX_SAMPLES_PER_ROW = 5
_SNIPPET_MAX = 200

HONESTY_NOTE = (
    "Rarity is a LEAD for triage, not a detection or verdict. Most rare activity is benign — admin tools, "
    "one-off installs, a single legitimate script. These rows are starting points for a hunt, not findings. "
    "Counts are over this loaded corpus only: \"first seen\" means first in this data, not first ever. A rare "
    "value on a CRITICAL host is a stronger lead but still needs human triage. No scoring, no ML, no "
    "probability — just occurrence counts."
)


def process_frequency_index(log_paths) -> dict:
    """casefolded process_name -> {name, occurrences, host_count, single_host, first_seen, last_seen}.

    One read-only pass over process_create events — the same counting as compute_rarity but keyed by
    process and NOT filtered to the rare tail, so a specific process's frequency can be looked up
    (common OR rare). Powers the FP-tuning propose baseline hint: advisory only, never a verdict.
    """
    occ: dict = {}
    hosts: dict = {}
    first: dict = {}
    last: dict = {}
    disp: dict = {}
    for ev in load_normalized(log_paths):
        if ev.kind != "process_create" or not ev.process_name:
            continue
        k = ev.process_name.casefold()
        ts = ev.timestamp.isoformat()
        occ[k] = occ.get(k, 0) + 1
        disp.setdefault(k, ev.process_name)
        hosts.setdefault(k, set()).add(ev.host)
        if k not in first or ts < first[k]:
            first[k] = ts
        if k not in last or ts > last[k]:
            last[k] = ts
    return {k: {"name": disp[k], "occurrences": occ[k], "host_count": len(hosts[k]),
                "single_host": len(hosts[k]) == 1, "first_seen": first[k], "last_seen": last[k]}
            for k in occ}


def _key(dimension: str, ev):
    """Return (bucket_key, display_value) for the event, or None to skip (missing field / non-process)."""
    pname = ev.process_name
    if not pname:
        return None
    pcf = pname.casefold()
    if dimension == "process":
        return (pcf, pcf)
    if dimension == "parent_child":
        parent = ev.parent_process_name
        if not parent:
            return None
        kp = parent.casefold()
        return ((kp, pcf), f"{kp} → {pcf}")
    if dimension == "host_binary":
        # The bucket is the binary; spread = distinct hosts it touched.
        return (pcf, pcf)
    raise ValueError(f"unknown dimension: {dimension!r}")


def compute_rarity(dimension: str, log_paths, topology, *,
                   max_count: int = 5, limit: int = 100) -> dict:
    if dimension not in DIMENSIONS:
        raise ValueError(f"unknown dimension: {dimension!r}; allowed: {', '.join(DIMENSIONS)}")

    # Per-bucket accumulators.
    occ: dict = {}                       # key -> occurrences
    display: dict = {}                   # key -> display value
    hosts: dict = {}                     # key -> {hostname -> count}
    first: dict = {}                     # key -> min iso
    last: dict = {}                      # key -> max iso
    samples: dict = {}                   # key -> list[(ts_iso, host, cmd)]

    for ev in load_normalized(log_paths):
        if ev.kind != "process_create":
            continue
        keyed = _key(dimension, ev)
        if keyed is None:
            continue
        k, disp = keyed
        ts = ev.timestamp.isoformat()
        occ[k] = occ.get(k, 0) + 1
        display.setdefault(k, disp)
        hc = hosts.setdefault(k, {})
        hc[ev.host] = hc.get(ev.host, 0) + 1
        if k not in first or ts < first[k]:
            first[k] = ts
        if k not in last or ts > last[k]:
            last[k] = ts
        cmd = (ev.command_line or "")[:_SNIPPET_MAX]
        samples.setdefault(k, []).append((ts, ev.host, cmd))

    total_values = len(occ)

    # Build candidate rows past the rarity threshold.
    rare_keys = [k for k in occ if occ[k] <= max_count]
    rare_count = len(rare_keys)

    if dimension == "host_binary":
        sort_key = lambda k: (len(hosts[k]), occ[k], display[k])
    else:
        sort_key = lambda k: (occ[k], len(hosts[k]), display[k])
    rare_keys.sort(key=sort_key)

    returned_keys = rare_keys[:limit]

    rows = []
    for k in returned_keys:
        hc = hosts[k]
        host_rows = []
        for hn in sorted(hc, key=lambda h: (-hc[h], h))[:MAX_HOSTS_PER_ROW]:
            zone, crit = topology.enrich(hn)
            host_rows.append({"hostname": hn, "zone": zone.value,
                              "criticality": crit.value, "count": hc[hn]})
        sample_rows = [
            {"host": h, "timestamp": ts, "command": cmd}
            for (ts, h, cmd) in sorted(samples[k])[:MAX_SAMPLES_PER_ROW]
        ]
        rows.append({
            "value": display[k],
            "occurrences": occ[k],
            "host_count": len(hc),
            "single_host": len(hc) == 1,
            "unique": occ[k] == 1,
            "first_seen": first[k],
            "last_seen": last[k],
            "hosts": host_rows,
            "hosts_truncated": len(hc) > MAX_HOSTS_PER_ROW,
            "samples": sample_rows,
            "samples_truncated": len(samples[k]) > MAX_SAMPLES_PER_ROW,
        })

    return {
        "dimension": dimension,
        "params": {"max_count": max_count, "limit": limit},
        "summary": {
            "total_values": total_values,
            "rare_values": rare_count,
            "returned": len(rows),
            "truncated": rare_count > len(rows),
            "honesty_note": HONESTY_NOTE,
        },
        "rows": rows,
    }
