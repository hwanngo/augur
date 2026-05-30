"""Incident / Campaign Clustering — deterministic connected-components correlation over detections.

HONESTY CONTRACT (verbatim in HONESTY_NOTE, the API payload, and the UI panel): an "incident" is a
deterministic CORRELATION over THIS corpus — detections grouped because they share a host or share a
MITRE technique; corpus-time adjacency is shown as context but never groups detections on its own. It
is NOT a confirmed adversary campaign, NOT a causal attribution, and NOT a network-reachability or
lateral-movement claim. Edges are same-corpus only; temporal adjacency uses corpus time, never
wall-clock. Singletons are honest one-member incidents, not noise that was discarded.

Pure module. Consumes the already-computed public detection dicts (the `_public` shape from
windowed_detections), the scenario library (technique join, identical to ioc.py), and a live
Topology (authoritative zone/criticality). It NEVER imports run_engine / scoring / matcher / any
graph backend / networkx / any normalizer, never reads wall-clock time, and uses no randomness. A
static AST test enforces this.
"""
from datetime import datetime, timezone

# tunables — module constants, documented; deterministic, no env, no now()
TEMPORAL_HORIZON_SECONDS = 3600   # corpus-time gap within which two detections are "adjacent"
MAX_DETECTIONS = 500              # input cap (honest truncation flag if exceeded)
MAX_MEMBERS_LISTED = 50           # per-incident member cap in payload (honest *_truncated flag)

# string-keyed (the public detection dict carries severity as a string, e.g. "HIGH")
SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

HONESTY_NOTE = (
    "An incident is a deterministic CORRELATION over THIS corpus — detections grouped because they "
    "share a host or share a MITRE technique; corpus-time adjacency is shown as context but never "
    "groups detections on its own. It is NOT a confirmed adversary campaign, NOT a causal "
    "attribution, and NOT a network-reachability or lateral-movement claim. Edges are same-corpus "
    "only; temporal adjacency uses corpus time, never wall-clock. Singletons are honest one-member "
    "incidents, not noise that was discarded."
)


def _scenario_technique_map(scenarios) -> dict[str, frozenset[str]]:
    """scenario_id -> frozenset of MITRE techniques (from scenario_metadata.mitre_mappings).

    Identical derivation to ioc.py (m.technique); the library is the source, the engine is never
    consulted. A scenario with no mappings maps to an empty frozenset.
    """
    out: dict[str, frozenset[str]] = {}
    for s in scenarios:
        techs = {m.technique for m in s.scenario_metadata.mitre_mappings}
        out[s.scenario_id] = frozenset(techs)
    return out


def _aware_epoch(ts: str) -> float | None:
    """Parse an ISO timestamp to a UTC epoch float. Naive -> assume-UTC (mirror momentum/_aware).
    Unparsable / None -> None (caller treats as no-timestamp)."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _detection_window(d: dict) -> tuple[float, float]:
    """(first_epoch, last_epoch) of a detection in CORPUS time from matched_steps[].timestamp.

    Empty / all-unparsable -> (inf, -inf) sentinel so the temporal-edge guard skips it (the
    detection is temporally isolated but still eligible for host/technique edges).
    """
    epochs = [e for e in (_aware_epoch(m.get("timestamp")) for m in d.get("matched_steps", []))
              if e is not None]
    if not epochs:
        return (float("inf"), float("-inf"))
    return (min(epochs), max(epochs))


def _temporal_gap(w_a: tuple[float, float], w_b: tuple[float, float]) -> float | None:
    """Corpus-time gap (seconds) between two intervals; overlapping -> 0. Empty window -> None."""
    a0, a1 = w_a
    b0, b1 = w_b
    if a0 == float("inf") or b0 == float("inf"):  # either window empty
        return None
    return max(0.0, max(a0, b0) - min(a1, b1))


def _edges(detections, tech_map) -> dict[frozenset, set]:
    """For every unordered pair (i, j) record the relations that hold. A pair is an EDGE (entry in the
    returned dict, consumed by union-find) iff it shares a host OR a technique. `temporal_adjacency` is
    a LABEL-ONLY signal: it is added to a pair's relations when the two corpus-time windows are within
    TEMPORAL_HORIZON_SECONDS, but it NEVER makes a pair an edge on its own. O(n^2), bounded,
    deterministic."""
    n = len(detections)
    windows = [_detection_window(d) for d in detections]
    host_sets = [set(d.get("affected_hosts", [])) for d in detections]
    edges: dict[frozenset, set] = {}
    for i in range(n):
        for j in range(i + 1, n):
            labels: set[str] = set()
            if host_sets[i] & host_sets[j]:
                labels.add("shared_host")
            ti = tech_map.get(detections[i]["scenario_id"], frozenset())
            tj = tech_map.get(detections[j]["scenario_id"], frozenset())
            if ti & tj:
                labels.add("shared_technique")
            # temporal is a LABEL ONLY — never promotes a pair to an edge by itself
            if labels:                                  # i.e. host or technique already linked them
                gap = _temporal_gap(windows[i], windows[j])
                if gap is not None and gap <= TEMPORAL_HORIZON_SECONDS:
                    labels.add("temporal_adjacency")
                edges[frozenset({i, j})] = labels
    return edges


def _components(n: int, edges: dict[frozenset, set]) -> list[list[int]]:
    """Pure-stdlib union-find over indices 0..n-1. Returns components as ascending index lists,
    the list ordered by each component's minimum index (deterministic)."""
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path-halving
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            # attach larger root index under smaller for determinism
            hi, lo = (ra, rb) if ra > rb else (rb, ra)
            parent[hi] = lo

    for pair in edges:
        a, b = sorted(pair)
        union(a, b)

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)
    comps = [sorted(members) for members in groups.values()]
    comps.sort(key=lambda c: c[0])
    return comps


_REQUIRED_KEYS = ("scenario_id", "severity", "proximity")


def _validate(detections) -> list[dict]:
    if not isinstance(detections, list):
        raise ValueError("detections must be a list")
    for d in detections:
        if not isinstance(d, dict):
            raise ValueError("each detection must be a dict")
        for k in _REQUIRED_KEYS:
            if k not in d:
                raise ValueError(f"detection missing required key: {k!r}")
    return detections


def _iso(epoch: float) -> str | None:
    if epoch in (float("inf"), float("-inf")):
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def cluster_incidents(detections: list[dict], scenarios, topology) -> dict:
    """Top-level. Validates/caps input, builds tech_map, edges, components; emits ranked incidents
    + rollup. ValueError on malformed input (-> 422 at the route). Deterministic total ordering."""
    detections = _validate(detections)

    truncated = len(detections) > MAX_DETECTIONS
    dets = detections[:MAX_DETECTIONS]                 # cap by existing rank order; never drop silently

    tech_map = _scenario_technique_map(scenarios)
    edges = _edges(dets, tech_map)
    comps = _components(len(dets), edges)

    incidents: list[dict] = []
    for members_idx in comps:
        # Order members deterministically by scenario_id so the payload is input-order invariant
        # (corpus index order would otherwise leak the input ordering into members[]).
        members = sorted((dets[i] for i in members_idx), key=lambda m: m["scenario_id"])
        windows = [_detection_window(m) for m in members]
        firsts = [w[0] for w in windows if w[0] != float("inf")]
        lasts = [w[1] for w in windows if w[1] != float("-inf")]
        first_epoch = min(firsts) if firsts else None
        last_epoch = max(lasts) if lasts else None

        # union of hosts (topology-enriched), sorted by hostname
        host_names = sorted({h for m in members for h in m.get("affected_hosts", [])})
        hosts = []
        for h in host_names:
            zone, crit = topology.enrich(h)
            hosts.append({"hostname": h, "zone": zone.value, "criticality": crit.value})

        # union of techniques, sorted
        techniques = sorted({t for m in members
                             for t in tech_map.get(m["scenario_id"], frozenset())})

        # union of edge labels inside this component
        member_set = set(members_idx)
        relation_set: set[str] = set()
        for pair, labels in edges.items():
            if pair <= member_set:
                relation_set |= labels
        relations = sorted(relation_set)

        top_severity = max((m["severity"] for m in members),
                           key=lambda s: SEV_RANK.get(s, 0))
        max_proximity = max(m["proximity"] for m in members)
        score = round(sum(m["proximity"] * SEV_RANK.get(m["severity"], 0) for m in members), 4)

        # member rows (capped, but size is the TRUE count)
        member_rows = [{
            "scenario_id": m["scenario_id"], "name": m.get("name", ""),
            "severity": m["severity"], "proximity": m["proximity"],
            "affected_hosts": list(m.get("affected_hosts", [])),
            "latest_ts": _iso(_detection_window(m)[1]),
        } for m in members[:MAX_MEMBERS_LISTED]]

        incidents.append({
            "size": len(members),
            "members": member_rows,
            "members_truncated": len(members) > MAX_MEMBERS_LISTED,
            "hosts": hosts,
            "techniques": techniques,
            "first_ts": _iso(first_epoch) if first_epoch is not None else None,
            "last_ts": _iso(last_epoch) if last_epoch is not None else None,
            "top_severity": top_severity,
            "max_proximity": max_proximity,
            "score": score,
            "relations": relations,
            "honesty_note": HONESTY_NOTE,
            "_first_epoch": first_epoch if first_epoch is not None else float("inf"),
            "_first_scenario": members[0]["scenario_id"],
        })

    # deterministic total order: (-score, -size, first_ts_or_empty, members[0].scenario_id)
    incidents.sort(key=lambda x: (-x["score"], -x["size"], x["_first_epoch"], x["_first_scenario"]))

    # assign rank-stable ids and strip sort-only keys
    for n, inc in enumerate(incidents, start=1):
        inc["incident_id"] = f"INC-{n:04d}"
        del inc["_first_epoch"]
        del inc["_first_scenario"]

    # re-key so incident_id leads (cosmetic ordering of dict keys is not load-bearing, but keep it tidy)
    ordered = [{"incident_id": inc.pop("incident_id"), **inc} for inc in incidents]

    clustered = sum(inc["size"] for inc in ordered if inc["size"] > 1)
    singletons = sum(1 for inc in ordered if inc["size"] == 1)
    largest = max((inc["size"] for inc in ordered), default=0)

    return {
        "incidents": ordered,
        "rollup": {
            "incidents": len(ordered),
            "clustered_detections": clustered,
            "singletons": singletons,
            "largest_incident_size": largest,
            "detections_total": len(dets),
            "truncated": truncated,
            "honesty_note": HONESTY_NOTE,
        },
    }
