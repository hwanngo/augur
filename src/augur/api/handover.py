"""Shift-Handover Diff helpers (additive, read-only, deterministic).

Pure diff math for GET /api/handover. Consumes the public detection dicts produced by
windowed_detections and the host-risk rows from compute_host_risk; no engine import, no
persistence, no wall-clock. The engine scoring/matcher path is never touched.

Scope: board diff only (detections + host-risk deltas) over corpus-event-time. Triage
(assign/resolve) lives on the separate wall-clock endpoint GET /api/triage_handover
(see api/triage_handover.py) — the two clocks are deliberately never mixed in one payload.
"""
from augur.alerting.bands import band_for, band_rank
from augur.enums import SEVERITY_RANK, Severity


def _round4(x: float) -> float:
    return round(x, 4)


def _sevrank(sev: str) -> int:
    try:
        return SEVERITY_RANK[Severity(sev)]
    except (KeyError, ValueError):
        return 0


def _detection_delta(sid, name, severity, prior, current, hosts) -> dict:
    band_prior = band_for(prior) if prior is not None else None
    band_current = band_for(current) if current is not None else None
    p = prior if prior is not None else 0.0
    c = current if current is not None else 0.0
    return {
        "scenario_id": sid, "name": name, "severity": severity,
        "proximity_prior": prior, "proximity_current": current,
        "proximity_delta": _round4(c - p),
        "band_prior": band_prior, "band_current": band_current,
        "band_changed": band_prior != band_current,
        "affected_hosts": hosts,
    }


def diff_detections(prior: list[dict], current: list[dict], *, min_proximity: float) -> dict:
    """Classify scenario_ids into new / escalated / decayed / gone (+ unchanged_count).

    Both lists are the public detection dicts from windowed_detections. A scenario is in
    scope when it clears the min_proximity floor in EITHER window (so a decay that drops
    below the floor is still reported as decayed, while a scenario below the floor in both
    windows is dropped entirely). Deterministic, total ordering.
    """
    prior_raw = {d["scenario_id"]: d for d in prior}
    current_raw = {d["scenario_id"]: d for d in current}
    in_scope = {
        sid for sid in prior_raw.keys() | current_raw.keys()
        if (sid in prior_raw and prior_raw[sid]["proximity"] >= min_proximity)
        or (sid in current_raw and current_raw[sid]["proximity"] >= min_proximity)
    }
    prior_by = {sid: d for sid, d in prior_raw.items() if sid in in_scope}
    current_by = {sid: d for sid, d in current_raw.items() if sid in in_scope}

    new, escalated, decayed, gone = [], [], [], []
    unchanged_count = 0

    for sid in current_by.keys() - prior_by.keys():
        d = current_by[sid]
        new.append(_detection_delta(sid, d["name"], d["severity"], None,
                                    _round4(d["proximity"]), d.get("affected_hosts", [])))
    for sid in prior_by.keys() - current_by.keys():
        d = prior_by[sid]
        gone.append(_detection_delta(sid, d["name"], d["severity"], _round4(d["proximity"]),
                                     None, d.get("affected_hosts", [])))
    for sid in prior_by.keys() & current_by.keys():
        p = _round4(prior_by[sid]["proximity"])
        c = _round4(current_by[sid]["proximity"])
        cur = current_by[sid]
        delta = _round4(c - p)
        band_up = band_rank(band_for(c)) > band_rank(band_for(p))
        band_down = band_rank(band_for(c)) < band_rank(band_for(p))
        if delta > 0 or band_up:
            escalated.append(_detection_delta(sid, cur["name"], cur["severity"], p, c,
                                              cur.get("affected_hosts", [])))
        elif delta < 0 or band_down:
            decayed.append(_detection_delta(sid, cur["name"], cur["severity"], p, c,
                                            cur.get("affected_hosts", [])))
        else:
            unchanged_count += 1

    escalated.sort(key=lambda d: (-abs(d["proximity_delta"]), -_sevrank(d["severity"]), d["scenario_id"]))
    decayed.sort(key=lambda d: (-abs(d["proximity_delta"]), -_sevrank(d["severity"]), d["scenario_id"]))
    new.sort(key=lambda d: (-d["proximity_current"], -_sevrank(d["severity"]), d["scenario_id"]))
    gone.sort(key=lambda d: (-d["proximity_prior"], d["scenario_id"]))
    return {"new": new, "escalated": escalated, "decayed": decayed,
            "gone": gone, "unchanged_count": unchanged_count}


def _host_delta(name, zone, crit, score_prior, score_current, band_prior, band_current) -> dict:
    return {"hostname": name, "zone": zone, "criticality": crit,
            "score_prior": score_prior, "score_current": score_current,
            "score_delta": _round4(score_current - score_prior),
            "band_prior": band_prior, "band_current": band_current}


def diff_hosts(prior_rows: list[dict], current_rows: list[dict]) -> dict:
    """Diff two compute_host_risk row lists. "On the board" == band != CLEAR (score > 0).

    Returns entered / left / escalated / deescalated, each deterministically ordered.
    """
    prior_by = {r["hostname"].lower(): r for r in prior_rows}
    current_by = {r["hostname"].lower(): r for r in current_rows}
    entered, left, escalated, deescalated = [], [], [], []

    for key in prior_by.keys() | current_by.keys():
        p = prior_by.get(key)
        c = current_by.get(key)
        sp = p["score"] if p else 0.0
        sc = c["score"] if c else 0.0
        on_prior = bool(p) and p["band"] != "CLEAR"
        on_current = bool(c) and c["band"] != "CLEAR"
        meta = c or p
        delta = _host_delta(meta["hostname"], meta["zone"], meta["criticality"], sp, sc,
                            p["band"] if p else "CLEAR", c["band"] if c else "CLEAR")
        if on_current and not on_prior:
            entered.append(delta)
        elif on_prior and not on_current:
            left.append(delta)
        elif on_prior and on_current and sc > sp:
            escalated.append(delta)
        elif on_prior and on_current and sc < sp:
            deescalated.append(delta)

    entered.sort(key=lambda h: (-h["score_current"], h["hostname"]))
    left.sort(key=lambda h: (-h["score_prior"], h["hostname"]))
    escalated.sort(key=lambda h: (-abs(h["score_delta"]), h["hostname"]))
    deescalated.sort(key=lambda h: (-abs(h["score_delta"]), h["hostname"]))
    return {"entered": entered, "left": left,
            "escalated": escalated, "deescalated": deescalated}


def build_handover(prior_dets, current_dets, prior_hosts, current_hosts, *,
                   from_iso: str, to_iso: str, min_proximity: float) -> dict:
    """Assemble the v1 HandoverDiff payload (board diff only; no triage).

    prior/current_dets:  public detection dicts at to=from_iso and to=to_iso.
    prior/current_hosts: compute_host_risk rows for the same two windows.
    """
    det = diff_detections(prior_dets, current_dets, min_proximity=min_proximity)
    hosts = diff_hosts(prior_hosts, current_hosts)
    counts = {
        "new": len(det["new"]), "escalated": len(det["escalated"]),
        "decayed": len(det["decayed"]), "gone": len(det["gone"]),
        "unchanged": det["unchanged_count"],
        "hosts_entered": len(hosts["entered"]), "hosts_left": len(hosts["left"]),
        "hosts_escalated": len(hosts["escalated"]), "hosts_deescalated": len(hosts["deescalated"]),
    }
    return {
        "window": {"from": from_iso, "to": to_iso},
        "meta": {"min_proximity": min_proximity, "basis": "corpus-windowed", "deterministic": True},
        "detections": det,
        "host_risk": hosts,
        "summary": {"counts": counts},
    }
