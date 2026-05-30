"""IOC / Threat-Intel Overlay — match an external watchlist against the loaded telemetry.

Read-only, deterministic. Reuses read_jsonl -> normalize_events (like timeline). Matches IOC types the
data can actually carry: process_name (exact), image (substring), command (substring), hash
(case-insensitive, any algo), and domain (exact, case-insensitive) against the NormalizedEvent fields,
and technique against the scenario library + cached detections. ip is matched (exact string) against
NormalizedEvent.dest_ip in the (synthetic) Windows network-connection telemetry (Sysmon EID 3), which uses
RFC 5737 documentation ranges. ipv6/CIDR stay rejected (v1 is exact v4 match only). DNS + dest-IP
telemetry now exists on all three OSes — native on Windows (Sysmon) and the Linux auditd connect(2)
syscall, and as an explicit agent/EDR overlay for Linux DNS and macOS DNS/connections (Increment 4).
All synthetic/deterministic, not a real-world reputation claim. No engine import, no persistence.
"""
import ipaddress

from augur.api.feed import load_normalized

MAX_IOCS = 256
MAX_HITS_PER_IOC = 200
_EVENT_TYPES = ("process_name", "image", "command", "hash", "domain", "ip", "cidr", "ipv6")
_UNMATCHABLE: dict[str, str] = {}
HONESTY_NOTE = (
    "Only process/image/command/hash/domain/ip/cidr/ipv6/technique indicators are evaluated against this "
    "endpoint telemetry. Hash IOCs are matched against file hashes, domain IOCs against queried domains in "
    "the (synthetic) DNS-query telemetry, and IP / CIDR / IPv6 IOCs against destination IPs in the "
    "(synthetic) network-connection telemetry — IPv4 uses RFC 5737 documentation ranges and IPv6 uses the "
    "RFC 3849 2001:db8::/32 documentation range, both IANA-reserved so they can never collide with "
    "real-world addresses; a match validates the hunting pipeline, not real-world prevalence. CIDR IOCs are "
    "tested for network membership and IPv6 IOCs are compared in canonical (compressed) form. DNS and "
    "connection telemetry exists on Windows, Linux, and macOS: native on Windows (Sysmon) and the Linux "
    "auditd connect(2) syscall, and as an explicit agent/EDR overlay for Linux DNS and macOS DNS/connections "
    "(auditd does not resolve DNS and stable ESF has no DNS/socket NOTIFY) — never claimed as more than the "
    "source genuinely carries. dest_port is context-only (not an IOC). Technique IOCs match the scenario "
    "library + detections, not raw events."
)
# Under a REAL captured feed (e.g. OTRF), Sysmon EID-3 destination IPs are real observed addresses, NOT
# synthetic RFC 5737 documentation ranges. Swap the synthetic-IP clause for an honest real-telemetry one.
HONESTY_NOTE_REAL = (
    "Only process/image/command/hash/domain/ip/cidr/ipv6/technique indicators are evaluated against this "
    "endpoint telemetry. This feed contains REAL captured telemetry; destination IPs are real observed "
    "addresses, not documentation ranges, so an IP/CIDR/IPv6 match reflects genuine captured network "
    "activity. Hash IOCs are matched against file hashes and domain IOCs against queried domains. "
    "dest_port is context-only (not an IOC). Technique IOCs match the scenario library + detections, not "
    "raw events."
)


def _label(ev) -> str:
    if ev.kind == "process_create":
        return ev.process_name or ev.kind
    if ev.kind == "image_load":
        return ev.image_loaded or ev.kind
    if ev.kind == "behavior":
        return (f"{ev.behavior} → {ev.target}" if ev.target else (ev.behavior or ev.kind))
    return ev.kind


def _validate(iocs: list) -> list:
    if not iocs:
        raise ValueError("watchlist is empty")
    if len(iocs) > MAX_IOCS:
        raise ValueError(f"watchlist exceeds {MAX_IOCS}-IOC cap ({len(iocs)})")
    seen, out = set(), []
    for it in iocs:
        typ, val = it.get("type"), it.get("value")
        if typ in _UNMATCHABLE:
            raise ValueError(f"IOC type {typ!r} is not evaluated: {_UNMATCHABLE[typ]}")
        if typ not in _EVENT_TYPES and typ != "technique":
            raise ValueError(f"unknown IOC type: {typ!r}")
        if not val or not str(val).strip():
            raise ValueError(f"empty value for {typ!r} IOC")
        key = (typ, val.casefold())
        if key not in seen:
            seen.add(key)
            out.append({"type": typ, "value": val})
    return out


def _event_hit(ev, typ: str, val_cf: str, net=None):
    if typ == "process_name":
        name = ev.process_name or ""
        return ("process_name", name) if name.casefold() == val_cf else None
    if typ == "image":
        for fld, v in (("image_loaded", ev.image_loaded), ("process_path", ev.process_path)):
            if v and val_cf in v.casefold():
                return (fld, v)
        return None
    if typ == "command":
        c = ev.command_line or ""
        return ("command_line", c) if val_cf in c.casefold() else None
    if typ == "hash":
        for algo, digest in (ev.hashes or {}).items():
            if digest and digest.casefold() == val_cf:
                return (algo, digest)
        return None
    if typ == "domain":
        d = ev.domain or ""
        return ("domain", d) if d.casefold() == val_cf else None
    if typ == "ip":
        d = ev.dest_ip or ""
        return ("dest_ip", d) if d.casefold() == val_cf else None
    if typ == "cidr":
        if not ev.dest_ip:
            return None
        try:
            addr = ipaddress.ip_address(ev.dest_ip)
        except ValueError:
            return None
        if addr.version != net.version:
            return None
        return ("dest_ip", ev.dest_ip) if addr in net else None
    if typ == "ipv6":
        if not ev.dest_ip:
            return None
        try:
            ev_canon = ipaddress.ip_address(ev.dest_ip).compressed
        except ValueError:
            return None
        return ("dest_ip", ev.dest_ip) if ev_canon == val_cf else None
    return None


def match_iocs(iocs: list, log_paths, scenarios, topology, detections, real_data: bool = False) -> dict:
    resolved = _validate(iocs)
    event_iocs = [i for i in resolved if i["type"] in _EVENT_TYPES]
    technique_iocs = [i for i in resolved if i["type"] == "technique"]

    counts = {(i["type"], i["value"]): 0 for i in event_iocs}
    hits = {(i["type"], i["value"]): [] for i in event_iocs}
    host_iocs: dict[str, set] = {}

    if event_iocs:
        cf = {(i["type"], i["value"]): (ipaddress.ip_address(i["value"]).compressed
                                        if i["type"] == "ipv6" else i["value"].casefold())
              for i in event_iocs}
        nets = {(i["type"], i["value"]): ipaddress.ip_network(i["value"], strict=False)
                for i in event_iocs if i["type"] == "cidr"}
        for ev in load_normalized(log_paths):
            ts = ev.timestamp.isoformat()
            lab = _label(ev)
            for i in event_iocs:
                k = (i["type"], i["value"])
                got = _event_hit(ev, i["type"], cf[k], nets.get(k))
                if got is None:
                    continue
                mf, snip = got
                counts[k] += 1
                if len(hits[k]) < MAX_HITS_PER_IOC:
                    hits[k].append({"host": ev.host, "timestamp": ts, "label": lab,
                                    "matched_field": mf, "snippet": snip})
                host_iocs.setdefault(ev.host, set()).add(k)

    ioc_results = []
    for i in event_iocs:
        k = (i["type"], i["value"])
        srt = sorted(hits[k], key=lambda h: (h["timestamp"], h["host"], h["matched_field"], h["snippet"]))
        ioc_results.append({"type": i["type"], "value": i["value"], "target": "event",
                            "matched": counts[k] > 0, "hit_count": counts[k],
                            "hits": srt, "truncated": counts[k] > len(srt)})

    det_by_scen = {}
    for d in detections:
        det_by_scen.setdefault(d["scenario_id"], d)
    scen_techs: dict[str, list] = {}
    for s in scenarios:
        for m in s.scenario_metadata.mitre_mappings:
            scen_techs.setdefault(m.technique, []).append(s.scenario_id)
    for i in technique_iocs:
        T = i["value"]
        covered = sorted(set(scen_techs.get(T, [])))
        fired = []
        for sid in covered:
            d = det_by_scen.get(sid)
            if d and d["proximity"] > 0:
                fired.append({"scenario_id": sid, "name": d["name"], "proximity": d["proximity"],
                              "affected_hosts": d["affected_hosts"]})
                for h in d["affected_hosts"]:
                    host_iocs.setdefault(h, set()).add(("technique", T))
        ioc_results.append({"type": "technique", "value": T, "target": "scenario",
                            "matched": len(fired) > 0, "hit_count": len(fired),
                            "covered": bool(covered), "covered_scenarios": covered,
                            "hits": fired, "truncated": False})

    hosts = []
    for h in sorted(host_iocs):
        zone, crit = topology.enrich(h)
        keys = host_iocs[h]
        hosts.append({"hostname": h, "zone": zone.value, "criticality": crit.value,
                      "ioc_count": len(keys), "types": sorted({t for (t, v) in keys})})
    hosts.sort(key=lambda r: (-r["ioc_count"], r["hostname"]))

    return {
        "summary": {"iocs_total": len(resolved),
                    "iocs_matched": sum(1 for r in ioc_results if r["matched"]),
                    "hosts_touched": len(hosts),
                    "honesty_note": HONESTY_NOTE_REAL if real_data else HONESTY_NOTE},
        "iocs": ioc_results, "hosts": hosts,
    }
