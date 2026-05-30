import random
from datetime import datetime, timedelta

from augur.simulator.emitters import emit
from augur.simulator.intents import EventIntent
from augur.simulator.profiles import BENIGN_CATALOG, MachineProfile

# Obviously-benign queried domains for the synthetic Windows DNS stream (Increment 2).
BENIGN_DOMAINS = (
    "update.microsoft.com", "ctldl.windowsupdate.com", "settings-win.data.microsoft.com",
    "login.microsoftonline.com", "clients4.google.com", "edge.microsoft.com",
    "outlook.office365.com", "teams.microsoft.com", "fonts.googleapis.com", "ocsp.digicert.com",
)
# Fixed "known-bad-for-demo" domains so a hand-authored watchlist has a real hit. Synthetic, NOT a
# real-world reputation claim — see ioc.py HONESTY_NOTE.
DEMO_BAD_DOMAINS = (
    "evil-c2.example.com", "exfil.badactor.test", "beacon.malware-demo.net",
)

# Obviously-benign dest IPs for the synthetic Windows network-connection stream (Increment 3).
# RFC 5737 documentation ranges (TEST-NET-1/2/3) — IANA-reserved for examples, can NEVER route to a
# real host, so a synthetic "match" can never masquerade as real-world intel (see ioc.py HONESTY_NOTE).
BENIGN_IPS = (
    "192.0.2.10", "192.0.2.20", "192.0.2.30", "198.51.100.10", "198.51.100.20",
    "198.51.100.30", "203.0.113.20", "203.0.113.30", "203.0.113.40", "203.0.113.50",
)
# Fixed "known-bad-for-demo" dest IPs so a hand-authored watchlist has a real hit. 203.0.113.10 is
# ALREADY the canonical C2/exfil host in realism.py command lines. Synthetic, NOT a reputation claim.
DEMO_BAD_IPS = (
    "203.0.113.10",
)

# Obviously-benign v6 dest IPs for the synthetic network-connection stream (Increment 5).
# RFC 3849 2001:db8::/32 — IANA-reserved for documentation, the v6 analogue of RFC 5737, can NEVER
# route to a real host, so a synthetic v6 "match" can never masquerade as real-world intel.
BENIGN_IPS6 = (
    "2001:db8::1", "2001:db8::2", "2001:db8::a", "2001:db8:1::10", "2001:db8:2::20",
)
# Fixed "known-bad-for-demo" v6 dest (v6 analogue of 203.0.113.10). Synthetic, NOT a reputation claim.
DEMO_BAD_IPS6 = (
    "2001:db8::dead:10",
)


def _windows_hosts(profiles: list[MachineProfile]) -> list[str]:
    return sorted(p.host for p in profiles if p.os_family == "windows")


def _hosts_for(profiles: list[MachineProfile], os_family: str) -> list[str]:
    return sorted(p.host for p in profiles if p.os_family == os_family)


def _dns_stream(profiles: list[MachineProfile], config, base_time: datetime) -> list[tuple[datetime, dict]]:
    """Deterministic benign + demo-bad DNS-query stream across ALL OS families (Increment 4).

    Uses a SECOND seeded RNG (config.seed ^ 0x444E53, 'DNS') so the DNS stream is independent of the
    process-create stream (Invariant 1 — no wall-clock/unseeded randomness). Windows hosts are iterated
    FIRST in the exact same draw order as before (Windows fixtures stay byte-identical); Linux/macOS hosts
    are appended after. Linux DNS rides an EDR agent overlay, macOS DNS an agent overlay — auditd/ESF do
    NOT natively resolve DNS (honest provenance). The demo-bad force is pinned per-OS to that OS's first host.
    """
    rng = random.Random(config.seed ^ 0x444E53)  # 'DNS' salt — independent, reproducible
    catalog = list(BENIGN_DOMAINS) + list(DEMO_BAD_DOMAINS)
    per_host = max(1, config.duration_seconds // 60)
    out: list[tuple[datetime, dict]] = []
    pid = 9000
    # Windows FIRST (identical draw order to pre-Increment-4 -> byte-identical fixtures), then Linux, macOS.
    for os_family in ("windows", "linux", "macos"):
        hosts = _hosts_for(profiles, os_family)
        for host in hosts:
            forced = [DEMO_BAD_DOMAINS[0]] if host == hosts[0] else []
            for i in range(per_host):
                domain = forced[i] if i < len(forced) else rng.choice(catalog)
                offset = rng.randint(0, max(1, config.duration_seconds - 1))
                ts = base_time + timedelta(seconds=offset)
                pid += 1
                intent = EventIntent(kind="dns_query", host=host, timestamp=ts, pid=pid, domain=domain)
                out.append((ts, emit(os_family, intent)))
    return out


def _netconn_stream(profiles: list[MachineProfile], config, base_time: datetime) -> list[tuple[datetime, dict]]:
    """Deterministic benign + demo-bad network-connection stream across ALL OS families (Increment 4).

    Uses a THIRD seeded RNG (config.seed ^ 0x4E4554, 'NET'), independent of the process AND DNS streams
    (Invariant 1). Windows hosts iterate FIRST in the exact same draw order as before (byte-identical
    fixtures); Linux/macOS appended after. Linux connections ride the realistic auditd connect SYSCALL;
    macOS connections ride an agent/Network-Extension overlay. dest_ip uses RFC 5737 ranges; dest_port is
    context-only (not matchable). Demo-bad force pinned per-OS to that OS's first host.
    """
    rng = random.Random(config.seed ^ 0x4E4554)  # 'NET' salt — independent, reproducible
    catalog = list(BENIGN_IPS) + list(DEMO_BAD_IPS)
    ports = (80, 443, 8080, 53)
    per_host = max(1, config.duration_seconds // 60)
    out: list[tuple[datetime, dict]] = []
    pid = 9500
    for os_family in ("windows", "linux", "macos"):
        hosts = _hosts_for(profiles, os_family)
        for host in hosts:
            forced = [DEMO_BAD_IPS[0]] if host == hosts[0] else []
            for i in range(per_host):
                dest_ip = forced[i] if i < len(forced) else rng.choice(catalog)
                dest_port = rng.choice(ports)
                offset = rng.randint(0, max(1, config.duration_seconds - 1))
                ts = base_time + timedelta(seconds=offset)
                pid += 1
                intent = EventIntent(kind="network_connect", host=host, timestamp=ts, pid=pid,
                                     dest_ip=dest_ip, dest_port=dest_port)
                out.append((ts, emit(os_family, intent)))
    # ── v6 sub-loop (Increment 5) ────────────────────────────────────────────
    # SEPARATE RNG (config.seed ^ 0x4E455436, 'NET6'): the v4 loop above draws with the 'NET' RNG and
    # is NOT touched, so every pre-existing v4 fixture stays byte-identical. v6 dests are RFC 3849.
    rng6 = random.Random(config.seed ^ 0x4E455436)  # 'NET6' salt — independent, reproducible
    catalog6 = list(BENIGN_IPS6) + list(DEMO_BAD_IPS6)
    pid6 = 9800
    for os_family in ("windows", "linux", "macos"):
        hosts = _hosts_for(profiles, os_family)
        for host in hosts:
            forced6 = [DEMO_BAD_IPS6[0]] if host == hosts[0] else []
            for i in range(per_host):
                dest_ip = forced6[i] if i < len(forced6) else rng6.choice(catalog6)
                dest_port = rng6.choice(ports)
                offset = rng6.randint(0, max(1, config.duration_seconds - 1))
                ts = base_time + timedelta(seconds=offset)
                pid6 += 1
                intent = EventIntent(kind="network_connect", host=host, timestamp=ts, pid=pid6,
                                     dest_ip=dest_ip, dest_port=dest_port)
                out.append((ts, emit(os_family, intent)))
    return out


def generate_baseline(profiles: list[MachineProfile], config, base_time: datetime) -> list[dict]:
    """Deterministic benign process_create events across all profiles for the window, PLUS a
    Windows-only synthetic dns_query stream AND a Windows-only synthetic network_connect stream.
    Seeded -> reproducible."""
    rng = random.Random(config.seed)
    total = max(1, (config.duration_seconds // 60) * config.rate_per_minute)
    raws: list[tuple[datetime, dict]] = []
    pid = 1000
    for _ in range(total):
        prof = rng.choice(profiles)
        proc = rng.choice(BENIGN_CATALOG[prof.os_family])
        offset = rng.randint(0, max(1, config.duration_seconds - 1))
        ts = base_time + timedelta(seconds=offset)
        pid += 1
        intent = EventIntent(
            kind="process_create", host=prof.host, timestamp=ts, pid=pid, ppid=1,
            user=rng.choice(prof.users), process_name=proc["name"], process_path=proc["path"],
            command_line=proc["name"], parent_process_name=proc["parent"])
        raws.append((ts, emit(prof.os_family, intent)))
    raws.extend(_dns_stream(profiles, config, base_time))
    raws.extend(_netconn_stream(profiles, config, base_time))
    raws.sort(key=lambda x: (x[0], x[1].get("host", "")))
    return [r for _, r in raws]
