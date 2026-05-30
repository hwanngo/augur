"""Pure, deterministic, AI-free IOC extraction from pasted threat-report text.

Refang the whole text once, run anchored/allowlisted regexes per type (tuned against
over-extraction on benign prose), dedup (type, value.casefold()), sort deterministically,
bound (MAX_TEXT/MAX_IOCS), and split into the load-bearing matchable/unmatchable arrays.

Matchable mapping (lockstep with augur.api.ioc):
  technique -> technique,  process_name -> process_name,  file_path -> image,
  md5/sha1/sha256 -> hash,  domain -> domain,  ip -> ip,  ipv6 -> ipv6.
Everything else is unmatchable (extracted for the analyst's other tools), carrying the
verbatim ioc.py-style reason. No engine/scoring import, no now(), no randomness, no LLM.
"""
import re
from urllib.parse import urlsplit

MAX_TEXT = 200_000
MAX_IOCS = 256  # matches augur.api.ioc.MAX_IOCS so a full push never overflows the matcher

HONESTY_NOTE = (
    "Extraction is pure pattern-matching, not AI. Process-name / file-path / technique / file-hash / "
    "domain / IPv4 / IPv6 indicators are matchable against Augur's endpoint telemetry (hashes, domains, and "
    "dest IPs against synthetic, deterministically-generated corpus telemetry — IPv4 uses RFC 5737 and IPv6 "
    "uses the RFC 3849 2001:db8::/32 documentation ranges: pipeline validation, not real-world prevalence). "
    "A URL's host is extracted as a matchable domain; the full URL string itself stays unmatchable (its "
    "path/query has no backing event field). Email, CVE, and registry indicators are extracted for your "
    "other tools but the corpus carries no matching fields, so a clean result for those would be misleading. "
    "Private/reserved IPv4 is filtered out (never a CTI IOC)."
)

# Unmatchable reasons — reuse ioc.py._UNMATCHABLE phrasing verbatim where shared; the rest extend it.
_REASON = {
    "url": "the URL host was extracted as a matchable domain; the full URL path/query has no backing event field",
    "email": "the corpus carries no identity/email field",
    "cve": "CVE is context only — not an Augur telemetry field",
    "registry_key": "the corpus carries no registry fields",
}

_CATEGORY = {
    "ip": "network", "ipv6": "network", "domain": "network", "url": "network",
    "email": "identity", "md5": "file", "sha1": "file", "sha256": "file",
    "cve": "vulnerability", "technique": "tactic", "process_name": "host",
    "file_path": "file", "registry_key": "host",
}

_CONFIDENCE = {  # deterministic per-type pattern-class confidence (NOT a reputation score)
    "technique": "high", "cve": "high", "md5": "high", "sha1": "high", "sha256": "high",
    "ip": "high", "url": "high",
    "domain": "medium", "email": "medium", "ipv6": "medium",
    "process_name": "medium", "file_path": "medium", "registry_key": "medium",
}

# Matchable mapping: extracted type -> ioc.py-accepted type. Everything else unmatchable.
_MATCHABLE_MAP = {
    "technique": "technique", "process_name": "process_name", "file_path": "image",
    "md5": "hash", "sha1": "hash", "sha256": "hash",
    "domain": "domain", "ip": "ip", "ipv6": "ipv6",
}

# Curated TLD allowlist — avoids matching report.pdf / file.txt as domains (key FP guard).
_TLDS = (
    "com", "net", "org", "io", "info", "biz", "xyz", "co", "gov", "edu", "mil",
    "ru", "cn", "uk", "de", "fr", "jp", "br", "in", "au", "us", "eu", "top", "site", "online", "onion",
)
_TLD_RE = "|".join(sorted(_TLDS, key=len, reverse=True))

# Unix file-path top-level dirs — anchored to avoid matching and/or, dates, etc.
_UNIX_DIRS = ("usr", "etc", "var", "tmp", "home", "opt", "bin", "sbin", "root", "Users", "Library", "Applications")
_UNIX_DIRS_RE = "|".join(_UNIX_DIRS)

# Process-name executable extensions (allowlist, not "any word").
# Deliberately excludes .js and .sh: bare prose tokens like "Node.js", "deploy.sh", "index.js"
# are almost always framework/tool names, not malicious process executions.  A .js/.sh payload
# that carries a real path is still caught by the file_path→image rule (win_path/unix_path).
_EXE_EXTS = ("exe", "dll", "sys", "scr", "ps1", "bat", "cmd", "vbs", "jar",
             "elf", "bin", "app", "dylib", "so")
_EXE_EXTS_RE = "|".join(_EXE_EXTS)

# ── compiled patterns (applied AFTER refang) ─────────────────────────────────
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_RE = {
    "url": re.compile(r"https?://[^\s\"'<>,;)}\]]+", re.IGNORECASE),
    "email": re.compile(rf"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.(?:{_TLD_RE})\b", re.IGNORECASE),
    "ipv4": re.compile(rf"\b{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}\b"),
    "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "technique": re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|TA\d{4})\b"),
    "domain": re.compile(rf"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{{0,61}}[A-Za-z0-9])?\.)+(?:{_TLD_RE})\b", re.IGNORECASE),
    "registry_key": re.compile(
        r"\bHK(?:EY_LOCAL_MACHINE|EY_CURRENT_USER|EY_CLASSES_ROOT|LM|CU|CR)\\[^\s\"',;)}\]]{5,}"),
    # Require at least one interior segment after the drive root (C:\X\Y...) so that bare
    # prose like "C:\Users in general" (no second backslash) does not match.
    "win_path": re.compile(r"\b[A-Za-z]:\\[^\s\"',;)}\]\\]+(?:\\[^\s\"',;)}\]\\]+)+"),
    "unix_path": re.compile(rf"(?<![\w./])/(?:{_UNIX_DIRS_RE})/[^\s\"',;)}}\]]+"),
    "process_name": re.compile(rf"(?<![\\/\w.])[\w.\-]+\.(?:{_EXE_EXTS_RE})\b", re.IGNORECASE),
}

# Private/reserved IPv4 — not CTI IOCs; cut noise.
_PRIV4 = re.compile(r"^(?:10\.|127\.|0\.|255\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")


def _refang(text: str) -> str:
    """Deterministic, idempotent refang of the whole text up front."""
    t = text
    t = re.sub(r"h(?:xx|XX)p", "http", t)              # hxxp / hXXp -> http
    t = re.sub(r"\[?\s*(?:at|@)\s*\]|\(at\)", "@", t, flags=re.IGNORECASE)  # [at] (at) [@] -> @
    t = re.sub(r"\[\s*dot\s*\]|\(\s*dot\s*\)", ".", t, flags=re.IGNORECASE) # [dot] (dot) -> .
    t = re.sub(r"\s+dot\s+", ".", t, flags=re.IGNORECASE)                   # word " dot " between labels
    t = re.sub(r"[\[\{(]\s*\.\s*[\]\})]", ".", t)      # [.] (.) {.} (and spaced) -> .
    t = t.replace("[:]", ":").replace("[//]", "//")
    return t


def _hash_is_fp(h: str) -> bool:
    low = h.lower()
    return len(set(low)) == 1  # all-same char (covers all-0 / all-f)


def _category(typ: str) -> str:
    return _CATEGORY[typ]


def _make_item(typ: str, value: str, defanged_from: str | None):
    mapped = _MATCHABLE_MAP.get(typ)
    item = {
        "type": mapped if mapped else typ,
        "value": value,
        "category": _category(typ),
        "confidence": _CONFIDENCE[typ],
        "matchable": mapped is not None,
    }
    if defanged_from is not None and defanged_from != value:
        item["defanged_from"] = defanged_from
    if mapped is None:
        item["reason"] = _REASON[typ]
    return item


def extract_iocs(text: str) -> dict:
    if text is None or not text.strip():
        raise ValueError("report text is empty")
    if len(text) > MAX_TEXT:
        raise ValueError(f"report exceeds {MAX_TEXT}-char cap")

    refanged = _refang(text)
    # Map a refanged span back to its original (defanged) span for provenance.
    original_at = _span_provenance(text, refanged)

    # collected[(type, value.casefold())] = (type, value, defanged_from)
    collected: dict[tuple[str, str], tuple[str, str, str | None]] = {}
    consumed: list[tuple[int, int]] = []  # spans already claimed by url/email (exclude domains inside)

    def add(typ: str, value: str, start: int, end: int):
        key = (typ, value.casefold())
        if key in collected:
            return
        df = original_at(start, end)
        collected[key] = (typ, value, df)

    # 1) URL + email first (claim their spans so inner domains aren't double-extracted).
    for typ in ("url", "email"):
        for mo in _RE[typ].finditer(refanged):
            # Strip trailing sentence-ending punctuation that the greedy char-class can swallow.
            val = mo.group(0).rstrip(".,;") if typ == "url" else mo.group(0)
            end = mo.start() + len(val)
            consumed.append((mo.start(), end))
            add(typ, val, mo.start(), end)
            if typ == "url":
                # Pull the registrable host out of the URL (urlsplit.hostname already drops
                # userinfo + port and lowercases). The host substring is INSIDE the consumed URL
                # span, so the generic domain pass (step 7) skips it — add it directly, deduped by
                # key. The full URL stays unmatchable; the host carries the match (honest split).
                host = urlsplit(val).hostname
                if host:
                    add("domain", host, mo.start(), end)

    def inside_consumed(s: int, e: int) -> bool:
        return any(cs <= s and e <= ce for cs, ce in consumed)

    # 2) Windows + Unix paths (claim spans so their basenames aren't re-typed as process_name).
    for typ in ("win_path", "unix_path"):
        for mo in _RE[typ].finditer(refanged):
            if inside_consumed(mo.start(), mo.end()):
                continue
            # Strip trailing sentence-ending punctuation that the greedy char-class can swallow.
            val = mo.group(0).rstrip(".,;")
            end = mo.start() + len(val)
            consumed.append((mo.start(), end))
            add("file_path", val, mo.start(), end)

    # 3) registry keys.
    for mo in _RE["registry_key"].finditer(refanged):
        if inside_consumed(mo.start(), mo.end()):
            continue
        add("registry_key", mo.group(0), mo.start(), mo.end())

    # 4) hashes (longest first so a SHA256 isn't sub-claimed as md5/sha1).
    for typ in ("sha256", "sha1", "md5"):
        for mo in _RE[typ].finditer(refanged):
            if inside_consumed(mo.start(), mo.end()):
                continue
            if _hash_is_fp(mo.group(0)):
                continue
            add(typ, mo.group(0).lower(), mo.start(), mo.end())
            consumed.append((mo.start(), mo.end()))

    # 5) ipv4 / ipv6.
    for mo in _RE["ipv6"].finditer(refanged):
        if not inside_consumed(mo.start(), mo.end()):
            add("ipv6", mo.group(0), mo.start(), mo.end())
            consumed.append((mo.start(), mo.end()))
    for mo in _RE["ipv4"].finditer(refanged):
        if inside_consumed(mo.start(), mo.end()) or _PRIV4.match(mo.group(0)):
            continue
        add("ip", mo.group(0), mo.start(), mo.end())
        consumed.append((mo.start(), mo.end()))

    # 6) cve / technique.
    for mo in _RE["cve"].finditer(refanged):
        add("cve", mo.group(0).upper(), mo.start(), mo.end())
    for mo in _RE["technique"].finditer(refanged):
        add("technique", mo.group(0).upper(), mo.start(), mo.end())

    # 7) domains (skip anything inside a claimed url/email/path span).
    for mo in _RE["domain"].finditer(refanged):
        if inside_consumed(mo.start(), mo.end()):
            continue
        add("domain", mo.group(0).lower(), mo.start(), mo.end())

    # 8) process names (basenames NOT preceded by a path sep; path spans already consumed).
    for mo in _RE["process_name"].finditer(refanged):
        if inside_consumed(mo.start(), mo.end()):
            continue
        add("process_name", mo.group(0).lower(), mo.start(), mo.end())

    # Build items, dedup already done by key; deterministic sort.
    items = [_make_item(typ, value, df) for (typ, value, df) in collected.values()]
    items.sort(key=lambda i: (i["type"], i["value"].casefold()))

    truncated = len(items) > MAX_IOCS
    if truncated:
        items = items[:MAX_IOCS]

    matchable = [i for i in items if i["matchable"]]
    unmatchable = [i for i in items if not i["matchable"]]
    return {
        "summary": {
            "extracted_total": len(items),
            "matchable_count": len(matchable),
            "unmatchable_count": len(unmatchable),
            "truncated": truncated,
            "honesty_note": HONESTY_NOTE,
        },
        "matchable": matchable,
        "unmatchable": unmatchable,
    }


def _span_provenance(original: str, refanged: str):
    """Return f(start,end)->original-substring|None.

    Refang is largely length-preserving except for collapses like '[.]'->'.'. To keep this
    deterministic and cheap, we record the defanged form only when the original text differs
    from the refanged value at the same logical token. We approximate provenance by searching
    the original for the token's defanged variants; if found and different, return it.
    """
    def lookup(start: int, end: int) -> str | None:
        live = refanged[start:end]
        if live in original:
            return None  # unchanged -> no provenance needed
        # Try common defang variants of the live token (ordered: more specific first).
        cand = (
            # bracket/paren long-form variants: (dot) [dot] (at) [at]
            live.replace(".", "(dot)"),
            live.replace(".", "[dot]"),
            live.replace("@", "(at)").replace(".", "(dot)"),
            live.replace("@", "[at]").replace(".", "[dot]"),
            live.replace("@", "(at)").replace(".", "[dot]"),
            live.replace("@", "[at]").replace(".", "(dot)"),
            # bracket/paren short-form [.] (.) [at]
            live.replace(".", "[.]"),
            live.replace(".", "(.)"),
            live.replace("@", "[at]").replace(".", "[.]"),
            # hxxp variants
            live.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]"),
            live.replace("https://", "hxxps://").replace("http://", "hxxp://"),
        )
        for c in cand:
            if c in original:
                return c
        return live  # changed but variant unknown -> return the live form as best-effort
    return lookup
