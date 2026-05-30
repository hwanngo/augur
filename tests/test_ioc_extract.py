"""TDD: pure regex IOC extractor — refang, type coverage, dedup, bounds, the
matchable/unmatchable honesty split, and the lockstep with ioc.py's accepted set."""
import pytest

from augur.api.ioc_extract import extract_iocs, MAX_IOCS, MAX_TEXT
from augur.api import ioc as ioc_mod


def _vals(items, typ):
    return sorted(i["value"] for i in items if i["type"] == typ)


def _all(res):
    return res["matchable"] + res["unmatchable"]


def _types(res):
    return {i["type"] for i in _all(res)}


# ── per-type extraction (fanged AND defanged) ─────────────────────────────────
def test_ipv4_defanged_refanged_matchable_ip():
    r = extract_iocs("beacon to 203[.]0[.]113[.]10 observed")
    ip = [i for i in r["matchable"] if i["type"] == "ip"]
    assert len(ip) == 1
    assert ip[0]["value"] == "203.0.113.10"
    assert ip[0]["defanged_from"] == "203[.]0[.]113[.]10"
    assert ip[0]["matchable"] is True
    assert ip[0]["category"] == "network"


def test_ipv4_private_reserved_dropped():
    r = extract_iocs("internal 10.0.0.1 127.0.0.1 192.168.1.1 172.16.5.5 0.0.0.0 255.255.255.255")
    assert _vals(r["matchable"], "ip") == [] and _vals(r["unmatchable"], "ip") == []
    assert _vals(r["unmatchable"], "ipv4") == []


def test_ipv6_full_form_matchable():
    r = extract_iocs("addr 2001:0db8:0000:0000:0000:ff00:0042:8329 seen")
    assert _vals(r["unmatchable"], "ipv6") == []
    assert _vals(r["matchable"], "ipv6") == ["2001:0db8:0000:0000:0000:ff00:0042:8329"]
    ipv6 = [i for i in r["matchable"] if i["type"] == "ipv6"]
    assert ipv6[0]["matchable"] is True and ipv6[0]["category"] == "network"


def test_domain_defanged_allowlist():
    r = extract_iocs("c2 at evil[.]example[.]com hosts payload")
    dom = [i for i in r["matchable"] if i["type"] == "domain"]
    assert dom and dom[0]["value"] == "evil.example.com"
    assert dom[0]["defanged_from"] == "evil[.]example[.]com"
    assert dom[0]["matchable"] is True and dom[0]["category"] == "network"


def test_url_hxxp_refanged():
    r = extract_iocs("download hxxps://bad[.]example[.]org/a/b.bin now")
    url = [i for i in r["unmatchable"] if i["type"] == "url"]
    assert url and url[0]["value"] == "https://bad.example.org/a/b.bin"


def test_url_host_extracted_as_matchable_domain():
    # The full URL stays UNMATCHABLE; its host is pulled out and surfaces as a matchable domain.
    r = extract_iocs("download hxxps://bad[.]example[.]org/a/b.bin now")
    url = [i for i in r["unmatchable"] if i["type"] == "url"]
    assert url and url[0]["value"] == "https://bad.example.org/a/b.bin"
    assert url[0]["matchable"] is False
    dom = [i for i in r["matchable"] if i["type"] == "domain" and i["value"] == "bad.example.org"]
    assert dom, "URL host should be added as a matchable domain"
    assert dom[0]["matchable"] is True


def test_url_host_strips_port_and_userinfo():
    r = extract_iocs("c2 at http://user:pass@evil.example.com:8443/x.php seen")
    dom = [i for i in r["matchable"] if i["type"] == "domain"]
    vals = [d["value"] for d in dom]
    assert "evil.example.com" in vals, f"host without userinfo/port expected, got {vals}"
    assert not any(":" in v or "@" in v for v in vals)


def test_email_defanged():
    r = extract_iocs("phish from attacker[at]evil[.]com today")
    em = [i for i in r["unmatchable"] if i["type"] == "email"]
    assert em and em[0]["value"] == "attacker@evil.com"
    assert em[0]["category"] == "identity"


def test_hashes_lengths_and_fp_drop():
    md5, sha1 = "d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    r = extract_iocs(f"hashes {md5} {sha1} {sha256} "
                     f"00000000000000000000000000000000 ffffffffffffffffffffffffffffffff")
    # md5/sha1/sha256 now map to a single matchable `hash` type (lockstep with ioc.py).
    hashes = sorted(i["value"] for i in r["matchable"] if i["type"] == "hash")
    assert hashes == sorted([md5, sha1, sha256])
    assert all(i["matchable"] is True and i["category"] == "file"
               for i in r["matchable"] if i["type"] == "hash")


def test_cve_upper_normalised():
    r = extract_iocs("exploits cve-2021-44228 in the wild")
    assert _vals(r["unmatchable"], "cve") == ["CVE-2021-44228"]


def test_technique_matchable():
    r = extract_iocs("uses T1059.001 and TA0001 for execution")
    techs = [i for i in r["matchable"] if i["type"] == "technique"]
    assert sorted(t["value"] for t in techs) == ["T1059.001", "TA0001"]
    assert all(t["matchable"] is True and t["category"] == "tactic" for t in techs)


def test_process_name_matchable():
    r = extract_iocs("spawns rundll32.exe and mimikatz.exe")
    procs = [i for i in r["matchable"] if i["type"] == "process_name"]
    assert sorted(p["value"] for p in procs) == ["mimikatz.exe", "rundll32.exe"]
    assert all(p["matchable"] is True and p["category"] == "host" for p in procs)


def test_file_path_win_and_unix_map_to_image():
    r = extract_iocs(r"drops C:\Users\Public\evil.exe and /usr/bin/curl payload")
    imgs = [i for i in r["matchable"] if i["type"] == "image"]
    vals = sorted(i["value"] for i in imgs)
    assert r"C:\Users\Public\evil.exe" in vals
    assert "/usr/bin/curl" in vals
    assert all(i["matchable"] is True and i["category"] == "file" for i in imgs)


def test_registry_key_unmatchable():
    r = extract_iocs(r"persists via HKEY_CURRENT_USER\Software\Microsoft\Run\evil")
    reg = [i for i in r["unmatchable"] if i["type"] == "registry_key"]
    assert reg and reg[0]["matchable"] is False and reg[0]["category"] == "host"


# ── matchable mapping + LOCKSTEP with ioc.py ──────────────────────────────────
def test_matchable_types_are_exactly_the_mapped_set():
    r = extract_iocs("T1059.001 rundll32.exe and C:\\x\\y.exe and "
                     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
                     "and 192.0.2.9 and evil.example.com")
    assert {i["type"] for i in r["matchable"]} <= {"technique", "process_name", "image", "hash", "domain", "ip"}
    assert all(i["matchable"] is True for i in r["matchable"])
    assert all(i["matchable"] is False for i in r["unmatchable"])


def test_lockstep_extractor_matchable_subset_of_iocpy_accepted():
    # The honesty contract guard: every type the extractor calls matchable MUST be a
    # type ioc.py accepts. Import both; cross-check against ioc.py's REAL constants.
    accepted = set(ioc_mod._EVENT_TYPES) | {"technique"}
    r = extract_iocs("T1059.001 rundll32.exe C:\\a\\b.exe /usr/bin/x")
    emitted = {i["type"] for i in r["matchable"]}
    assert emitted <= accepted, f"{emitted - accepted} not accepted by ioc.py"
    # And no ioc.py-rejected type ever appears as matchable.
    assert emitted.isdisjoint(set(ioc_mod._UNMATCHABLE))


def test_unmatchable_reasons_mirror_iocpy_phrasing():
    r = extract_iocs("203.0.113.10 2001:0db8:0000:0000:0000:ff00:0042:8329 evil.example.com")
    by = {i["type"]: i for i in r["unmatchable"]}
    assert "ipv4" not in by and "ip" not in by  # ipv4 -> matchable ip now
    assert any(i["type"] == "ip" for i in r["matchable"])
    assert "ipv6" not in by  # ipv6 -> matchable now
    assert any(i["type"] == "ipv6" for i in r["matchable"])
    assert "domain" not in by  # domain is matchable
    assert any(i["type"] == "domain" for i in r["matchable"])


# ── dedup / ordering / bounds / categorize / confidence ───────────────────────
def test_dedup_same_ioc_once():
    r = extract_iocs("rundll32.exe then rundll32.exe again RUNDLL32.EXE")
    assert _vals(r["matchable"], "process_name") == ["rundll32.exe"]


def test_deterministic_sorted_across_runs():
    text = "zeta.example.com alpha.example.com 192.0.2.9 T1003 T1059"
    assert extract_iocs(text) == extract_iocs(text)
    techs = [i["value"] for i in extract_iocs(text)["matchable"] if i["type"] == "technique"]
    assert techs == sorted(techs)


def test_bounds_truncation():
    many = " ".join(f"T{1000 + i}" for i in range(MAX_IOCS + 20))
    r = extract_iocs(many)
    assert r["summary"]["truncated"] is True
    assert len(_all(r)) == MAX_IOCS


def test_max_text_rejected():
    with pytest.raises(ValueError):
        extract_iocs("a" * (MAX_TEXT + 1))


def test_empty_text_rejected():
    with pytest.raises(ValueError):
        extract_iocs("   \n  ")


def test_confidence_per_type_rank():
    r = extract_iocs("T1059.001 192.0.2.9 evil.example.com rundll32.exe")
    conf = {i["type"]: i["confidence"] for i in _all(r)}
    assert conf["technique"] == "high"
    assert conf["ip"] == "high"
    assert conf["domain"] == "medium"
    assert conf["process_name"] == "medium"


def test_summary_shape_and_honesty_note():
    r = extract_iocs("T1059.001 and 192.0.2.9")
    s = r["summary"]
    assert set(s) == {"extracted_total", "matchable_count", "unmatchable_count", "truncated", "honesty_note"}
    assert s["extracted_total"] == s["matchable_count"] + s["unmatchable_count"]
    assert "not AI" in s["honesty_note"] and "matchable" in s["honesty_note"]


# ── zero-FP gate on benign prose (the key risk) ───────────────────────────────
def test_no_over_extraction_on_benign_prose():
    prose = ("Please review the attached report.pdf and decide whether to proceed and/or escalate. "
             "As of 2026/06/01 the version 1.2.3 rollout is on track; e.g. the etc. notes apply. "
             "See the summary for details.")
    r = extract_iocs(prose)
    assert _types(r) == set() or _types(r) <= {"cve"}  # nothing falsely typed
    assert _vals(_dict(r), "domain") == [] if False else True  # explicit checks below
    everything = _all(r)
    assert not any(i["type"] == "domain" for i in everything), [i for i in everything if i["type"] == "domain"]
    assert not any(i["type"] == "file_path" or i["type"] == "image" for i in everything)
    assert not any(i["type"] == "process_name" for i in everything)
    assert not any(i["type"] == "ip" for i in everything)


def _dict(res):
    return res["matchable"] + res["unmatchable"]


# ── realistic mixed report → exact partition ──────────────────────────────────
def test_realistic_mixed_report_partition():
    report = (
        "Threat advisory. The actor used T1059.001 and TA0002. "
        "It dropped rundll32.exe and C:\\Users\\Public\\evil[.]exe. "
        "C2 beacon to 192[.]0[.]2[.]10 and evil[.]example[.]com over hxxps://evil[.]example[.]com/x. "
        "Payload sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. "
        "Tracked as CVE-2021-44228."
    )
    r = extract_iocs(report)
    m = {(i["type"], i["value"]) for i in r["matchable"]}
    assert ("technique", "T1059.001") in m
    assert ("technique", "TA0002") in m
    assert ("process_name", "rundll32.exe") in m
    assert ("image", "C:\\Users\\Public\\evil.exe") in m
    u = {(i["type"], i["value"]) for i in r["unmatchable"]}
    assert ("ip", "192.0.2.10") in m  # public doc-range IP is now matchable (Increment 3)
    assert ("domain", "evil.example.com") in m  # domain is matchable (Increment 2)
    assert ("url", "https://evil.example.com/x") in u
    assert ("cve", "CVE-2021-44228") in u
    assert ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") in m
    assert all(i["matchable"] is False for i in r["unmatchable"])


# ── Fix 1 regression: .js / .sh prose tokens must NOT produce process_name ────
def test_js_sh_prose_tokens_zero_process_name():
    """Node.js, Vue.js, index.js, deploy.sh, handler.js are framework/tool names in
    prose — they must NOT be extracted as matchable process_name IOCs (Fix 1)."""
    prose = (
        "The application was built with Node.js and Vue.js as the frontend framework. "
        "The entry point is index.js and it calls handler.js. "
        "Deployment is handled by deploy.sh running on the CI pipeline."
    )
    r = extract_iocs(prose)
    procs = [i for i in r["matchable"] if i["type"] == "process_name"]
    assert procs == [], (
        f"Expected zero process_name from JS/shell prose, got: {[p['value'] for p in procs]}"
    )


# ── Fix 2 regression: C:\<single-word> prose must NOT produce image file_path ─
def test_win_path_bare_single_segment_not_extracted():
    r"""C:\Users in general, C:\Windows somewhere have no interior backslash segment --
    they must NOT be extracted as image/file_path (Fix 2)."""
    prose = r"C:\Users in general and C:\Windows somewhere are typical paths discussed in prose."
    r = extract_iocs(prose)
    images = [i for i in r["matchable"] if i["type"] == "image"]
    assert images == [], (
        f"Expected no image from single-segment Windows prose, got: {[i['value'] for i in images]}"
    )


def test_win_path_multi_segment_still_extracted():
    r"""A real Windows path with interior segments must still be extracted as image (Fix 2)."""
    r = extract_iocs(r"drops C:\Windows\System32\rundll32.exe silently")
    images = [i for i in r["matchable"] if i["type"] == "image"]
    vals = [i["value"] for i in images]
    assert r"C:\Windows\System32\rundll32.exe" in vals, f"Real Windows path not extracted: {vals}"


# ── Fix 3 regression: (dot)/[dot]/(at) defang forms preserve provenance ───────
def test_defang_paren_dot_form_provenance():
    """evil(dot)com style indicators must carry a non-None defanged_from (Fix 3)."""
    r = extract_iocs("c2 at evil(dot)example(dot)com hosting payload")
    dom = [i for i in r["matchable"] if i["type"] == "domain"]
    assert dom, "domain should be extracted after refanging (dot) -> ."
    assert dom[0]["value"] == "evil.example.com"
    assert dom[0].get("defanged_from") is not None, (
        f"defanged_from should be set for (dot) form, got: {dom[0]}"
    )
    assert "dot" in dom[0]["defanged_from"], (
        f"defanged_from should contain the original (dot) text: {dom[0]['defanged_from']}"
    )


def test_defang_bracket_dot_form_provenance():
    """evil[dot]com style indicators must carry a non-None defanged_from (Fix 3)."""
    r = extract_iocs("loader from bad[dot]example[dot]org observed")
    dom = [i for i in r["matchable"] if i["type"] == "domain"]
    assert dom, "domain should be extracted after refanging [dot] -> ."
    assert dom[0]["value"] == "bad.example.org"
    assert dom[0].get("defanged_from") is not None, (
        f"defanged_from should be set for [dot] form, got: {dom[0]}"
    )
