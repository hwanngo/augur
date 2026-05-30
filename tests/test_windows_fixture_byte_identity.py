"""Increment 4 guard: parameterizing the baseline to all OSes must NOT change any Windows corpus line.

The Windows RNG draws are produced first and in the same order, so every windows_sysmon line in the
regenerated corpus is byte-identical to the pre-Increment-4 baseline (captured in
tests/_windows_corpus_baseline.sha256). New Linux/macOS DNS/connect records are purely additive.
"""
import hashlib
import json
from pathlib import Path

_BASELINE = Path(__file__).parent / "_windows_corpus_baseline.sha256"
_CORPUS = Path("sample_data/corpus/enterprise_day.jsonl")


def _is_v6_netconn(rec: dict) -> bool:
    # Increment 5 adds additive RFC 3849 v6 dests on Sysmon EID 3 (a SEPARATE seeded sub-loop). They
    # are purely additive and must be excluded from the v4-line byte-identity hash.
    return rec.get("event_id") == 3 and ":" in (rec.get("dest_ip") or "")


def test_windows_corpus_lines_byte_identical():
    expected = _BASELINE.read_text().strip()
    lines = _CORPUS.read_text().splitlines()
    win = [l for l in lines
           if json.loads(l).get("source_type") == "windows_sysmon" and not _is_v6_netconn(json.loads(l))]
    got = hashlib.sha256("\n".join(win).encode()).hexdigest()
    assert win, "corpus has no windows_sysmon lines"
    assert got == expected, (
        "Windows corpus lines changed after Increment-4 baseline parameterization — "
        "the Windows RNG draw order was perturbed (regression of byte-identity guarantee)."
    )


def test_corpus_has_new_multi_os_netintel_records():
    lines = [json.loads(l) for l in _CORPUS.read_text().splitlines()]
    # Linux DNS overlay + connect SYSCALL exist
    assert any(r.get("source_type") == "linux_auditd" and r.get("type") == "EDR"
               and r.get("behavior") == "dns_query" for r in lines)
    assert any(r.get("source_type") == "linux_auditd" and r.get("syscall") == "connect" for r in lines)
    # macOS agent overlays exist
    assert any(r.get("event_type") == "ES_AGENT_NOTIFY_DNS_QUERY" for r in lines)
    assert any(r.get("event_type") == "ES_AGENT_NOTIFY_NETWORK_CONNECT" for r in lines)
