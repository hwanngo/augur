"""Lockstep honesty guard (Increment 5): none of the FIVE honesty strings (+ validTypes) may still
claim v4-only / CIDR-not-evaluated / URL-deferred, and the two Python notes must name CIDR + v6 + the
RFC documentation ranges.

Five strings: ioc.py HONESTY_NOTE, ioc_extract.py HONESTY_NOTE, en.json intel.unsupportedNote,
en.json intel.extract.honesty, vi.json the same two keys — plus the en/vi intel.validTypes.
"""
import json
from pathlib import Path

from augur.api.ioc import HONESTY_NOTE as IOC_NOTE
from augur.api.ioc_extract import HONESTY_NOTE as EXTRACT_NOTE

_STALE = ("v4-only", "v4 match only", "exact v4 match", "CIDR ranges are not yet evaluated",
          "are not evaluated", "không được đánh giá", "deferred")


def _has_stale(s: str) -> list[str]:
    return [p for p in _STALE if p in s]


def test_iocpy_note_no_stale_and_names_cidr_v6():
    assert _has_stale(IOC_NOTE) == [], IOC_NOTE
    assert "CIDR" in IOC_NOTE
    assert "RFC 3849" in IOC_NOTE
    assert "RFC 5737" in IOC_NOTE
    assert "IPv6" in IOC_NOTE or "v6" in IOC_NOTE


def test_extractpy_note_no_stale_and_names_url_host_v6():
    assert _has_stale(EXTRACT_NOTE) == [], EXTRACT_NOTE
    assert "IPv6" in EXTRACT_NOTE
    assert "URL" in EXTRACT_NOTE


def _load(rel):
    return json.loads((Path(__file__).resolve().parent.parent / rel).read_text())


def test_en_locale_strings_no_stale():
    en = _load("frontend/src/locales/en.json")
    note = en["intel"]["unsupportedNote"]
    honesty = en["intel"]["extract"]["honesty"]
    valid = en["intel"]["validTypes"]
    assert _has_stale(note) == [], note
    assert "CIDR" in note or "cidr" in note
    assert _has_stale(honesty) == [], honesty
    assert _has_stale(valid) == [], valid
    assert "cidr" in valid and "ipv6" in valid


def test_vi_locale_strings_no_stale():
    vi = _load("frontend/src/locales/vi.json")
    note = vi["intel"]["unsupportedNote"]
    honesty = vi["intel"]["extract"]["honesty"]
    valid = vi["intel"]["validTypes"]
    assert _has_stale(note) == [], note
    assert _has_stale(honesty) == [], honesty
    assert _has_stale(valid) == [], valid
    assert "cidr" in valid and "ipv6" in valid
