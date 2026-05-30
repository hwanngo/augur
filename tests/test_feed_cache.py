"""TDD: the normalized feed is read+normalized at most once per path set, not
re-read on every windowed/IOC/rarity/timeline call (DoS / wasted-I/O guard)."""
import augur.api.feed as feed


def test_load_normalized_caches_disk_reads(monkeypatch):
    feed._load_normalized.cache_clear()
    paths = ["sample_data/acceptance/full_detection.jsonl"]
    calls = {"n": 0}
    real = feed.read_jsonl
    monkeypatch.setattr(feed, "read_jsonl", lambda p: (calls.__setitem__("n", calls["n"] + 1), real(p))[1])

    a = feed.load_normalized(paths)
    b = feed.load_normalized(paths)

    assert len(a) > 0
    assert [e.timestamp for e in a] == [e.timestamp for e in b]   # same content
    assert calls["n"] == 1, "second call must be served from cache, not re-read from disk"


def test_load_normalized_returns_independent_lists():
    feed._load_normalized.cache_clear()
    paths = ["sample_data/acceptance/full_detection.jsonl"]
    a = feed.load_normalized(paths)
    a.clear()                                  # mutating the returned list...
    b = feed.load_normalized(paths)
    assert len(b) > 0                          # ...must not corrupt the cached copy
