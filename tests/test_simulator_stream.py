import glob
import json
from augur.simulator.stream import chunk, stream_feed


def test_chunk_splits_into_batches():
    items = list(range(10))
    assert chunk(items, 3) == [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9]]
    assert chunk([], 3) == []


def test_stream_feed_writes_one_file_per_batch_no_real_sleep(tmp_path):
    raws = [{"i": i, "timestamp": "2026-01-01T09:00:00+00:00", "host": "h"} for i in range(7)]
    slept = []
    paths = stream_feed(str(tmp_path), raws, batch_size=3, interval=99,
                        sleep_fn=lambda s: slept.append(s))
    files = sorted(glob.glob(str(tmp_path / "*.jsonl")))
    assert len(files) == 3 and len(paths) == 3          # 7 items / 3 -> 3 batches
    # union of all files == the full feed, in order
    recovered = []
    for f in files:
        recovered.extend(json.loads(l) for l in open(f).read().strip().splitlines())
    assert recovered == raws
    assert slept == [99, 99, 99]                         # injected sleep called per batch, never real


def test_stream_feed_empty_writes_nothing(tmp_path):
    assert stream_feed(str(tmp_path), [], batch_size=3, interval=0, sleep_fn=lambda s: None) == []
