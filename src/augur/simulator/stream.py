import time

from augur.simulator.sinks import DirectoryBatchSink


def chunk(items: list, size: int) -> list[list]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def stream_feed(out_dir: str, raws: list[dict], *, batch_size: int = 50, interval: float = 1.0,
                sleep_fn=time.sleep) -> list[str]:
    """Write the feed to out_dir as one JSONL file per batch, sleeping `interval` between batches.

    `sleep_fn` is injectable so tests never actually sleep. The 3d monitor's DirectorySource reads every
    file in out_dir on each scan, so batches accumulate into a growing graph.
    """
    sink = DirectoryBatchSink(out_dir)
    paths: list[str] = []
    for i, batch in enumerate(chunk(raws, batch_size)):
        paths.append(sink.write_batch(batch, name=f"batch-{i:04d}"))
        sleep_fn(interval)
    return paths
