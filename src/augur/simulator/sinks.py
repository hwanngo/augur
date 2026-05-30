import json
from pathlib import Path


class JsonlBatchSink:
    """Append native raw events to a single JSONL file."""
    def __init__(self, path: str, mode: str = "w") -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, mode)

    def write(self, raws: list[dict]) -> None:
        for r in raws:
            self._fh.write(json.dumps(r) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class DirectoryBatchSink:
    """Write each batch as its own JSONL file in a directory (drop-feed for the 3d monitor)."""
    def __init__(self, directory: str) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def write_batch(self, raws: list[dict], *, name: str) -> str:
        dest = self.directory / f"{name}.jsonl"
        with open(dest, "w") as fh:
            for r in raws:
                fh.write(json.dumps(r) + "\n")
        return str(dest)
