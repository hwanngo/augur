import json
import sys
import urllib.request
from pathlib import Path
from typing import Iterable

from augur.ingest.jsonl import read_jsonl


class JsonlSource:
    """Read a single JSONL file (the first Source — wraps the existing reader)."""
    def __init__(self, path: str) -> None:
        self.path = path

    def read(self) -> Iterable[dict]:
        return read_jsonl(self.path)


class DirectorySource:
    """Read every file matching `glob` under `directory`, sorted by name, concatenated."""
    def __init__(self, directory: str, glob: str = "*.jsonl") -> None:
        self.directory = directory
        self.glob = glob

    def read(self) -> Iterable[dict]:
        events: list[dict] = []
        for f in sorted(Path(self.directory).glob(self.glob)):
            events.extend(read_jsonl(f))
        return events


class StdinSource:
    """Read JSONL events from standard input (e.g. piped from another tool)."""
    def read(self) -> Iterable[dict]:
        out: list[dict] = []
        for line in sys.stdin:
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out


class HttpSource:
    """Read JSON Lines (or a JSON array) via HTTP GET from a URL."""

    def __init__(self, url: str, *, timeout: float = 10.0) -> None:
        self.url = url
        self.timeout = timeout

    def read(self) -> list[dict]:
        req = urllib.request.Request(self.url, method="GET")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read().decode()
        body = body.strip()
        if not body:
            return []
        # Accept a JSON array as well as JSON Lines
        if body.startswith("["):
            return json.loads(body)
        out: list[dict] = []
        for line in body.splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out


# Roadmap (not implemented; see docs/en/ARCHITECTURE.md (Design Decisions)):
# SplunkSource, SentinelSource, ElasticSource — vendor SDK Sources, deferred.
