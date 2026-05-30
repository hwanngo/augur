import json
from pathlib import Path


class IngestError(ValueError):
    pass


def read_jsonl(path: str | Path) -> list[dict]:
    events: list[dict] = []
    for i, line in enumerate(Path(path).read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise IngestError(f"malformed JSON at line {i} of {path}: {e}") from e
    return events
