from datetime import datetime


def merge(*streams: list[dict]) -> list[dict]:
    """Merge native-event streams into one chronologically-ordered list (stable by host)."""
    all_events: list[dict] = []
    for s in streams:
        all_events.extend(s)
    all_events.sort(key=lambda r: (datetime.fromisoformat(r["timestamp"]), r.get("host", "")))
    return all_events
