from augur.ingest.jsonl import read_jsonl
from augur.normalize.registry import normalize_events as new_norm
from augur.normalize.windows_sysmon import normalize as win

import glob


def _is_windows(raw):
    st = raw.get("source_type")
    return st in (None, "windows_sysmon")


def test_every_acceptance_fixture_normalizes_via_windows_path():
    for path in sorted(glob.glob("sample_data/acceptance/*.jsonl")):
        raws = list(read_jsonl(path))
        events = new_norm(raws)
        assert len(events) == len(raws)
        # for the Windows-Sysmon rows, the registry must agree with the windows path
        for raw, ev in zip(raws, events):
            if not _is_windows(raw):
                continue
            assert ev.kind == win(raw).kind and ev.process_name == win(raw).process_name


def test_ecs_shim_still_exports_public_api():
    from augur.normalize.ecs import NormalizedEvent, normalize_event, normalize_events  # noqa: F401
    e = normalize_event({"timestamp": "2026-05-01T10:00:00+00:00", "event_id": 1, "host": "h"})
    assert isinstance(e, NormalizedEvent) and e.kind == "process_create"
