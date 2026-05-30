import pytest
from augur.ingest.jsonl import read_jsonl, IngestError


def test_reads_objects_and_skips_blank_lines(tmp_path):
    f = tmp_path / "logs.jsonl"
    f.write_text('{"event_id": 1, "host": "A"}\n\n{"event_id": 7, "host": "B"}\n')
    events = read_jsonl(f)
    assert [e["host"] for e in events] == ["A", "B"]


def test_malformed_json_raises_with_line_number(tmp_path):
    f = tmp_path / "logs.jsonl"
    f.write_text('{"ok": 1}\nNOT JSON\n')
    with pytest.raises(IngestError) as ei:
        read_jsonl(f)
    assert "line 2" in str(ei.value)
