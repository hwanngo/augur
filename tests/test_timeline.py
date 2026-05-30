"""TDD: Case Timeline builder (infra-free, deterministic, read-only)."""
from augur.api.timeline import build_case_timeline, PAD_SECONDS, MAX_CONTEXT, HONESTY_NOTE


def _det(**kw):
    base = dict(scenario_id="SCEN-X", name="Cred Theft", severity="CRITICAL",
                affected_hosts=["HOSTA"],
                matched_steps=[
                    {"step_id": 1, "name": "Spawn powershell", "element_id": "e1", "host": "HOSTA",
                     "timestamp": "2026-01-01T09:00:00+00:00"},
                    {"step_id": 2, "name": "LSASS dump", "element_id": "e2", "host": "HOSTA",
                     "timestamp": "2026-01-01T09:00:10+00:00"},
                ])
    base.update(kw)
    return base


def _write_feed(tmp_path, lines):
    import json
    p = tmp_path / "feed.jsonl"
    p.write_text("\n".join(json.dumps(x) for x in lines))
    return [str(p)]


def _topo():
    from augur.pipeline import default_topology
    return default_topology()


def _ctx_line(ts, host, proc):
    return {"timestamp": ts, "host": host, "event_id": 1, "process_guid": "{g}",
            "process_name": proc, "Image": f"C:\\\\{proc}", "CommandLine": f"{proc} -x"}


def test_matched_backbone_and_context_tagging(tmp_path):
    feed = _write_feed(tmp_path, [
        _ctx_line("2026-01-01T09:00:05+00:00", "HOSTA", "explorer.exe"),
        _ctx_line("2026-01-01T08:00:00+00:00", "HOSTA", "old.exe"),
        _ctx_line("2026-01-01T09:00:05+00:00", "OTHER", "x.exe"),
    ])
    out = build_case_timeline(_det(), feed, _topo(), host=None, frm=None, to=None)
    assert out["scenario_id"] == "SCEN-X" and out["hosts"] == ["HOSTA"]
    kinds = [(r["kind"], r["label"]) for r in out["rows"]]
    assert ("matched_step", "Spawn powershell") in kinds
    assert ("matched_step", "LSASS dump") in kinds
    assert ("context", "explorer.exe") in kinds
    assert all(r["host"] == "HOSTA" for r in out["rows"])
    assert out["matched_count"] == 2
    assert out["honesty_note"] == HONESTY_NOTE
    ts = [r["timestamp"] for r in out["rows"]]
    assert ts == sorted(ts)


def test_band_is_first_minus_pad_to_last_plus_pad(tmp_path):
    out = build_case_timeline(_det(), _write_feed(tmp_path, []), _topo())
    assert out["band"]["pad_seconds"] == PAD_SECONDS
    assert out["band"]["from"] == "2026-01-01T08:55:00+00:00"
    assert out["band"]["to"] == "2026-01-01T09:05:10+00:00"


def test_matched_event_not_duplicated_as_context(tmp_path):
    feed = _write_feed(tmp_path, [_ctx_line("2026-01-01T09:00:00+00:00", "HOSTA", "powershell.exe")])
    out = build_case_timeline(_det(), feed, _topo())
    at_t0 = [r for r in out["rows"] if r["timestamp"] == "2026-01-01T09:00:00+00:00"]
    assert len(at_t0) == 1 and at_t0[0]["kind"] == "matched_step"


def test_host_filter_422_when_not_affected(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        build_case_timeline(_det(), _write_feed(tmp_path, []), _topo(), host="NOPE")


def test_from_to_override_band(tmp_path):
    from datetime import datetime, timezone
    out = build_case_timeline(_det(), _write_feed(tmp_path, []), _topo(),
                              frm=datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc),
                              to=datetime(2026, 1, 2, 0, 0, tzinfo=timezone.utc))
    assert out["band"]["from"] == "2026-01-01T00:00:00+00:00"
    assert out["band"]["to"] == "2026-01-02T00:00:00+00:00"


def test_context_cap_and_truncation(tmp_path):
    lines = [_ctx_line(f"2026-01-01T09:00:0{(i%9)+1}+00:00", "HOSTA", f"p{i}.exe") for i in range(MAX_CONTEXT + 50)]
    out = build_case_timeline(_det(), _write_feed(tmp_path, lines), _topo())
    assert out["context_total"] >= MAX_CONTEXT + 1
    assert out["context_shown"] == MAX_CONTEXT and out["context_truncated"] is True
    assert out["matched_count"] == 2


def test_deterministic_recompute_identical(tmp_path):
    feed = _write_feed(tmp_path, [_ctx_line("2026-01-01T09:00:05+00:00", "HOSTA", "explorer.exe")])
    a = build_case_timeline(_det(), feed, _topo())
    b = build_case_timeline(_det(), feed, _topo())
    assert a == b


def test_multi_host_band_spans_both_hosts(tmp_path):
    # cross-host case: matched steps on two hosts; context on each; band spans both; both hosts present.
    det = _det(affected_hosts=["HOSTA", "HOSTB"], matched_steps=[
        {"step_id": 1, "name": "Foothold A", "element_id": "a1", "host": "HOSTA",
         "timestamp": "2026-01-01T09:00:00+00:00"},
        {"step_id": 2, "name": "Pivot B", "element_id": "b1", "host": "HOSTB",
         "timestamp": "2026-01-01T09:00:10+00:00"},
    ])
    feed = _write_feed(tmp_path, [
        _ctx_line("2026-01-01T09:00:05+00:00", "HOSTA", "a.exe"),
        _ctx_line("2026-01-01T09:00:06+00:00", "HOSTB", "b.exe"),
    ])
    out = build_case_timeline(det, feed, _topo(), host=None)
    assert out["hosts"] == ["HOSTA", "HOSTB"]
    assert {r["host"] for r in out["rows"]} == {"HOSTA", "HOSTB"}
    assert out["matched_count"] == 2
    labels = {(r["host"], r["label"]) for r in out["rows"]}
    assert ("HOSTA", "a.exe") in labels and ("HOSTB", "b.exe") in labels
    assert out["band"]["from"] == "2026-01-01T08:55:00+00:00"   # 09:00:00 (HOSTA) - 300s
    assert out["band"]["to"] == "2026-01-01T09:05:10+00:00"     # 09:00:10 (HOSTB) + 300s
