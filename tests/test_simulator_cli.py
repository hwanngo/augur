from augur.simulator.__main__ import main


def test_batch_writes_a_feed_file(tmp_path, capsys):
    out = tmp_path / "feed.jsonl"
    main(["--batch", "--seed", "7", "--duration", "600", "--rate", "20", "--out", str(out)])
    lines = out.read_text().strip().splitlines()
    assert len(lines) > 0
    import json
    for ln in lines:
        json.loads(ln)            # valid JSONL
    assert "events" in capsys.readouterr().out.lower()


def test_batch_is_reproducible(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    main(["--batch", "--seed", "7", "--duration", "600", "--rate", "20", "--out", str(a)])
    main(["--batch", "--seed", "7", "--duration", "600", "--rate", "20", "--out", str(b)])
    assert a.read_text() == b.read_text()
