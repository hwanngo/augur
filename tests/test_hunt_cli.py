import json
from augur.hunt import main


def test_hunt_cli_writes_jsonl(tmp_path, capsys):
    out = tmp_path / "det.jsonl"
    main([
        "--source", "jsonl",
        "--source-arg", "path=sample_data/acceptance/full_detection.jsonl",
        "--sink", "jsonl", "--sink-arg", f"jsonl:path={out}",
        "--min-proximity", "0.3",
    ])
    rows = [json.loads(l) for l in out.read_text().strip().splitlines()]
    assert any(r["scenario_id"] == "SCEN-WIN-001" and r["proximity"] == 1.0 for r in rows)
