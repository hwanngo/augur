import json
import pytest
from augur.metrics.__main__ import main


def test_cli_writes_markdown_file(tmp_path):
    """main() with --out writes a markdown file containing the three section headers."""
    out_path = tmp_path / "report.md"
    # Use a small benign corpus (short duration) so the test is fast
    main(["--out", str(out_path), "--duration", "120", "--rate", "5"])
    content = out_path.read_text()
    assert "MITRE" in content
    assert "False Positive" in content
    assert "Detectability" in content


def test_cli_with_logs_path_runs_without_error():
    """main() with --logs against the acceptance benign fixture must not raise."""
    main(["--logs", "sample_data/acceptance/no_detection_benign.jsonl"])


def test_cli_writes_json(tmp_path):
    """--json writes a parseable JSON file with expected top-level keys."""
    json_path = tmp_path / "report.json"
    main(["--json", str(json_path), "--duration", "60", "--rate", "5"])
    data = json.loads(json_path.read_text())
    assert "coverage" in data
    assert "false_positive" in data
    assert "detectability" in data
    assert "generated_at" in data
