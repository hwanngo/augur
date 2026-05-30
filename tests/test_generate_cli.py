from augur.generate import main
from augur.scenarios.loader import load_scenarios


def test_cli_generates_and_reports(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("AUGUR_AI_GENERATOR", "fake")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "c.db"))
    main(["--seed", "SCEN-WIN-001", "--n", "3"])
    out = capsys.readouterr().out
    assert "candidate" in out.lower()
    assert "SCEN-GEN-" in out
