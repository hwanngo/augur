from augur.demo import run_headless


def test_run_headless_prints_and_returns_detections(capsys):
    dets = run_headless(["sample_data/acceptance/demo_multi_os.jsonl"], min_proximity=0.30)
    ids = [d.scenario_id for d in dets]
    assert "SCEN-WIN-001" in ids
    out = capsys.readouterr().out
    assert "SCEN-WIN-001" in out
    assert "100%" in out
