from augur.simulator.__main__ import main


def test_batch_with_yaml_config_injection(tmp_path):
    cfg = tmp_path / "sim.yaml"
    cfg.write_text(
        "seed: 9\nduration_seconds: 1800\nrate_per_minute: 10\n"
        "injections:\n  - {scenario_id: SCEN-WIN-001, host: HR_User_PC, start_offset_seconds: 300}\n")
    out = tmp_path / "feed.jsonl"
    main(["--batch", "--config", str(cfg), "--out", str(out)])
    import json
    lines = [json.loads(x) for x in out.read_text().strip().splitlines()]
    assert len(lines) > 0
    # the injected SCEN-WIN-001 chain (powershell/rundll32/lsass) is present on HR_User_PC
    assert any(l.get("host") == "HR_User_PC" and l.get("event_id") == 1 for l in lines)
