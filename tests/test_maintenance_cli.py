"""TDD: the `augur.maintenance prune` CLI wires up and prunes all four stores."""
import pytest

from augur.maintenance import main, _do_prune


def test_prune_cli_runs_across_all_stores(tmp_path, capsys):
    db = tmp_path / "m.db"
    # Fresh DB: stores auto-create their tables; prune should run cleanly and
    # report a count for every store it orchestrates.
    main(["prune", "--days", "30", "--db", str(db)])
    out = capsys.readouterr().out
    assert "pruned:" in out
    for store in ("sessions=", "auth_events=", "alerts=", "candidates="):
        assert store in out


def test_prune_cli_requires_subcommand(tmp_path):
    with pytest.raises(SystemExit):
        main([])  # no subcommand -> argparse errors out


def test_do_prune_is_callable_directly(tmp_path):
    _do_prune(str(tmp_path / "d.db"), days=1)  # no raise on a fresh DB
