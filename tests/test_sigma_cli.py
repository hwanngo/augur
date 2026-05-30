import io
from contextlib import redirect_stdout, redirect_stderr

import pytest
import yaml

from augur.sigma.__main__ import main


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def test_cli_default_emits_full_pack():
    rc, out, err = _run([])
    assert rc == 0
    docs = list(yaml.safe_load_all(out))
    assert len(docs) >= 40
    assert "per-step" in err.lower()  # honesty banner on stderr


def test_cli_single_scenario():
    rc, out, _ = _run(["--scenario", "SCEN-WIN-001"])
    assert rc == 0
    docs = list(yaml.safe_load_all(out))
    assert len(docs) == 3


def test_cli_out_writes_deterministic_files(tmp_path):
    rc1, _, _ = _run(["--scenario", "SCEN-WIN-001", "--out", str(tmp_path)])
    assert rc1 == 0
    files = sorted(p.name for p in tmp_path.glob("*.yml"))
    assert files == ["SCEN-WIN-001-step1.yml", "SCEN-WIN-001-step2.yml", "SCEN-WIN-001-step3.yml"]
    first = (tmp_path / "SCEN-WIN-001-step1.yml").read_bytes()
    # second run is byte-identical
    rc2, _, _ = _run(["--scenario", "SCEN-WIN-001", "--out", str(tmp_path)])
    assert rc2 == 0
    assert (tmp_path / "SCEN-WIN-001-step1.yml").read_bytes() == first


def test_cli_unknown_scenario_nonzero():
    rc, _, _ = _run(["--scenario", "SCEN-NOPE-999"])
    assert rc != 0
