import glob
from augur.simulator.__main__ import main


def test_stream_cli_writes_batches_to_dir(tmp_path):
    out_dir = tmp_path / "feed"
    # --interval 0 -> no real sleep; the feed is chunked into files and the command returns
    main(["--stream", "--seed", "4", "--duration", "600", "--rate", "20",
          "--out-dir", str(out_dir), "--batch-size", "25", "--interval", "0"])
    files = glob.glob(str(out_dir / "*.jsonl"))
    assert len(files) >= 1
