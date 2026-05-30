"""Fetch real public attack datasets (OTRF / Security-Datasets) for real-Sysmon validation.

Stdlib-only (urllib + zipfile + pathlib). Downloads into gitignored datasets/real/<name>/.
Idempotent: skips a dataset that's already extracted. Nothing large is ever committed.

Usage:
    uv run python scripts/fetch_real_datasets.py                 # fetch all registered datasets
    uv run python scripts/fetch_real_datasets.py empire_mimikatz_logonpasswords
"""
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
DEST_ROOT = _ROOT / "datasets" / "real"

_BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"

# name -> zip URL (OTRF Security-Datasets, atomic windows). Paths verified against live captures.
REGISTRY: dict[str, str] = {
    "empire_mimikatz_logonpasswords": (
        _BASE + "credential_access/host/empire_mimikatz_logonpasswords.zip"
    ),
    # ── Wave 1: EID-1 process_create command-line LOLBin captures ──────────────
    "cmd_dumping_ntds_dit_file_ntdsutil": (
        _BASE + "credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil.zip"
    ),
    "cmd_sam_copy_esentutl": (
        _BASE + "credential_access/host/cmd_sam_copy_esentutl.zip"
    ),
    "cmd_mshta_vbscript_execute_psh": (
        _BASE + "defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip"
    ),
    "empire_uac_shellapi_fodhelper": (
        _BASE + "privilege_escalation/host/empire_uac_shellapi_fodhelper.zip"
    ),
    "cmd_bitsadmin_download_psh_script": (
        _BASE + "defense_evasion/host/cmd_bitsadmin_download_psh_script.zip"
    ),
    "empire_schtasks_creation_execution_elevated_user": (
        _BASE + "persistence/host/empire_schtasks_creation_execution_elevated_user.zip"
    ),
    # ── Wave 2: behavior captures where the technique is the actual MALICIOUS instance ─────────────
    # (EID 8 CreateRemoteThread + EID 13 RegistryEvent SetValue). Chosen because the Wave-1 captures
    # carry these EIDs only as BENIGN baseline (csrss->svchost CtrlRoutine, W32Time writes); detecting
    # on those would be a false positive. These two captures contain the real malicious instance.
    "empire_dllinjection_LoadLibrary_CreateRemoteThread": (
        _BASE + "defense_evasion/host/empire_dllinjection_LoadLibrary_CreateRemoteThread.zip"
    ),
    "empire_persistence_registry_modification_run_keys_elevated_user": (
        _BASE + "persistence/host/empire_persistence_registry_modification_run_keys_elevated_user.zip"
    ),
}

# Wave-1 suite: the 7 tags surfaced by `--real all` (registry order = deterministic feed order).
WAVE1: list[str] = [
    "empire_mimikatz_logonpasswords",
    "cmd_dumping_ntds_dit_file_ntdsutil",
    "cmd_sam_copy_esentutl",
    "cmd_mshta_vbscript_execute_psh",
    "empire_uac_shellapi_fodhelper",
    "cmd_bitsadmin_download_psh_script",
    "empire_schtasks_creation_execution_elevated_user",
]

# Wave-2 suite: behavior captures (EID 8 injection, EID 13 Run-key persistence).
WAVE2: list[str] = [
    "empire_dllinjection_LoadLibrary_CreateRemoteThread",
    "empire_persistence_registry_modification_run_keys_elevated_user",
]

SUITES: dict[str, list[str]] = {
    "wave1": WAVE1,
    "wave2": WAVE2,
    "all": WAVE1 + WAVE2,
}


def fetch(name: str) -> Path:
    if name not in REGISTRY:
        raise SystemExit(f"unknown dataset {name!r}; known: {sorted(REGISTRY)}")
    dest = DEST_ROOT / name
    if dest.exists() and any(dest.iterdir()):
        print(f"[skip] {name} already present at {dest}")
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    url = REGISTRY[name]
    zip_path = dest / f"{name}.zip"
    print(f"[get ] {url}")
    urllib.request.urlretrieve(url, zip_path)
    print(f"[unzip] {zip_path} -> {dest}")
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)
    zip_path.unlink()
    print(f"[done] {name} -> {dest}")
    return dest


TAGGED_SOURCE_TYPE = "windows_sysmon_real"


def tag_jsonl(src: Path, out: Path) -> int:
    """Read a real OTRF jsonl, inject source_type on every record, write tagged.jsonl.

    Deterministic, stdlib-only. Returns the record count. The registry maps
    source_type='windows_sysmon_real' -> windows_sysmon_real.normalize, so the tagged feed routes
    through every existing read-path with no route change. Provider gating (EventIDs are NOT unique
    across providers — e.g. Microsoft-Windows-Kernel-IO also emits EID 1) lives in exactly one correct
    layer, windows_sysmon_real.normalize, which drops a modeled EID from a foreign provider at ingest.
    """
    src, out = Path(src), Path(out)
    count = 0
    with src.open() as fh, out.open("w") as wh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            rec["source_type"] = TAGGED_SOURCE_TYPE
            wh.write(json.dumps(rec) + "\n")
            count += 1
    print(f"[tag ] {count} records -> {out}")
    return count


def fetch_and_tag(name: str) -> Path:
    """Fetch (if absent) then tag the dataset's first .jsonl into <dest>/tagged.jsonl.

    Idempotent on the fetch step (fetch() skips an extracted dataset). Always rewrites tagged.jsonl.
    """
    dest = fetch(name)
    # OTRF extracts are line-delimited JSON but ship with a .json extension; accept both .json/.jsonl.
    jsonls = sorted(p for p in dest.iterdir()
                    if p.is_file() and p.suffix in (".json", ".jsonl") and p.name != "tagged.jsonl")
    if not jsonls:
        raise SystemExit(f"no .json/.jsonl found in {dest} to tag")
    out = dest / "tagged.jsonl"
    tag_jsonl(jsonls[0], out)
    return out


def main(argv: list[str]) -> int:
    args = argv[1:]
    do_tag = False
    if "--tag" in args:
        do_tag = True
        args = [a for a in args if a != "--tag"]
    if "--suite" in args:
        i = args.index("--suite")
        suite = args[i + 1] if i + 1 < len(args) else ""
        if suite not in SUITES:
            raise SystemExit(f"unknown suite {suite!r}; known: {', '.join(SUITES)}")
        # `--suite <name>` implies fetch+tag of the whole suite list.
        for name in SUITES[suite]:
            fetch_and_tag(name)
        return 0
    names = args or list(REGISTRY)
    for name in names:
        if do_tag:
            fetch_and_tag(name)
        else:
            fetch(name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
