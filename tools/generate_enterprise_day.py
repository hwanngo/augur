"""Generate a realistic "enterprise day" log corpus.

Produces sample_data/corpus/enterprise_day.jsonl: thousands of benign events across the
topology interleaved with a handful of planted attack traces (reused verbatim from
the verified per-scenario *_tp.jsonl fixtures, time-shifted into the day). The benign
pool is curated to never match any scenario's first step, so the only detections are
the planted attacks — exactly what a real SIEM export buried in noise looks like.

Reproducible: fixed seed, no wall-clock reads. Run:  uv run python tools/generate_enterprise_day.py
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "sample_data" / "corpus" / "enterprise_day.jsonl"
DAY = datetime(2026, 5, 28, 0, 0, 0, tzinfo=timezone.utc)
rng = random.Random(20260528)

# Benign endpoints/users (curated; all hostnames exist in the topology).
HOSTS = [
    "HR_User_PC", "Finance_User_PC", "Sales_User_PC", "Legal_User_PC", "Exec_User_PC",
    "Dev_User_PC", "CORP-WKS-0421", "CORP-WKS-0588", "CORP-WKS-0733", "CORP-LAPTOP-0102",
    "IT_Admin_PC", "Helpdesk_PC", "App_Server_01", "CORP-APP02", "File_Server_01",
    "CORP-FILE02", "CORP-SQL02", "CORP-EXCH01", "Jump_Host", "CORP-SCCM01",
]
USERS = ["asmith", "bjones", "cwilliams", "dbrown", "ekim", "fgarcia", "hlee", "jpatel",
         "kowalski", "mrossi", "nnguyen", "ozhang", "rtaylor", "svec", "twhite"]

# Curated benign processes: (name, path, command_line_templates, parent). None of these
# match any scenario step-1 (no temp/appdata exe, no attack tooling, no attack flags).
BENIGN_PROCS = [
    ("OUTLOOK.EXE", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", ["\"OUTLOOK.EXE\""], "explorer.exe"),
    ("WINWORD.EXE", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", ["\"WINWORD.EXE\" /n \"Q2_Report.docx\""], "explorer.exe"),
    ("EXCEL.EXE", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", ["\"EXCEL.EXE\" \"Budget.xlsx\""], "explorer.exe"),
    ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", ["\"chrome.exe\"", "\"chrome.exe\" --type=renderer"], "explorer.exe"),
    ("msedge.exe", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", ["\"msedge.exe\""], "explorer.exe"),
    ("Teams.exe", r"C:\Program Files\Microsoft\Teams\current\Teams.exe", ["\"Teams.exe\""], "explorer.exe"),
    ("OneDrive.exe", r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", ["\"OneDrive.exe\" /background"], "explorer.exe"),
    ("Code.exe", r"C:\Program Files\Microsoft VS Code\Code.exe", ["\"Code.exe\""], "explorer.exe"),
    ("notepad.exe", r"C:\Windows\System32\notepad.exe", ["notepad.exe notes.txt"], "explorer.exe"),
    ("SearchApp.exe", r"C:\Windows\SystemApps\Microsoft.Windows.Search\SearchApp.exe", ["\"SearchApp.exe\""], "svchost.exe"),
    ("RuntimeBroker.exe", r"C:\Windows\System32\RuntimeBroker.exe", ["RuntimeBroker.exe -Embedding"], "svchost.exe"),
    ("taskhostw.exe", r"C:\Windows\System32\taskhostw.exe", ["taskhostw.exe"], "svchost.exe"),
    ("MsMpEng.exe", r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe", ["\"MsMpEng.exe\""], "services.exe"),
    ("sqlservr.exe", r"C:\Program Files\Microsoft SQL Server\MSSQL15\Binn\sqlservr.exe", ["\"sqlservr.exe\" -sMSSQLSERVER"], "services.exe"),
    ("w3wp.exe", r"C:\Windows\System32\inetsrv\w3wp.exe", ["w3wp.exe -ap \"AppPool\""], "svchost.exe"),
]
SIGNED_DLLS = [
    r"C:\Windows\System32\kernel32.dll", r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\user32.dll", r"C:\Windows\System32\advapi32.dll",
    r"C:\Windows\System32\ole32.dll", r"C:\Windows\System32\gdi32.dll",
]
# Planted attacks: reuse verified traces. (label, trace path, base time during the day).
PLANTS = [
    ("sample_data/acceptance/true_positive.jsonl", 8 * 3600 + 12 * 60),
    ("sample_data/initial_access/SCEN-2026-100_tp.jsonl", 9 * 3600 + 5 * 60),
    ("sample_data/execution/SCEN-2026-120_tp.jsonl", 9 * 3600 + 48 * 60),
    ("sample_data/credential_access/SCEN-2026-200_tp.jsonl", 10 * 3600 + 22 * 60),
    ("sample_data/persistence/SCEN-2026-140_tp.jsonl", 11 * 3600 + 3 * 60),
    ("sample_data/privilege_escalation/SCEN-2026-160_tp.jsonl", 11 * 3600 + 41 * 60),
    ("sample_data/defense_evasion/SCEN-2026-184_tp.jsonl", 12 * 3600 + 30 * 60),
    ("sample_data/discovery/SCEN-2026-221_tp.jsonl", 13 * 3600 + 15 * 60),
    ("sample_data/lateral_movement/SCEN-2026-240_tp.jsonl", 14 * 3600 + 7 * 60),
    ("sample_data/exfiltration/SCEN-2026-262_tp.jsonl", 15 * 3600 + 50 * 60),
    ("sample_data/impact/SCEN-2026-280_tp.jsonl", 16 * 3600 + 38 * 60),
]


def benign_events(n: int) -> list[dict]:
    out = []
    for i in range(n):
        host = rng.choice(HOSTS)
        user = rng.choice(USERS)
        name, path, cmds, parent = rng.choice(BENIGN_PROCS)
        secs = rng.randint(7 * 3600, 18 * 3600)   # 07:00–18:00
        ts = (DAY + timedelta(seconds=secs)).isoformat()
        guid = f"benign-{i}"
        out.append({
            "timestamp": ts, "event_id": 1, "host": host, "user": user,
            "process_guid": guid, "process_name": name, "process_path": path,
            "command_line": rng.choice(cmds), "parent_process_name": parent,
            "integrity_level": "Medium",
            "user_sid": f"S-1-5-21-{rng.randint(10**9,10**10)}-{rng.randint(10**9,10**10)}-{rng.randint(10**9,10**10)}-{rng.randint(1000,1999)}",
            "hashes": {"sha256": "".join(rng.choice("0123456789abcdef") for _ in range(64))},
        })
        if rng.random() < 0.4:   # some benign signed image loads
            out.append({
                "timestamp": (DAY + timedelta(seconds=secs + rng.randint(1, 5))).isoformat(),
                "event_id": 7, "host": host, "process_guid": guid,
                "image_loaded": rng.choice(SIGNED_DLLS), "signed": True,
                "signature_status": "Valid", "signature_vendor": "Microsoft Windows",
                "is_injected": False, "api_hooking_detected": False,
            })
    return out


def planted_events() -> list[dict]:
    out = []
    for rel, base in PLANTS:
        lines = [json.loads(x) for x in (ROOT / rel).read_text().splitlines() if x.strip()]
        t0 = min(datetime.fromisoformat(e["timestamp"]) for e in lines)
        anchor = DAY + timedelta(seconds=base)
        shift = anchor - t0
        for e in lines:
            e = dict(e)
            e["timestamp"] = (datetime.fromisoformat(e["timestamp"]) + shift).isoformat()
            out.append(e)
    return out


def main() -> None:
    events = benign_events(1400) + planted_events()
    events.sort(key=lambda e: e["timestamp"])
    OUT.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    print(f"wrote {len(events)} events to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
