from dataclasses import dataclass, field


@dataclass
class MachineProfile:
    host: str
    os_family: str
    users: list[str]


# Benign process catalogs: (name, path, parent). Deliberately mundane — no powershell/rundll32/lsass/etc.
BENIGN_CATALOG: dict[str, list[dict]] = {
    "windows": [
        {"name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "parent": "explorer.exe"},
        {"name": "outlook.exe", "path": "C:\\Program Files\\Microsoft Office\\outlook.exe", "parent": "explorer.exe"},
        {"name": "notepad.exe", "path": "C:\\Windows\\System32\\notepad.exe", "parent": "explorer.exe"},
        {"name": "teams.exe", "path": "C:\\Users\\Public\\teams.exe", "parent": "explorer.exe"},
        {"name": "code.exe", "path": "C:\\Program Files\\Microsoft VS Code\\code.exe", "parent": "explorer.exe"},
        {"name": "OneDrive.exe", "path": "C:\\Users\\Public\\OneDrive.exe", "parent": "explorer.exe"},
    ],
    # NOTE: do NOT add winword.exe / excel.exe — they are step-1 ProcessName indicators in
    # scenarios/initial_access/macro_initial_access.yaml and would fire a benign detection (0.33).
    "linux": [
        {"name": "curl", "path": "/usr/bin/curl", "parent": "bash"},
        {"name": "git", "path": "/usr/bin/git", "parent": "bash"},
        {"name": "node", "path": "/usr/bin/node", "parent": "bash"},
        {"name": "python3", "path": "/usr/bin/python3", "parent": "bash"},
        {"name": "apt", "path": "/usr/bin/apt", "parent": "bash"},
        {"name": "vim", "path": "/usr/bin/vim", "parent": "bash"},
    ],
    "macos": [
        {"name": "Safari", "path": "/Applications/Safari.app/Contents/MacOS/Safari", "parent": "launchd"},
        {"name": "Finder", "path": "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", "parent": "launchd"},
        {"name": "Spotlight", "path": "/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight", "parent": "launchd"},
        {"name": "Terminal", "path": "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", "parent": "launchd"},
        {"name": "Mail", "path": "/Applications/Mail.app/Contents/MacOS/Mail", "parent": "launchd"},
        {"name": "Music", "path": "/Applications/Music.app/Contents/MacOS/Music", "parent": "launchd"},
    ],
}


def default_profiles() -> list[MachineProfile]:
    return [
        MachineProfile(host="HR_User_PC", os_family="windows", users=["alice", "bob"]),
        MachineProfile(host="CORP-JENKINS01", os_family="linux", users=["jenkins", "deploy"]),
        MachineProfile(host="DESIGN-MBP-07", os_family="macos", users=["jsmith"]),
    ]
