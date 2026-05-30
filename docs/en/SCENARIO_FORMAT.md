**English** | [Tiếng Việt](../vi/SCENARIO_FORMAT.md)

# Augur — Scenario Format Reference

Scenarios are YAML files in the `scenarios/` directory tree, grouped by MITRE ATT&CK tactic
(e.g. `scenarios/credential_access/`, `scenarios/execution/`). Each file is loaded and strictly
validated against the Pydantic schema in `src/augur/scenarios/schema.py` (`extra="forbid"` on every
model — unknown fields cause a load-time error). A duplicate `scenario_id` across any two files also
fails at startup.

This document is the authoritative authoring reference. See [ENGINE.md](ENGINE.md) for how the
engine evaluates scenarios, and [DATA_MODEL.md](DATA_MODEL.md) for the underlying data model.

---

## Top-Level Structure

A valid scenario YAML has exactly four top-level blocks:

```yaml
scenario_metadata:   # identity, severity, MITRE, OS family
  ...
spatial_constraints: # which zones/assets this scenario applies to
  ...
attack_sequence_flow: # the ordered detection steps
  steps:
    - ...
actionable_hunting_outputs: # KQL/Sigma queries to run when the scenario fires
  validation_queries:
    - ...
```

---

## 1. `scenario_metadata`

| Field | Type | Required | Description |
|---|---|---|---|
| `scenario_id` | `str` | yes | Unique ID; follow the OS-prefixed scheme below |
| `name` | `str` | yes | Short human-readable title |
| `description` | `str` | yes | What the adversary is doing; 1–3 sentences |
| `severity` | `str` | yes | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `mitre_mappings` | `list` | yes (≥1) | One or more `{tactic, technique}` pairs |
| `os_family` | `str` | no | `windows` (default) / `linux` / `macos` |

### Scenario ID Scheme

IDs follow the pattern `SCEN-<OS>-<NNN>` where `<NNN>` is a zero-padded three-digit number:

| Prefix | OS family | Example |
|---|---|---|
| `SCEN-WIN-` | windows | `SCEN-WIN-001` |
| `SCEN-LNX-` | linux | `SCEN-LNX-001` |
| `SCEN-MAC-` | macos | `SCEN-MAC-001` |
| `SCEN-CLD-` | cloud stub (endpoint telemetry) | `SCEN-CLD-001` |

All 40 current scenarios are uniquely identified within their prefix namespace. The `os_family`
field drives documentation and tooling; it is not enforced by the matcher (which is graph-agnostic).

### `mitre_mappings` entries

Each entry must have exactly `tactic` and `technique`:

```yaml
mitre_mappings:
  - tactic: "TA0006"
    technique: "T1003.001"
```

---

## 2. `spatial_constraints`

Controls which hosts in the graph are eligible participants in this scenario.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `applicable_zones` | `list[str]` | yes (≥1) | — | Zone values that qualify; see `Zone` enum |
| `critical_assets_only` | `bool` | no | `false` | When `true`, only hosts with `Criticality.CRITICAL` qualify |
| `required_log_sources` | `list[str]` | no | `[]` | Informational labels (not evaluated by the matcher) |

Valid zone strings: `DMZ`, `Internal_Server`, `User_Endpoint`, `Cloud_SaaS`,
`Active_Directory`, `Unknown`. Zone and criticality are always read from the topology, never from
log events. A host with `Zone.Unknown` fails all zone checks automatically.

```yaml
spatial_constraints:
  applicable_zones: ["User_Endpoint", "Internal_Server"]
  critical_assets_only: false
  required_log_sources: ["Windows_Sysmon", "EDR_Telemetry"]
```

---

## 3. `attack_sequence_flow`

Contains a single `steps` list. Steps must be numbered `1..N` contiguously with no gaps.

### 3.1 Step Schema

| Field | Type | Required | Notes |
|---|---|---|---|
| `step_id` | `int` | yes | Must form a contiguous sequence starting at `1` |
| `name` | `str` | yes | Short label for this detection step |
| `temporal_link` | object | step 1: forbidden; steps 2+: required | Links this step to the previous |
| `matching_criteria` | `dict` | yes | Must include `Node_Type`; see §3.3 |

**Step 1 must not have a `temporal_link`. Steps 2 and beyond must have one.** Violating either
constraint raises a validation error at load time.

### 3.2 `temporal_link`

Defines the time window and host-scope relationship between this step and the previous one.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `previous_step` | `int` | yes | — | Must equal `step_id - 1` |
| `link_scope` | `str` | no | `same_host` | `same_host` / `cross_host` / `any` |
| `min_time_delta_seconds` | `int` | no | `0` | Minimum elapsed time from previous step |
| `max_time_delta_seconds` | `int` | yes | — | Maximum elapsed time; must be ≥ `min_time_delta_seconds` |

```yaml
temporal_link:
  previous_step: 2
  link_scope: same_host
  min_time_delta_seconds: 0
  max_time_delta_seconds: 120
```

### 3.3 `matching_criteria`

A dictionary of field criteria applied to graph nodes. The engine evaluates these against
`ProcessNode` or `FileNode` attributes depending on `Node_Type`.

**`Node_Type` is mandatory** and must be `"Process"` or `"File"`.

#### Process node criterion keys

| Criterion key | `ProcessNode` field | Notes |
|---|---|---|
| `ProcessName` | `name` | Executable basename |
| `ProcessPath` | `path` | Full path |
| `CommandLine` | `command_line` | Full argument string |
| `ParentProcessName` | `parent_process_name` | Parent basename |
| `IntegrityLevel` | `integrity_level` | e.g. `"High"` |
| `ProcessGuid` | `id` | Stable process identifier |

#### File node criterion keys

| Criterion key | `FileNode` field | Notes |
|---|---|---|
| `FileName` | `name` | Basename of the loaded file |
| `Path` | `path` | Full path |
| `Extension` | `extension` | Lowercased, with dot (e.g. `".dll"`) |
| `IsSigned` | `is_signed` | Boolean |
| `IsInjected` | `is_injected` | Boolean |
| `ApiHookingDetected` | `api_hooking_detected` | Boolean |
| `SignatureVendor` | `signature_vendor` | Signing identity string |

#### Behavior criterion keys (behavior steps only)

These keys match against `EXHIBITED` edge attributes rather than node fields directly.

| Criterion key | Edge attribute | Description |
|---|---|---|
| `TargetProcess` | `target` | Target process name, e.g. `"lsass.exe"` |
| `GrantedAccess` | `granted_access` | Access mask hex string, e.g. `"0x1410"` |
| `Behavior_Markers` | `behavior` | Membership test: the behavior string must appear in the given list |

A step that uses any of `TargetProcess`, `GrantedAccess`, or `Behavior_Markers` is treated as a
behavior step. Behavior steps still require `Node_Type: "Process"` for the source node.

### 3.4 Matching Operators

Every criterion value may be a **literal** or an **operator object**:

| Form | Example | Semantics |
|---|---|---|
| Literal | `"rundll32.exe"` | Equality: `actual == value` |
| `{in: [...]}`  | `{in: ["cmd.exe", "powershell.exe"]}` | Membership: `actual in list` |
| `{equals: ...}` | `{equals: false}` | Explicit equality (useful for booleans) |
| `{exists: true}` | `{exists: true}` | Non-null check: `actual is not None` |
| `{exists: false}` | `{exists: false}` | Null check: `actual is None` |
| `{regex: "..."}` | `{regex: ".*comsvcs.*"}` | `re.search(pattern, str(actual)) is not None` |

Regexes are compiled and validated at load time; an invalid pattern raises an error immediately.
The literal form and `{equals: ...}` use Python `==`, so type matters (`"1"` ≠ `1`).

---

## 4. `actionable_hunting_outputs`

Contains a `validation_queries` list with at least one entry. Each entry is a `HuntingQuery`:

| Field | Type | Required | Description |
|---|---|---|---|
| `engine` | `str` | yes | Query language, e.g. `"KQL"`, `"Sigma"` |
| `query` | `str` | one of `query`/`query_path` | Inline query string |
| `query_path` | `str` | one of `query`/`query_path` | Path to a query file (relative to repo root) |

Exactly one of `query` or `query_path` must be present; providing neither or both raises a
validation error.

```yaml
actionable_hunting_outputs:
  validation_queries:
    - engine: "KQL"
      query: >
        DeviceProcessEvents
        | where FileName == 'rundll32.exe'
        and ProcessCommandLine has 'comsvcs'
        and ProcessCommandLine has 'MiniDump'
```

---

## 5. Schema Invariants

The following constraints are enforced by the Pydantic validators and will raise errors at load time
if violated:

1. `extra="forbid"` on every model — unknown YAML keys are rejected.
2. `scenario_id` must be unique across the entire scenarios directory (`load_scenarios` raises on
   duplicate detection).
3. `step_ids` must be exactly `[1, 2, …, N]` with no gaps and no duplicates.
4. Step 1 must have `temporal_link: null` (or omit the field).
5. Steps 2..N must each have a `temporal_link` with `previous_step == step_id - 1`.
6. `max_time_delta_seconds >= min_time_delta_seconds`.
7. `matching_criteria` must contain `Node_Type` set to `"Process"` or `"File"`.
8. Any `{regex: ...}` value must compile without error.
9. `mitre_mappings` must have at least one entry.
10. `applicable_zones` must have at least one entry.

---

## 6. Synth-Friendly Authoring

The scenario simulator (`augur.simulator`) is the **inverse of the normalizer**: given a scenario,
it generates realistic JSONL log fixtures that fire the scenario at 100% proximity. To keep
generated sample data exercisable:

- Use `{regex: "..."}` patterns that match real binary names and typical argument patterns.
- Prefer `{in: [...]}` for small sets of known process names rather than broad wildcards.
- Set `max_time_delta_seconds` to a realistic window (60–300 s for most lateral-movement chains).
- Use `same_host` link scope unless the technique explicitly requires cross-host activity (e.g.
  a lateral movement step from workstation to server).

Each scenario in the current library has a corresponding `<tactic>/<id>_tp.jsonl` fixture in
`sample_data/` that fires at proximity 1.0 and uses technique-accurate command lines.

---

## 7. Annotated Example — SCEN-WIN-001

The canonical Windows scenario `scenarios/credential_access/win_lsass_comsvcs.yaml` demonstrates
all four blocks in a realistic five-step chain:

```yaml
scenario_metadata:
  scenario_id: "SCEN-WIN-001"
  name: "LSASS Credential Dump via comsvcs.dll MiniDump"
  description: >
    Adversary spawns a LOLBin chain (rundll32 -> comsvcs.dll MiniDump) to dump
    LSASS memory for offline credential extraction.
  severity: "CRITICAL"
  mitre_mappings:
    - { tactic: "TA0006", technique: "T1003.001" }
  os_family: "windows"

spatial_constraints:
  applicable_zones: ["User_Endpoint", "Internal_Server"]
  critical_assets_only: false
  required_log_sources: ["Windows_Sysmon", "EDR_Telemetry"]

attack_sequence_flow:
  steps:
    # Step 1 — no temporal_link (this is the anchor)
    - step_id: 1
      name: "Rundll32_Launch"
      matching_criteria:
        Node_Type: "Process"
        ProcessName: { in: ["rundll32.exe"] }    # membership operator
        CommandLine: { regex: ".*comsvcs.*" }     # regex operator

    # Step 2 — same_host, within 60 s of step 1
    - step_id: 2
      name: "MiniDump_CommandLine"
      temporal_link:
        previous_step: 1
        link_scope: same_host
        min_time_delta_seconds: 0
        max_time_delta_seconds: 60
      matching_criteria:
        Node_Type: "Process"
        ProcessName: { in: ["rundll32.exe"] }
        CommandLine: { regex: ".*MiniDump.*" }

    # Step 3 — behavior step; matches EXHIBITED edge attrs
    - step_id: 3
      name: "LSASS_Access_Behavior"
      temporal_link:
        previous_step: 2
        link_scope: same_host
        min_time_delta_seconds: 0
        max_time_delta_seconds: 120
      matching_criteria:
        Node_Type: "Process"
        TargetProcess: "lsass.exe"     # literal equality on edge.target
        GrantedAccess: "0x1410"        # literal equality on edge.granted_access

actionable_hunting_outputs:
  validation_queries:
    - engine: "KQL"
      query: >
        DeviceProcessEvents
        | where FileName == 'rundll32.exe'
        and ProcessCommandLine has 'comsvcs'
        and ProcessCommandLine has 'MiniDump'
```

When this scenario fires at 100% proximity the `/api/detections` response will show:
- `proximity: 1.0`
- `matched_steps: 3`
- `total_steps: 3`
- `affected_hosts: ["HR_User_PC"]` (or whichever host the events were on)

---

## 8. Adding a New Scenario — Checklist

1. Choose the right tactic folder under `scenarios/` (create it if it does not exist).
2. Use a unique ID in `SCEN-WIN/LNX/MAC/CLD-NNN` format; verify no existing scenario uses it.
3. Set `os_family` to match the normalizer that will produce the events.
4. Write `matching_criteria` that accurately describe the observable artifacts — test with regex
   operators against realistic process names and argument strings.
5. Set `temporal_link` windows generously enough to cover real-world jitter but not so wide that
   unrelated benign events could accidentally satisfy the step.
6. Include at least one `mitre_mapping` and one `validation_query`.
7. Run `uv run pytest tests/test_scenario_library.py` — the loader will validate all YAML files
   and flag schema errors immediately.
8. Add a `sample_data/<tactic>/<id>_tp.jsonl` fixture and cover it in
   `tests/test_scenario_tp_fixtures.py` if the scenario is load-bearing.

---

## See Also

- [DATA_MODEL.md](DATA_MODEL.md) — NormalizedEvent fields and graph node attributes
- [ENGINE.md](ENGINE.md) — how steps are matched and proximity is scored
- [API.md](API.md) — REST endpoints for listing scenarios and triggering generation
- [CONTRIBUTING.md](CONTRIBUTING.md) — development workflow and test conventions
