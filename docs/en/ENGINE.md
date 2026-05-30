**English** | [Tiếng Việt](../vi/ENGINE.md)

# Augur — Detection Engine Deep-Dive

Related documents: [ARCHITECTURE.md](ARCHITECTURE.md) | [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) | [DATA_MODEL.md](DATA_MODEL.md)

---

## Overview

The Augur detection engine answers one question for each scenario: *"given the current knowledge graph,
how much of this attack chain is already present?"* It does this by finding the longest contiguous prefix
of scenario steps that can be satisfied by graph elements — subject to spatial, temporal, and
host-relationship constraints — and expressing the result as a `proximity` score between 0.0 and 1.0.

Three modules implement the engine:

| Module | Responsibility |
|--------|---------------|
| `engine/criteria.py` | Criterion operators and node/edge predicate functions |
| `engine/matcher.py` | Longest-valid-prefix DFS (`match_scenario`) |
| `engine/scoring.py` | Detection construction and ranking (`build_detection`, `rank`) |

`engine/runner.py::run_engine(backend, scenarios, min_proximity)` drives the outer loop: one
`match_scenario` call per scenario, one `build_detection` call for any non-zero match, then `rank`.

---

## Criterion Operators — `engine/criteria.py`

### `match_value(criterion, actual)`

Every field check in the engine bottoms out in `match_value`. It handles five forms:

| Criterion form | Match rule |
|----------------|-----------|
| Bare scalar — `"lsass.exe"`, `false`, `42` | `actual == criterion` |
| `{"regex": "<pattern>"}` | `re.search(pattern, str(actual)) is not None` — pattern is compiled and validated at scenario load time |
| `{"equals": value}` | `actual == value` — useful when the value is a dict literal |
| `{"in": [v1, v2, ...]}` | `actual in [v1, v2, ...]` |
| `{"exists": true/false}` | `(actual is not None) == bool(exists)` — presence/absence check |

An unknown criterion dict key (anything other than `regex`, `equals`, `in`, `exists`) raises `ValueError`
at evaluation time.

### Criterion Key Maps

Scenario step criteria use domain-friendly key names that the engine maps to the dataclass attributes
stored in the graph.

**Process nodes** (`PROCESS_KEY_MAP`):

| Criterion key | `ProcessNode` attribute | Typical content |
|---------------|------------------------|-----------------|
| `ProcessName` | `name` | Image filename, e.g. `"rundll32.exe"` |
| `ProcessPath` | `path` | Full executable path |
| `CommandLine` | `command_line` | Full command-line string |
| `ParentProcessName` | `parent_process_name` | Parent image filename |
| `IntegrityLevel` | `integrity_level` | e.g. `"High"`, `"System"` |
| `ProcessGuid` | `id` | Internal graph node ID (= `process_guid` from the log) |

**File nodes** (`FILE_KEY_MAP`):

| Criterion key | `FileNode` attribute | Typical content |
|---------------|---------------------|-----------------|
| `FileName` | `name` | Filename without path |
| `Path` | `path` | Full file path |
| `Extension` | `extension` | Lower-cased, dot-prefixed, e.g. `".dll"` |
| `IsSigned` | `is_signed` | Boolean |
| `IsInjected` | `is_injected` | Boolean |
| `ApiHookingDetected` | `api_hooking_detected` | Boolean |
| `SignatureVendor` | `signature_vendor` | e.g. `"Microsoft Windows"` |

**Behavior edges** (`BEHAVIOR_KEYS`):

The keys `TargetProcess`, `GrantedAccess`, and `Behavior_Markers` are treated specially. Their presence in
`matching_criteria` marks the step as a **behavior step** (see below).

| Criterion key | `EXHIBITED` edge attribute | Match rule |
|---------------|--------------------------|-----------|
| `TargetProcess` | `attrs["target"]` | `match_value(criterion, attrs["target"])` |
| `GrantedAccess` | `attrs["granted_access"]` | `match_value(criterion, attrs["granted_access"])` |
| `Behavior_Markers` | `attrs["behavior"]` | `attrs["behavior"] in criterion` — criterion must be a list |

### `node_matches(node, criteria)`

Iterates all keys in the criteria dict, skipping `Node_Type` and the three behavior keys. For each
remaining key it:

1. Looks the key up in the appropriate key map (`PROCESS_KEY_MAP` or `FILE_KEY_MAP`).
2. If the key is not in the map, returns `False` immediately.
3. Reads `getattr(node, attr, None)` and calls `match_value(criterion, actual)`.
4. Returns `False` on the first failing criterion; `True` if all pass.

`node_matches_nonbehavior` is an alias of `node_matches` used in the behavior-step path to clarify intent:
only the non-behavior portion of the criteria is checked against the process node; the behavior keys are
checked separately against the EXHIBITED edge.

---

## Matched Elements and Step Types

Each scenario step resolves to exactly one graph *element* — either a node or an edge. The engine
distinguishes two step types:

**Non-behavior step** (`is_behavior_step(criteria) == False`):

- Matches a `ProcessNode` (when `Node_Type = "Process"`) or a `FileNode` (`Node_Type = "File"`).
- Candidate timestamp: the `timestamp` field of the node (set at graph-build time from the event
  timestamp).
- Candidate host: `backend.host_of(node.id)`.

**Behavior step** (`is_behavior_step(criteria) == True`):

- Matches an `EXHIBITED` self-loop edge on a process node.
- The engine first finds `ProcessNode`s whose non-behavior attributes satisfy the criteria, then for each
  such process iterates its `EXHIBITED` edges and checks the behavior attributes.
- Each matching `(process, EXHIBITED_edge)` pair becomes one `Candidate` with a synthetic ID
  `{proc_id}|EXH|{i}` (sequence index within the process's EXHIBITED edges).
- Candidate timestamp: `Edge.timestamp`.
- Candidate host: host of the source process node.

---

## The Longest-Valid-Prefix Algorithm — `engine/matcher.py`

### Pre-computation Phase

Before the DFS begins, `match_scenario` calls `_find_candidates(scenario, step, backend)` for every step.
This function:

1. Calls `backend.find_nodes(node_type, predicate)` (non-behavior) or
   `backend.find_nodes("Process", predicate)` + `backend.edges_from(proc.id, "EXHIBITED")` (behavior).
2. Applies the **spatial gate** to every raw candidate.
3. Returns the surviving candidates sorted by `(timestamp, element_id)`.

If the candidate set for step 1 is empty, `match_scenario` returns `(0, [])` immediately.

### Spatial Gate — `_spatial_ok(host, spatial_constraints)`

A candidate fails the spatial gate — and is removed from the candidate set before DFS starts — if any of:

- `host` is `None` (node has no resolved host).
- `host.zone == Zone.Unknown` (host was not found in the topology file).
- `host.zone.value` is not in `spatial_constraints.applicable_zones`.
- `spatial_constraints.critical_assets_only == True` and `host.criticality != Criticality.CRITICAL`.

Unknown hosts always fail this gate because `topology.enrich()` assigns them `Zone.Unknown`.

### DFS Phase — `extend(idx, prev, chain)`

After pre-computation, the DFS proceeds:

```
best = (0, [])

for each anchor in cands[step 1]:
    call extend(idx=1, prev=anchor, chain=[anchor])

def extend(idx, prev, chain):
    if len(chain) > best[0]:
        best = (len(chain), copy(chain))   # update best at every depth
    if idx >= len(steps):
        return                             # all steps matched — chain is complete
    step = steps[idx]
    for cand in cands[step.step_id]:       # pre-sorted by (timestamp, element_id)
        if not _temporal_ok(prev.timestamp, cand.timestamp, step):
            continue                       # fails time-window gate
        if not _link_ok(prev, cand, step.temporal_link.link_scope):
            continue                       # fails host-relationship gate
        chain.append(cand)
        extend(idx + 1, cand, chain)       # recurse
        chain.pop()                        # backtrack
```

`best` is updated inside the recursion, not only at the leaves. This means if step *k* matches but no
candidate for step *k+1* passes the gates, `best` already holds the length-*k* chain when the recursion
unwinds.

Unrelated events that occur between two matched steps do not break the chain; the algorithm is a
subsequence search over the pre-sorted candidate list, not a sliding-window scan.

### Temporal Gate — `_temporal_ok(prev_ts, cand_ts, step)`

```python
link = step.temporal_link
if cand_ts < prev_ts:
    return False                           # must be non-decreasing
lo = prev_ts + timedelta(seconds=link.min_time_delta_seconds)
hi = prev_ts + timedelta(seconds=link.max_time_delta_seconds)
return lo <= cand_ts <= hi
```

Both `min_time_delta_seconds` (default 0) and `max_time_delta_seconds` are set per step in the scenario
YAML. A step is suppressed if the matched element's timestamp falls outside `[prev + min, prev + max]`.

### Host-Relationship Gate — `_link_ok(prev, cand, scope)`

```python
same = prev.host.hostname.lower() == cand.host.hostname.lower()
if scope == LinkScope.same_host:   return same
if scope == LinkScope.cross_host:  return not same
if scope == LinkScope.any:         return True
```

`link_scope` is set per step in the YAML `temporal_link` block. The default is `same_host`.

---

## Determinism Guarantees

The engine is designed to produce **byte-identical output for identical inputs**. The guarantees are:

1. **Candidate sorting.** `_find_candidates` returns candidates sorted by `(timestamp, element_id)`.
   Both `NetworkXBackend.find_nodes()` and `NetworkXBackend.edges_from()` sort their outputs before
   returning them. The Neo4j backend applies the same ordering via `ORDER BY` in its Cypher queries.

2. **DFS iteration order.** `extend()` iterates sorted candidate lists in a fixed, deterministic order.
   There is no dict or set iteration over Python objects whose ordering is hash-dependent.

3. **Tie-breaking.** `best` is updated with a strict `>` comparison on chain length. When two equally
   long chains are found, the one explored first (earlier timestamp and/or lower element_id) wins.

4. **No external state in the hot path.** No wall-clock reads (`datetime.now()`), no random number
   generation (`random`, `uuid4`), no environment reads inside `match_scenario` or `_find_candidates`.

5. **Stable ranking.** `rank()` sorts by a tuple of floats `(-proximity, -severity_rank,
   -latest_ts_epoch)`. Float comparison is fully deterministic.

6. **Event sort at pipeline entry.** `pipeline.build_backend` sorts the event list by `timestamp` before
   passing it to `build_graph`, so the graph is always built in the same order regardless of file
   concatenation order.

Given identical JSONL input and identical `scenarios/*.yaml`, a detection run will produce the same ranked
list — including identical proximity values, matched step chains, and affected hosts — across machines,
Python invocations, and time.

---

## Proximity Formula

```
proximity = round(matched_prefix_length / scenario.step_count, 4)
```

Where:
- `matched_prefix_length` = `len(chain)` returned by `match_scenario` — the number of steps matched,
  starting from step 1.
- `scenario.step_count` = `len(scenario.attack_sequence_flow.steps)`.
- The result is rounded to 4 decimal places.

**The prefix must be contiguous.** If step *k* cannot be matched (no candidate survives all gates), steps
*k+1* through *N* cannot contribute, even if matching events exist in the graph. This is enforced by the
DFS structure: once `extend` runs out of valid candidates at depth *k*, the chain stops and `best` is not
updated further from that branch.

### Default Reporting Threshold

`run_engine` and `rank` accept a `min_proximity` parameter (default `0.30`). Only detections with
`proximity >= min_proximity` and `proximity > 0` are included in the output.

Examples by step count:

| Step count | Min matched steps to appear | Min proximity |
|------------|-----------------------------|---------------|
| 3 | 1 | 0.3333 |
| 4 | 2 | 0.50 |
| 5 | 2 | 0.40 |
| 10 | 3 | 0.30 |

---

## Ranking Rule

```python
sorted(kept, key=lambda d: (-d.proximity, -d._severity_rank, -d._latest_ts_epoch))
```

The three sort keys in priority order:

1. **Proximity descending** — highest percentage of the attack chain matched comes first.
2. **Severity descending** — `SEVERITY_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}`. The integer
   rank is computed once in `build_detection` and stored in the private field `_severity_rank`.
3. **Most-recent matched event first** — `_latest_ts_epoch` is the Unix epoch float of the latest
   timestamp among all matched step candidates. More recent activity surfaces above older matches at the
   same proximity and severity.

The three private sort fields (`_latest_ts`, `_latest_ts_epoch`, `_severity_rank`) are stripped by
`api/app.py::_public()` before the `Detection` is serialised into the HTTP response.

---

## Detection Dataclass — `engine/scoring.py`

```python
@dataclass
class Detection:
    scenario_id:    str          # e.g. "SCEN-WIN-001"
    name:           str          # scenario human name
    severity:       str          # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    proximity:      float        # round(matched_len / step_count, 4)
    matched_steps:  list[dict]   # [{step_id, name, element_id, host, timestamp}, ...]
    missing_steps:  list[dict]   # [{step_id, name}, ...] for unmatched suffix
    affected_hosts: list[str]    # sorted unique hostnames in the matched chain
    affected_zones: list[str]    # sorted unique zone values in the matched chain
    hunting_queries: list[dict]  # [{engine, query, query_path}, ...]
    _latest_ts:      str         # ISO timestamp of latest matched element (sort only)
    _latest_ts_epoch: float      # Unix epoch float of latest matched element (sort only)
    _severity_rank:  int         # integer rank of severity (sort only)
```

`build_detection(scenario, matched_len, chain)` constructs the `Detection` from the matched chain:
`affected_hosts` and `affected_zones` are derived by iterating the chain's `Candidate.host` fields and
deduplicating. `hunting_queries` comes from `scenario.actionable_hunting_outputs.validation_queries`.

---

## Worked Example: SCEN-WIN-001 LSASS comsvcs Chain

**Scenario:** LSASS Credential Dump via comsvcs.dll MiniDump (`SCEN-WIN-001`), 3 steps, CRITICAL.

```yaml
# scenarios/credential_access/win_lsass_comsvcs.yaml (abridged)
scenario_metadata:
  scenario_id: "SCEN-WIN-001"
  severity: "CRITICAL"
  os_family: "windows"
spatial_constraints:
  applicable_zones: ["User_Endpoint", "Internal_Server"]
attack_sequence_flow:
  steps:
    - step_id: 1
      name: "Rundll32_Launch"
      matching_criteria:
        Node_Type: "Process"
        ProcessName: {in: ["rundll32.exe"]}
        CommandLine: {regex: ".*comsvcs.*"}
    - step_id: 2
      name: "MiniDump_CommandLine"
      temporal_link: {previous_step: 1, link_scope: same_host,
                      min_time_delta_seconds: 0, max_time_delta_seconds: 60}
      matching_criteria:
        Node_Type: "Process"
        ProcessName: {in: ["rundll32.exe"]}
        CommandLine: {regex: ".*MiniDump.*"}
    - step_id: 3
      name: "LSASS_Access_Behavior"
      temporal_link: {previous_step: 2, link_scope: same_host,
                      min_time_delta_seconds: 0, max_time_delta_seconds: 120}
      matching_criteria:
        Node_Type: "Process"
        TargetProcess: "lsass.exe"
        GrantedAccess: "0x1410"
```

**Graph state** after processing `full_detection.jsonl` on host `CORP-WS-01`
(zone = `User_Endpoint`, criticality = `MEDIUM`):

```
HostNode    id="corp-ws-01"  zone=User_Endpoint  criticality=MEDIUM

ProcessNode id="proc-a"  name="rundll32.exe"
            command_line="rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump ..."
            timestamp=T+00:00

ProcessNode id="proc-b"  name="rundll32.exe"
            command_line="rundll32.exe comsvcs.dll MiniDump 636 C:\temp\lsass.dmp full"
            timestamp=T+00:15

EXHIBITED edge  src=proc-b  dst=proc-b
    attrs={behavior="lsass_memory_read", target="lsass.exe", granted_access="0x1410"}
    timestamp=T+00:45
```

**Pre-computation phase:**

```
Step 1 candidates:
  find_nodes("Process", predicate):
    proc-a → ProcessName in ["rundll32.exe"] ✓
              CommandLine matches .*comsvcs.* ✓
    host corp-ws-01 → zone=User_Endpoint ∈ ["User_Endpoint","Internal_Server"] ✓
    proc-b → CommandLine "...MiniDump..." does NOT match .*comsvcs.* ✗
  cands[1] = [Candidate(element_id="proc-a", ts=T+00:00, host=corp-ws-01)]

Step 2 candidates:
  find_nodes("Process", predicate):
    proc-a → CommandLine "comsvcs.dll, MiniDump..." matches .*MiniDump.* ✓
    proc-b → CommandLine "comsvcs.dll MiniDump..." matches .*MiniDump.* ✓
  both pass spatial gate
  cands[2] = [Candidate("proc-a", T+00:00), Candidate("proc-b", T+00:15)]
              (sorted by timestamp then element_id)

Step 3 candidates:  (behavior step — TargetProcess in criteria)
  find_nodes("Process", all):
    proc-b has EXHIBITED edge with target="lsass.exe" and granted_access="0x1410" ✓
  cands[3] = [Candidate("proc-b|EXH|0", T+00:45, host=corp-ws-01)]
```

**DFS phase:**

```
Anchor = proc-a (T+00:00)  →  extend(idx=1, prev=proc-a, chain=[proc-a])
  best = (1, [proc-a])

  Try cand proc-a for step 2:
    temporal_ok? T+00:00 - T+00:00 = 0s, 0 ≤ 0s ≤ 60s ✓
    link_ok? corp-ws-01 == corp-ws-01 (same_host) ✓
    chain = [proc-a, proc-a]  →  extend(idx=2, prev=proc-a, chain=[proc-a, proc-a])
      best = (2, [proc-a, proc-a])
      Try cand proc-b|EXH|0 for step 3:
        temporal_ok? T+00:45 - T+00:00 = 45s ≤ 120s ✓
        link_ok? same_host ✓
        chain = [proc-a, proc-a, proc-b|EXH|0]  →  extend(idx=3, ...)
          best = (3, [proc-a, proc-a, proc-b|EXH|0])
          idx >= len(steps)=3 → return
        chain.pop()
      (no more step-3 cands)
    chain.pop()  → chain=[proc-a]

  Try cand proc-b for step 2:
    temporal_ok? T+00:15 - T+00:00 = 15s ≤ 60s ✓
    link_ok? same_host ✓
    chain = [proc-a, proc-b]  →  extend(idx=2, prev=proc-b, chain=[proc-a, proc-b])
      best stays (3, ...) — 2 < 3
      Try cand proc-b|EXH|0 for step 3:
        temporal_ok? T+00:45 - T+00:15 = 30s ≤ 120s ✓
        link_ok? same_host ✓
        chain = [proc-a, proc-b, proc-b|EXH|0]  →  extend(idx=3, ...)
          best still (3, ...) — 3 not > 3, no update (tie goes to first-found)
          return
        chain.pop()
    chain.pop()
```

**Result:**

```
match_scenario returns: matched_len=3, chain=[proc-a, proc-a, proc-b|EXH|0]

build_detection:
  proximity = round(3 / 3, 4) = 1.0
  severity  = "CRITICAL"
  matched_steps = [
    {step_id: 1, name: "Rundll32_Launch",       element_id: "proc-a",       host: "CORP-WS-01", timestamp: "T+00:00"},
    {step_id: 2, name: "MiniDump_CommandLine",   element_id: "proc-a",       host: "CORP-WS-01", timestamp: "T+00:00"},
    {step_id: 3, name: "LSASS_Access_Behavior",  element_id: "proc-b|EXH|0", host: "CORP-WS-01", timestamp: "T+00:45"},
  ]
  missing_steps  = []
  affected_hosts = ["CORP-WS-01"]
  affected_zones = ["User_Endpoint"]
  _latest_ts_epoch = T+00:45 as Unix float
  _severity_rank   = 3  (CRITICAL)

rank output: Detection(scenario_id="SCEN-WIN-001", proximity=1.0, ...)
  → top of the ranked list
```

### Partial-Match Variant

If only step 1 and step 2 events are present (step 3's LSASS access behavior is absent):

```
cands[3] = []
extend from proc-a → extend from proc-a for step 2 → step 3 has no cands → returns
best = (2, [proc-a, proc-a])

proximity = round(2 / 3, 4) = 0.6667
→ appears in results at min_proximity ≤ 0.6667
missing_steps = [{step_id: 3, name: "LSASS_Access_Behavior"}]
```

### Temporal-Violation Variant

If the LSASS access EXHIBITED edge timestamp is at T+03:00 (180 seconds after step 2 at T+00:00):

```
Step 3 temporal gate (max=120s):
  T+03:00 - T+00:00 = 180s > 120s → _temporal_ok returns False → cand dropped

best = (2, [proc-a, proc-a])  →  proximity = 0.6667
Step 3 is suppressed and appears in missing_steps.
```

---

## Acceptance Test Coverage

The engine behaviour is pinned by the acceptance tests in `tests/test_acceptance.py`:

| Fixture file | Expected outcome |
|---|---|
| `acceptance/full_detection.jsonl` | Scenario matched at `proximity == 1.0` |
| `acceptance/partial_detection.jsonl` | Same scenario at `proximity == 0.6` (or scenario-specific value) |
| `acceptance/no_detection_temporal_gap.jsonl` | No detection (temporal gate fires) |
| `acceptance/no_detection_wrong_zone.jsonl` | No detection (spatial gate fires) |
| `acceptance/no_detection_benign.jsonl` | Zero detections above `min_proximity=0.30` |
| `acceptance/demo_multi_os.jsonl` | Multiple scenarios at correct scores, multi-OS events |

The test suite runs 1164 tests (3 skipped for Neo4j / AI extras). See [CONTRIBUTING.md](CONTRIBUTING.md)
for how to add a new scenario and its acceptance fixture.

## Robustness validation (false-negative boundary)

The engine's precision rests on three gates: **temporal** (`max_time_delta_seconds`), **spatial**
(`applicable_zones`), and **link** (`link_scope`). Every positive validator (detectability, drill,
campaign) proves a scenario *fires*; none proves the engine *correctly stops firing*. A regression that
loosened a gate to always-accept would keep every positive test green while gutting precision.

**Detection-robustness validation** (`augur.metrics.robustness`) closes that blind spot **without
touching the engine**. It mutates a scenario's deterministic synthetic trace and asserts the engine
degrades to the spec-mandated proximity:

| Mutation | What it perturbs | Expected proximity (`n = step_count`) |
|----------|------------------|----------------------------------------|
| `drop_step(k)` | removes step *k*'s events | `round((k-1)/n, 4)` — partial prefix (None if `k == 1`) |
| `stretch_temporal(k)` | pushes step *k* one second past its temporal gate | `round((k-1)/n, 4)` — truncates before *k* |
| `relocate_zone` | retargets every event to an off-zone host | **no detection** (anchor fails the spatial gate) |
| `relink_host(k)` | moves step *k*..end onto a second applicable host, breaking the `same_host` link | `round((k-1)/n, 4)` — truncates before *k* (the link gate rejects the k-1→k hop) |

All **80** inter-step links across the **40** library scenarios are `link_scope: same_host`, so the
only library-realizable link mutation is to move step *k* onto a *different* applicable host than step
*k-1* — which a correct `same_host` gate must reject. The relocated host stays in an applicable zone and
the same criticality class, so `_spatial_ok` still passes and only `_link_ok` can reject (anti-circular
guard). When a scenario's topology offers only one eligible host the row is recorded `no_distinct_host`
and excluded from the pass denominator (mirrors `no_offzone_host`).

The default run exercises the **last** step (the deepest gate) of every scenario. Pass `--all-steps` to
sweep **every** applicable step per gate (`stretch_temporal` & `relink_host` 2..n; `drop_step` and
`relocate_zone` stay last/single), proving the gates reject at *every* prefix position — not just the
deepest. `drop_step` stays last-step-only **by design**: it is not a gate mutation (it removes a step's
events rather than exercising a temporal/spatial/link rejection), and at an *intermediate* step its
matched-prefix is **not** spec-derivable as `(k-1)/n` — the DFS can realize a valid contiguous prefix from
the surviving steps, or a later step's `matching_criteria` can be satisfied by the dropped step's surviving
events (overlapping process predicates).

That last property is itself a real **precision signal about the scenario library**, so `--all-steps` also
emits a separate **criteria cross-step overlap** diagnostic (`criteria_overlap_diagnostic`). It drops each
*non-last* step (k in 1..n-1) and flags scenarios whose chain still matches **above** the naive `(k-1)/n`
truncation. In the current library two scenarios flag: `SCEN-LNX-005` (anchor `bash`/`sh` is a superset of
step 3's `bash`, so a surviving step-3 event re-anchors a 1-step prefix → 0.3333) and `SCEN-MAC-001` (step
2's `{sh,bash,curl}` is a superset of step 3's `curl`, so the full chain completes without step 2's own
events → 1.0). This is **informational, NOT a gate failure** — the three gates reject correctly — and it is
**excluded from the robustness pass/fail aggregate** (it flags potential over-match under partial evidence,
a known benign property of synth-friendly criteria, surfaced honestly rather than scoped away). Expectations are **derived from the schema, not snapshotted** — a test that blessed
"whatever the engine did" would be circular. An **anti-circular sentinel test** monkeypatches `_link_ok`
to always-True and asserts the relink row flips to `unexpected_fire`, proving the assertion binds to the
gate, not the synth.

Run it from the metrics report:

```bash
uv run python -m augur.metrics --fail-on-robustness
uv run python -m augur.metrics --all-steps --fail-on-robustness
```

`--fail-on-robustness` exits non-zero if any gate failed to reject — a CI tripwire. Programmatic:
`detection_robustness(default_scenarios(), default_topology())` returns `{rows, aggregate, honesty_note}`.

**Honesty:** a PASS proves each gate currently *rejects on the scenario library* — a
construction-integrity / regression gate — **NOT** a real-world false-negative-rate claim and **not**
evidence against a live adversary.
