**English** | [Tiếng Việt](../vi/CONTRIBUTING.md)

# Augur — Contributing Guide

This guide covers the full development workflow: environment setup, testing expectations, the invariants you must not break, how to add a scenario, how to add a new log source or OS normalizer, the opt-in extras (Neo4j, gRPC, AI generation), commit conventions, and Make targets. When something is not covered here, the relevant deep-dive doc is linked.

Related docs: [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) | [ARCHITECTURE.md](ARCHITECTURE.md) | [ENGINE.md](ENGINE.md) | [DATA_MODEL.md](DATA_MODEL.md)

---

## Prerequisites

- **Python 3.14 or later** — the project's `pyproject.toml` pins `requires-python = ">=3.14"`.
- **uv** — the sole environment and dependency manager for this project.

Install uv if it is not already present:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Never use bare `pip`, `pip install`, or `python -m venv`** on this project. Every environment operation, including dependency installs, running tests, and running the CLI modules, goes through `uv`.

Optional, for Docker-based workflows:

- **Docker with Compose v2** — needed for `make up` (full containerised stack) or `make neo4j-local`.
- **pnpm** — needed for `make ui-build` or `make ui-dev` (React frontend).

---

## Setup

```bash
git clone <repo>
cd augur
make install   # equivalent to: uv sync
```

`uv sync` reads `pyproject.toml`, creates a `.venv`, and installs:

- **Runtime deps** — `pydantic`, `PyYAML`, `networkx`, `fastapi`, `uvicorn`, `argon2-cffi`, `python-multipart`
- **Dev group** — `pytest`, `httpx2`

The `neo4j`, `grpc`, and `ai` extras are **not** installed by default. See the "Opt-in Extras" section below.

---

## Running Tests

```bash
make test                                      # = uv run pytest -q
uv run pytest -q                               # same — 1164 passed, 3 skipped
uv run pytest -v                               # verbose
uv run pytest -v tests/test_acceptance.py      # one file
uv run pytest -k "test_scoring"               # by keyword
```

Expected baseline: **1164 passed, 3 skipped**. The 3 skipped are the Neo4j integration tests (always skipped unless `AUGUR_NEO4J_TEST=1` — see below).

### TDD expectation

Augur follows Test-Driven Development. Before implementing any new feature:

1. Write a failing test that precisely describes the expected behaviour.
2. Run `uv run pytest -q` and confirm it fails for the right reason.
3. Write the minimum production code to make it pass.
4. Refactor if useful; keep the test green.

The acceptance tests in `tests/test_acceptance.py` and the v2 gate test in `tests/test_scenario_library_v2.py` are the ground truth for engine correctness. Do not adjust their assertions to fit a broken implementation.

---

## Project Layout

```
augur/
├── pyproject.toml              # metadata, deps, pytest config
├── Makefile                    # make help | install | dev | test | engine | demo |
│                               #       demo-min | hunt | up | down | logs | neo4j-local |
│                               #       grpc-demo | ui-dev | ui-build | clean
├── Dockerfile                  # app image (Python 3.14, uv, neo4j extra)
├── docker-compose.yml          # full stack: app + Neo4j 5.26 + named volumes
├── scripts/
│   └── regen_sample_data.py    # regenerates all sample_data fixtures from scenarios
├── src/augur/                  # all production source
│   ├── enums.py                # Severity, Zone, Criticality, LinkScope, SEVERITY_RANK
│   ├── pipeline.py             # build_backend(), default_topology(), default_scenarios()
│   ├── demo.py                 # python -m augur.demo  (serve dashboard / headless)
│   ├── hunt.py                 # python -m augur.hunt  (source → engine → sinks)
│   ├── generate.py             # python -m augur.generate  (LLM candidate generation, [ai])
│   ├── useradmin.py            # python -m augur.useradmin (admin bootstrap)
│   ├── maintenance.py          # python -m augur.maintenance (store retention / prune)
│   ├── topology/
│   │   ├── network.py          # load_topology(), Topology.enrich(host) -> (Zone, Criticality)
│   │   └── standard_topology.yaml
│   ├── scenarios/
│   │   ├── schema.py           # Scenario, Step, TemporalLink, SpatialConstraints (extra=forbid)
│   │   └── loader.py           # load_scenarios(dir) — recursive, dup-id guard
│   ├── ingest/
│   │   └── jsonl.py            # read_jsonl(path) — raises IngestError with line number
│   ├── normalize/
│   │   ├── registry.py         # REGISTRY dict; normalize_event(); source_type dispatch
│   │   ├── model.py            # NormalizedEvent dataclass
│   │   ├── windows_sysmon.py   # source_type "windows_sysmon" (event_id 1/7/"edr")
│   │   ├── linux_auditd.py     # source_type "linux_auditd" (EXECVE/SYSCALL/EDR)
│   │   ├── macos_esf.py        # source_type "macos_esf" (ES_EVENT_NOTIFY_EXEC/MMAP)
│   │   └── ecs.py              # back-compat shim for legacy Windows path (no source_type)
│   ├── graph/
│   │   ├── models.py           # HostNode, ProcessNode, FileNode, Edge dataclasses
│   │   ├── interface.py        # GraphBackend ABC
│   │   ├── networkx_backend.py # default infra-free backend
│   │   ├── neo4j_backend.py    # opt-in Cypher adapter
│   │   └── builder.py         # build_graph(events, topology, backend)
│   ├── engine/
│   │   ├── criteria.py         # match_value(), node_matches(), behavior_edge_matches()
│   │   ├── matcher.py          # match_scenario() — longest-valid-prefix DFS
│   │   ├── scoring.py          # Detection dataclass, build_detection(), rank()
│   │   └── runner.py           # run_engine(backend, scenarios, min_proximity)
│   ├── connectors/             # Source/Sink protocols + run_hunt()
│   ├── auth/                   # session cookies, argon2id, RBAC, CSRF, rate-limit
│   ├── alerting/               # stateful alerts, bands, SOC inbox, autonomous monitor
│   ├── generative/             # opt-in [ai] LLM candidate generation + guardrail gauntlet
│   ├── simulator/              # deterministic multi-OS log generator (PoC feed)
│   ├── metrics/                # MITRE coverage, FP rate, detectability. CLI augur.metrics
│   └── api/app.py              # FastAPI: all routes, RBAC, CSRF, static serving
├── frontend/                   # React 19 + Vite + TS + Tailwind (SOC console SPA)
├── scenarios/                  # 40 *.yaml files in 14 ATT&CK tactic subfolders
│   ├── reconnaissance/
│   ├── resource_development/
│   ├── initial_access/
│   ├── execution/
│   ├── persistence/
│   ├── privilege_escalation/
│   ├── defense_evasion/
│   ├── credential_access/
│   ├── discovery/
│   ├── lateral_movement/
│   ├── collection/
│   ├── command_and_control/
│   ├── exfiltration/
│   └── impact/
├── sample_data/                # per-scenario *_tp.jsonl fixtures + acceptance/ + corpus/
└── tests/                      # pytest suite (flat, no subdirectories)
```

---

## Invariants — Do Not Break

These invariants protect the correctness and portability guarantees of the engine. A PR that violates any of them will not be merged.

### 1. Engine determinism
`match_scenario` must produce identical output for identical inputs. The matcher sorts candidate sets by `(timestamp, element_id)` before DFS. There must be no wall-clock reads, no randomness, and no non-deterministic iteration order anywhere in the scoring path.

### 2. Infra-free default test suite
`uv run pytest` (or `make test`) must pass with **zero external services** — no running Neo4j, no network access, no Docker, no real timers. `NetworkXBackend` is always the default. The three Neo4j tests in `tests/test_neo4j_backend.py` are decorated with `@pytest.mark.skipif(AUGUR_NEO4J_TEST != "1", ...)` and must remain so.

### 3. Topology is authoritative
`Topology.enrich(hostname)` is the only source of truth for zone and criticality. Event-supplied `zone` fields are ignored for constraint evaluation. An unknown host receives `(Zone.Unknown, Criticality.UNKNOWN)` and automatically fails all spatial constraints. Do not bypass this.

### 4. Scenario schema strictness
All pydantic models use `ConfigDict(extra="forbid")`. Add new fields explicitly — never relax to `extra="allow"`. The scenario validator also enforces: `step_ids` must be 1..N contiguous; step 1 must have no `temporal_link`; all subsequent steps must have one with `previous_step == step_id - 1`.

### 5. Proximity formula
`proximity = round(matched_len / scenario.step_count, 4)`. The prefix must be strictly contiguous — a step that fails any gate (spatial, temporal, or link-scope) breaks the chain; later steps cannot contribute. Do not change the formula without updating [ENGINE.md](ENGINE.md) and the acceptance tests.

### 6. Ranking order
`rank()` sorts by `(-proximity, -severity_rank, -latest_ts_epoch)`. Do not change this order.

### 7. No LLM in the default path
The `[ai]` extra (`anthropic` SDK) must never be imported outside `src/augur/generative/`. The default `uv sync` must not pull in the SDK. The generative layer is admin-gated and operates on candidate mutations that pass the deterministic guardrail gauntlet before any human approval.

### 8. `_public()` strips private Detection fields
`api/app.py::_public()` removes any `Detection` field whose name starts with `_` (specifically `_latest_ts`, `_latest_ts_epoch`, `_severity_rank`) before sending API responses. Do not rename these fields without updating `_public()`.

---

## How to Add a Scenario

The full schema reference is in [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md). The steps below are the required checklist.

### 1. Choose ID and tactic folder

Scenario IDs are OS-prefixed: `SCEN-WIN-NNN`, `SCEN-LNX-NNN`, `SCEN-MAC-NNN`, or `SCEN-CLD-NNN`. Pick the next sequential number for the OS family. Place the YAML file in the matching ATT&CK tactic folder:

```
scenarios/<tactic>/<descriptive_name>.yaml
```

For example: `scenarios/credential_access/lsass_comsvcs.yaml`.

### 2. Write the YAML

```yaml
scenario_metadata:
  scenario_id: SCEN-WIN-042
  name: "My New Scenario"
  description: "..."
  severity: HIGH
  os_family: windows           # windows | linux | macos
  applicable_zones:
    - User_Endpoint
  mitre_mappings:
    - tactic: credential_access
      technique: T1003.001
  validation_queries:
    - type: kql
      query: |
        SecurityEvent | where EventID == 4688 ...

steps:
  - step_id: 1
    description: "Step 1 description"
    matching_criteria:
      Node_Type: Process
      process_name: suspicious.exe   # synth-friendly: exact string or simple pattern
  - step_id: 2
    description: "Step 2"
    temporal_link:
      previous_step: 1
      link_scope: same_host
      max_time_delta_seconds: 120
    matching_criteria:
      Node_Type: Process
      process_name: another.exe
```

Key rules:
- `Node_Type` is required in every step's `matching_criteria`.
- Steps 2..N must have `temporal_link` with `previous_step == step_id - 1`.
- Step 1 must **not** have `temporal_link`.
- Include `≥1` `mitre_mapping` and `≥1` `validation_query`.
- Keep criteria synth-friendly (exact strings or simple patterns) — the v2 gate test synthesizes a trace and expects the scenario to fire at 1.0.

### 3. Pass the v2 gate test

This is the most important quality gate. It synthesizes a trace from the scenario, injects it into the engine, and asserts proximity == 1.0:

```bash
uv run pytest tests/test_scenario_library_v2.py -v
```

The test in `test_every_v2_scenario_synthesizes_and_fires_at_1` will fail if your scenario's criteria are too broad (false positives on benign traffic) or too narrow to match the synthesized trace. Iterate until this test is green.

The same file also runs `test_every_v2_scenario_well_formed` (ID format, `os_family`, `step_count >= 3`, `>= 1` MITRE mapping) and `test_v2_covers_all_14_tactics` (library-wide tactic coverage).

### 4. Regenerate sample data

After the v2 gate passes, regenerate the per-scenario TP fixture so the fixture gate test also passes:

```bash
uv run python -m scripts.regen_sample_data
```

This script calls `render_injection` for every scenario, writes one `sample_data/<tactic>/<SCEN-ID>_tp.jsonl` per scenario, and also regenerates the `acceptance/` and `corpus/` fixtures. The resulting files must be committed alongside the scenario YAML.

### 5. Verify the fixture gate

```bash
uv run pytest tests/test_scenario_tp_fixtures.py -v
```

`test_tp_fixture_matches_its_scenario_fully` parametrizes over every `*_tp.jsonl` file and asserts proximity == 1.0. This must pass for your new scenario.

### 6. Run the full suite

```bash
make test   # 1164 passed, 3 skipped — no regressions
```

---

## How to Add a New Log Source / OS Normalizer

All event parsing is dispatched through `src/augur/normalize/registry.py` using the `source_type` field in raw log events.

### 1. Write the normalizer module

Create `src/augur/normalize/<source_type>.py`. The module must expose a `normalize(raw: dict) -> NormalizedEvent | None` function. Return `None` for event types the normalizer does not handle.

Use `windows_sysmon.py` or `linux_auditd.py` as a reference. The function maps raw fields to `NormalizedEvent` (defined in `normalize/model.py`). The `kind` field must be one of `"process_create"`, `"image_load"`, or `"behavior"`.

### 2. Register the normalizer

In `src/augur/normalize/registry.py`, add the new `source_type` key to `REGISTRY`:

```python
from augur.normalize import windows_sysmon, linux_auditd, macos_esf, my_source

REGISTRY: dict[str, ...] = {
    "windows_sysmon": windows_sysmon.normalize,
    "linux_auditd": linux_auditd.normalize,
    "macos_esf": macos_esf.normalize,
    "my_source": my_source.normalize,     # add here
}
```

Events whose `source_type` is absent fall through to the `windows_sysmon` legacy path (no change needed for that).

### 3. Extend NormalizedEvent if needed

If the new source introduces fields not already present in `NormalizedEvent`, add them to `src/augur/normalize/model.py`. Follow the existing naming conventions (snake_case, optional fields default to `None`).

### 4. Update graph construction if needed

If the new kind creates a new node or edge type, add the corresponding branch in `src/augur/graph/builder.py`. If it reuses existing types (another process event, for example), add a branch in the existing `build_graph` logic.

### 5. Update engine criteria if needed

If the new source introduces matchable attributes not already in `PROCESS_KEY_MAP` or `FILE_KEY_MAP`, add them to `src/augur/engine/criteria.py`.

### 6. Write tests

Add normalisation tests in `tests/test_normalize_<source_type>.py` following the patterns in `test_normalize_linux.py` or `test_normalize_macos.py`. Add builder tests in `tests/test_builder.py` if new node/edge types are introduced. All tests must be infra-free.

---

## How to Add an Engine-Blind Telemetry Signal

Some signals (the `dns_query` / `network_connect` kinds added for the IOC threat-intel overlay) feed the **read-only `/api/ioc_match` overlay only** — the engine never sees them. The recipe keeps them strictly additive so engine output stays byte-identical:

1. **Add the field(s) to `NormalizedEvent`** (`normalize/model.py`) — optional, default `None`/empty. Keep them **out** of `criteria.py`'s `PROCESS_KEY_MAP` / `FILE_KEY_MAP` so the engine stays blind to them (e.g. `hashes`, `domain`, `dest_ip`, `dest_port`).
2. **Map the source event → a new `kind`** in the per-OS normalizer (e.g. `dns_query`, `network_connect`).
3. **Add the inverse branch** to the per-OS simulator emitter (`simulator/emitters.py`) so the simulator can generate the signal.
4. **Regenerate sample_data** with `uv run python -m scripts.regen_sample_data`.
5. **Add a graph-equality guard test** proving `build_graph` drops the new kind (zero nodes/edges) so engine output is byte-identical — see `tests/test_graph_blind_multi_os_netintel.py`.

The core invariant holds: the **engine / matcher / scoring / graph code must NEVER change** to add an engine-blind signal. If a signal needs to drive detection, it is no longer engine-blind — add it as a graph node/edge and a criteria key per the section above instead.

---

## How to Add a New Behavior Marker

EDR behavior events produce `EXHIBITED` self-loop edges on `ProcessNode` instances. The `behavior` edge attribute carries a string tag (e.g., `"lsass_access"`, `"shadow_copy_delete"`).

To add a new behavior marker:

1. Add sample events that carry the new behavior string in the relevant `sample_data/*.jsonl` file.
2. Reference the marker in a scenario step using `Behavior_Markers: ["my_new_behavior"]` in `matching_criteria`.
3. No code change is needed unless you need a **new criterion key** beyond the existing `Behavior_Markers`, `TargetProcess`, and `GrantedAccess`. If a new key is needed:
   - Add it to `BEHAVIOR_KEYS` in `src/augur/engine/criteria.py`.
   - Add matching logic to `behavior_edge_matches()`.
   - Update [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md).

---

## Opt-in Extras

Three extras extend Augur with optional capabilities. They must never be imported outside their designated modules and must not appear in the default test run.

### `[neo4j]` — alternative graph backend

```bash
uv sync --extra neo4j
```

Installs the `neo4j` Python driver. The backend is activated by setting `AUGUR_BACKEND=neo4j`. See [ARCHITECTURE.md](ARCHITECTURE.md) for the `GraphBackend` abstraction.

Integration tests (3 in `tests/test_neo4j_backend.py`) are skipped by default. Run them against a live Neo4j instance:

```bash
AUGUR_NEO4J_TEST=1 uv run pytest tests/test_neo4j_backend.py -v
```

These tests must never be added to the default `make test` run.

### `[grpc]` — polyglot gRPC microservice slice

```bash
uv sync --extra grpc
```

Installs `grpcio` and `grpcio-tools`. Used by the Go collector → Python detection engine gRPC demo (`services/`, see ARCHITECTURE.md). Run with `make grpc-demo`.

### `[ai]` — generative scenario candidate layer

```bash
uv sync --extra ai
```

Installs `anthropic`. Enables `python -m augur.generate` and the `/api/generate` + `/api/candidates` API routes (admin-only). The `ANTHROPIC_API_KEY` env var is required at runtime. Nothing auto-enters the scenario library: LLM output runs the full deterministic guardrail gauntlet (schema validation → dedup → FP-guard → detectability check) before a human approves it via the UI or API.

The `[ai]` extra must never be imported anywhere outside `src/augur/generative/`.

---

## Connectors (Sources and Sinks)

The pluggable connector layer in `src/augur/connectors/` decouples log ingestion from the engine and lets detections be fanned out to multiple targets without touching the engine.

| Concept | Interface | Location |
|---------|-----------|----------|
| `Source` | `read() -> Iterable[dict]` | `connectors/base.py` |
| `Sink` / `SinkBase` | `emit(Detection)`, `emit_all(list[Detection])` | `connectors/base.py` |
| Registry | `SOURCES`, `SINKS`, `get_source()`, `get_sink()` | `connectors/__init__.py` |
| Orchestrator | `run_hunt(source, sinks, *, min_proximity, …)` | `connectors/runner.py` |

`run_hunt` pipelines: `source.read()` → `normalize_events` → `build_graph` → `run_engine` → fan detections to every sink. Each sink is isolated — one crashing sink is logged and does not block the others.

Run a hunt from the CLI:

```bash
make hunt
# equivalent to:
uv run python -m augur.hunt \
  --source jsonl --source-arg path=sample_data/corpus/enterprise_day.jsonl \
  --sink stdout --sink jsonl --sink-arg jsonl:path=out/detections.jsonl \
  --min-proximity 0.9
```

Built-in sources: `jsonl`, `directory`, `stdin`. Built-in sinks: `stdout`, `jsonl`, `webhook`, `slack`. Use `AUGUR_WEBHOOK_URL` / `AUGUR_SLACK_WEBHOOK_URL` for webhook URLs.

**Adding a Source:** implement `read(self) -> Iterable[dict]`, register in `SOURCES`, write an infra-free test in `tests/test_connectors.py`.

**Adding a Sink:** subclass `SinkBase`, implement `emit(self, detection: Detection) -> None`, register in `SINKS`, write an infra-free test (use `tmp_path` for file sinks, in-process `ThreadingHTTPServer` for network sinks).

---

## Docker Workflows

### Full containerised stack

```bash
make up      # docker compose up -d --build (also runs ui-build first)
make down    # docker compose down (named volumes persist — use -v to wipe)
make logs    # docker compose logs -f app
```

The compose file starts:
- **app** — FastAPI + React SPA at `http://localhost:8000`, configured with `AUGUR_BACKEND=neo4j` and `NEO4J_URI=bolt://neo4j:7687`.
- **neo4j** — Neo4j 5.26 at port 7474 (browser) + 7687 (Bolt), named volumes `neo4j_data`/`neo4j_logs`.

Named volumes survive `down`/`up` cycles. Use `docker compose down -v` only to wipe stored graph data.

### Neo4j in Docker, engine running locally

```bash
uv sync --extra neo4j
make neo4j-local
# equivalent to:
# docker compose up -d neo4j
# AUGUR_BACKEND=neo4j NEO4J_URI=bolt://localhost:7687 uv run --extra neo4j python -m augur.demo
```

Neo4j defaults: `bolt://localhost:7687`, user `neo4j`, password `augur`. Override with `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`.

---

## Make Targets Reference

Run `make` (or `make help`) for a self-documenting, grouped list. Override tunables on the CLI,
e.g. `make demo PORT=9000`. Each target is annotated with a `## …` comment that `make help` renders.

| Target | What it does |
|--------|-------------|
| `make help` | List all targets, grouped (the default goal) |
| `make install` | `uv sync` — create/update venv |
| `make dev` | Run the API (`:8000`) + Vite dev server (`:5173`) together — hot-reload UI |
| `make test` | `uv run pytest -q` — full suite (1164 passed, 3 skipped) |
| `make engine` | Headless demo on built-in 2-attack sample (`--no-serve`) |
| `make demo` | Dashboard on the full `enterprise_day.jsonl` corpus — `http://127.0.0.1:8000`; bootstraps an `admin`/`dev-password-123` login on a fresh DB |
| `make demo-min` | Dashboard on the minimal 2-attack sample |
| `make hunt` | Corpus → engine → stdout + `out/detections.jsonl` (min-proximity 0.9) |
| `make up` | Build UI then `docker compose up -d --build` (app + Neo4j) |
| `make down` | `docker compose down` |
| `make logs` | `docker compose logs -f app` |
| `make neo4j-local` | Start only Neo4j in Docker; run engine locally against it |
| `make grpc-demo` | Go collector → gRPC → Python engine demo |
| `make ui-dev` | Vite dev server (proxies `/api` to localhost:8000) |
| `make ui-build` | `pnpm build` (deps auto-installed when the lockfile changes) — produces `frontend/dist` |
| `make clean` | Remove `__pycache__`, `.pytest_cache`, egg-info |

---

## Commit Conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <short description, ≤72 characters>

[optional body — explain why, not just what]
```

| Type | When to use |
|------|-------------|
| `feat` | New feature or scenario |
| `fix` | Bug fix |
| `test` | Adding or correcting tests |
| `refactor` | Restructure with no behaviour change |
| `docs` | Documentation only |
| `chore` | Build, CI, tooling |

Examples:

```
feat(scenarios): add SCEN-LNX-014 cron-based persistence scenario
fix(normalize): handle missing is_injected field in EID 7 events
test(acceptance): add no_detection_temporal_gap case for SCEN-WIN-001
docs: update ENGINE.md proximity formula section
chore: bump pydantic to 2.13.4
```

Commit frequently. Small, focused commits are easier to review and bisect.

---

## Code Quality Notes

- **Pydantic models** — all use `ConfigDict(extra="forbid")`. Do not relax to `extra="allow"`.
- **Graph nodes** — plain `@dataclass` objects in `graph/models.py`. Keep them as dataclasses; `api/app.py` uses `dataclasses.asdict()` for serialization.
- **Enum string values** — `Zone`, `Severity`, `Criticality`, `LinkScope` are `str, Enum`. Their `.value` attributes are the canonical strings used in YAML, API responses, and spatial constraint checks.
- **Timestamps** — always `datetime` objects (timezone-aware, from `datetime.fromisoformat()`). Never compare or sort raw ISO strings.
- **No bare `print()` in library code** — only `demo.py` and the CLI entry-points print to stdout. Library code uses logging.
- **Test file naming** — flat in `tests/`, prefixed `test_`. No subdirectories.
- **Infra-free tests** — no real network calls, no subprocesses, no `time.sleep`. Use `tmp_path`, `monkeypatch`, and in-process servers.
