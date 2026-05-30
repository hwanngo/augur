**English** | [Tiếng Việt](../vi/README.md)

# Augur

**Deterministic, AI-free proactive threat-hunting and risk-validation platform.**

Augur answers one question, deterministically and without any LLM: *"Is this attack scenario already unfolding inside my organisation — and if so, exactly which one, and how far along?"*

It ingests raw endpoint logs (JSON Lines), normalises them through multi-OS normalizers to a canonical event schema, projects them onto a temporal knowledge graph enriched with network topology, and scores how much of each pre-defined attack scenario is present. Output is a ranked list of detections — each with a `matched/total` proximity score, a per-step evidence trace, and copy-ready KQL/Sigma hunting queries — surfaced through a FastAPI REST backend and a React SOC console.

No LLM calls in the scoring path. No probabilistic black boxes. Identical inputs always produce identical, fully explainable results.

---

## Why Augur Exists

SOC teams face two compounding problems. The first is **alert fatigue**: conventional tools are optimised to generate as many signals as possible, burying analysts in noise and directing attention almost entirely to yesterday's events. The second is the absence of a **kill-chain validation lens**: even when suspicious events surface, there is no mechanism to automatically ask whether they form early steps of a *specific, named* attack scenario already in progress.

Augur rejects the alert-maximiser model. Instead of asking "does this event look suspicious?", it asks "is kill-chain pattern X already progressing inside this network, and how far along is the attacker?" Every detection is tied to a named, human-authored scenario; every proximity score is a direct measure of how many ordered kill-chain steps have been observed; every result shows the exact steps matched, on which hosts, at which timestamps, and what evidence is still missing.

Augur supports two complementary operations:

- **Active hunting** — given live or recent log data, surface which attack scenarios are actively unfolding, ranked by progression and severity.
- **Posture assessment** — even with no active incident, the proximity scores across all scenarios give a quantitative exposure read. A scenario at 40% proximity is a hunting priority before any alert fires.

---

## The Differentiator: Longest-Valid-Prefix Proximity Scoring

The engine's core concept is simple to state and mechanically precise to compute.

Each scenario is an ordered list of N steps. The engine finds the longest *contiguous prefix* of steps that all match the graph simultaneously, gated by three constraints at each step boundary:

- **Spatial** — is the host in an applicable zone (e.g. `User_Endpoint`, `Active_Directory`)? Unknown hosts automatically fail all spatial gates.
- **Temporal** — did this step occur within the specified time window after the previous step?
- **Link scope** — is this step on the same host (`same_host`), a different host (`cross_host`), or either (`any`)?

```
proximity = round(matched_prefix_length / total_steps, 4)
```

If step 3 fails any gate, steps 4 and 5 do not contribute — the kill-chain must progress in order. Ranking: `(-proximity, -severity_rank, -latest_timestamp)`.

There is no wall-clock read, no random number, and no LLM anywhere in the scoring path. The result is deterministic: run the same logs through the same scenarios and you get the same answer, every time, auditable step by step.

---

## Platform Map

Augur is organised into focused, independently testable subsystems:

| Subsystem | Path | Responsibility |
|-----------|------|----------------|
| **Ingest** | `ingest/` | `read_jsonl(path)` — line-by-line JSONL reader; raises `IngestError` with line number on parse failure |
| **Normalize** | `normalize/` | Multi-OS normalizer registry keyed by `source_type`: `windows_sysmon` (event IDs 1/7/"edr"), `linux_auditd` (EXECVE/SYSCALL/EDR), `macos_esf` (ES_EVENT_NOTIFY_EXEC/MMAP). Absent `source_type` falls back to the legacy Windows path. All paths map to one canonical `NormalizedEvent` (kinds: `process_create`, `image_load`, `behavior`). `ecs.py` is a back-compat shim. |
| **Graph** | `graph/` | `GraphBackend` ABC with two implementations: `NetworkXBackend` (default, zero infra) and `Neo4jBackend` (opt-in). Typed nodes: `HostNode`, `ProcessNode`, `FileNode`. Edge types: `SPAWNED`, `LOADED`, `EXHIBITED`, `RUNS_ON`. `build_graph(events, topology, backend)`. |
| **Topology** | `topology/` | `load_topology()` + `Topology.enrich(host) -> (Zone, Criticality)`. Authoritative source for zone and criticality — event-supplied zone fields are ignored. Unknown host → `(Zone.Unknown, Criticality.UNKNOWN)` → fails all spatial gates. |
| **Scenarios** | `scenarios/` | Pydantic schema (`extra=forbid`): `Scenario`, `Step`, `TemporalLink`, `SpatialConstraints`. Optional `os_family` field (default `windows`). `load_scenarios(dir)` recursively loads + validates all YAML with a duplicate-ID guard. |
| **Engine** | `engine/` | `criteria.py` (match operators), `matcher.py` (longest-valid-prefix DFS, deterministic), `scoring.py` (`Detection`, `build_detection` — additively enriches each missing step with its criteria + temporal window for next-step hunting, `rank`), `diagnose.py` (explainable near-misses: *why* a partial detection stalled — the gate the next step failed plus the concrete delta; read-only, re-uses the matcher's gate helpers, never touches scoring), `runner.py` (`run_engine(backend, scenarios, min_proximity)`). |
| **Connectors** | `connectors/` | `Source`/`Sink` protocols + `run_hunt`. Sources: Jsonl, Directory, Stdin, Http. Sinks: Stdout, JsonlFile, Webhook, Slack, Jira, CortexXsoar. |
| **Auth** | `auth/` | Server-side session cookies (`fs_session`, HttpOnly/SameSite=Strict, Secure in prod), argon2id password hashing, SQLite stores (users/sessions/auth_events), RBAC viewer < analyst < admin, CSRF double-submit, in-process rate-limit/lockout, fail-closed `AUGUR_SECRET_KEY` in prod, env/CLI admin bootstrap with no default password. |
| **Generative** | `generative/` | Opt-in `[ai]` extra. An LLM (`claude-opus-4-8`) proposes candidate mutation scenarios; a deterministic guardrail gauntlet (schema → dedup → fires-on-benign FP-guard → detectability check) plus a human approval gate before anything enters the library. CLI: `augur.generate`. |
| **Alerting** | `alerting/` | Stateful alert lifecycle: dedup by `(scenario_id + hosts)`, bands WATCH/HIGH/CONFIRMED (0.6/0.8/1.0), notify-once-per-band-cross via Sinks, autonomous background monitor (env-gated `AUGUR_MONITOR_ENABLED`). Full SOC triage workflow: assignee + status (open → ack → in_progress → resolved → closed), `/assign` `/status` `/comment`, time filters, summary cards, SLA chip, bulk actions. API + SOC inbox UI. |
| **Response** | `response/` | Response Playbooks: a standard tactic-derived contain/eradicate/recover/validate runbook per detection (`playbook.py`), plus one-click dispatch through the connector Sinks. Infra-free **preview** by default; real Slack/Jira dispatch only via the persisted alert sink config. |
| **Simulator** | `simulator/` | Deterministic multi-OS log generator: per-OS profiles and emitters (inverse of the normalizers), seeded benign baseline, attack injection via `synth`, `--batch`/`--stream` CLI, directory drop-feed for the monitor. `realism.py` provides technique-accurate command lines and real binary paths. |
| **Metrics** | `metrics/` | Eval harness: MITRE coverage, false-positive rate, per-scenario detectability, and `robustness.py` (mutates synthetic traces to prove the engine's temporal/spatial/link gates correctly REJECT — the false-negative boundary, not just that detections fire). `coverage.py` `coverage_gap_matrix` — a tactics×OS grid of where the library has NO coverage for the OS families deployed (cloud-stub coverage folds into windows/linux). CLI: `augur.metrics` — `--fail-on-robustness [--all-steps]` is a CI gate. Detectability 40/40, robustness 100%. |
| **API** | `api/` | FastAPI REST backend. All data routes RBAC-gated. Read-only SOC-analyst layer: `momentum.py` (proximity momentum — an honest rising/flat/falling series from running the engine over the same corpus at growing time bounds; no fabricated history, no persistence), `host_risk.py` (Host Risk Board — hosts ranked by Σ(proximity × criticality × severity)), `navigator.py` (ATT&CK Navigator v4.5 JSON layer export), `drill.py` (Purple-Team Drill — deterministic simulator-injected scenario run, fixed seed + base-time). **Incident IR loop:** `incidents.py` (clusters correlated detections into incidents), `incident_response.py` (consolidated contain/eradicate/recover/validate runbook per incident), `incident_report.py` (post-incident report with markdown export). **Detection Health:** `detection_health.py` (per-scenario liveness — firing / partial / silent / never over the corpus). **Threat-intel overlay:** `ioc.py` + `ioc_extract.py` (match a CTI watchlist — process/image/command/technique + hash/domain/ip/CIDR/IPv6 — or the matchable IOCs extracted from a pasted report (hash/domain/ip/IPv6), across Windows/Linux/macOS synthetic telemetry). All build on the read-only engine; the scoring path is unchanged. |
| **Frontend** | `frontend/` | React 19 + Vite + TypeScript + Tailwind + zustand + react-router v7 + i18next (en/vi). Dark SOC console — PWA-installable, fully responsive (hamburger drawer). |
| **Pipeline** | `pipeline.py` | `build_backend()` / `_select_backend()` wiring layer. |

Top-level CLIs: `augur.demo` (run engine / serve dashboard), `augur.hunt`, `augur.generate`, `augur.useradmin`, `augur.maintenance` (store retention prune).

---

## Scenario Library

The library contains **40 scenarios** with OS-prefixed IDs:

| Prefix | OS family | Count |
|--------|-----------|-------|
| `SCEN-WIN-*` | Windows (Sysmon) | 19 |
| `SCEN-LNX-*` | Linux (auditd) | 13 |
| `SCEN-MAC-*` | macOS (ESF) | 8 |
| `SCEN-CLD-*` | Cloud-stub (tagged with host OS) | included above |

All **14 ATT&CK tactics** are covered across 14 category subfolders (`reconnaissance`, `resource_development`, `initial_access`, `execution`, `persistence`, `privilege_escalation`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `collection`, `command_and_control`, `exfiltration`, `impact`).

Each scenario is grounded in a real MITRE technique, carries at least one `mitre_mapping` and one KQL/Sigma hunting query, and is authored to be synth-friendly — meaning the PoC simulator can exercise it end-to-end.

Canonical anchors:

| ID | Scenario |
|----|---------|
| `SCEN-WIN-001` | LSASS comsvcs MiniDump (credential theft) |
| `SCEN-LNX-001` | cron backdoor (persistence) |
| `SCEN-MAC-001` | osascript stager (execution) |
| `SCEN-CLD-001` | AWS key theft (cloud-stub, credential access) |

Adding a new scenario requires only a YAML file in the appropriate category folder — no code changes. The loader discovers all `*.yaml` files recursively. See [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) for the full schema reference.

---

## Sample Data

All sample data is regenerable via `python -m scripts.regen_sample_data`.

**Per-scenario true-positive fixtures** (`sample_data/<tactic>/<id>_tp.jsonl`): one file per scenario (40 total), native-OS positive traces that fire at 1.0 proximity with realistic values.

**Acceptance fixtures** (`sample_data/acceptance/`, self-documenting names):

| File | Purpose |
|------|---------|
| `full_detection.jsonl` | Complete attack trace → 100% proximity |
| `partial_detection.jsonl` | First 3 of 5 steps → 60% proximity |
| `no_detection_benign.jsonl` | Normal office activity → zero detections (FP guard) |
| `no_detection_temporal_gap.jsonl` | Last step outside time window → chain stops at 80% |
| `no_detection_wrong_zone.jsonl` | Same attack on wrong-zone host → suppressed entirely |
| `demo_multi_os.jsonl` | Realistic multi-OS mix: one full attack + ransomware partial + benign noise |

**Enterprise corpus** (`sample_data/corpus/enterprise_day.jsonl`): approximately 9,616 events across 6 hosts (multi-OS), with 5 planted attacks declared in `corpus/manifest.json`. Used by `make demo` to give the SOC console a realistic-looking feed.

---

## REST API

All data routes are RBAC-gated. The full reference is in [API.md](API.md).

| Category | Endpoints |
|----------|-----------|
| Health | `GET /api/health` |
| Data | `GET /api/detections`, `/api/scenarios`, `/api/topology`, `/api/metrics` |
| Analyst layer | `GET /api/momentum`, `/api/host_risk`, `/api/coverage_gaps`, `/api/navigator_layer`, `/api/detection_health` |
| Incidents | `GET /api/incidents`, `/api/incident_response`, `/api/incident_report/{id}` (`?format=markdown`) |
| Threat intel | `POST /api/ioc_match`, `/api/ioc_extract` |
| Drill | `POST /api/drill` |
| Response | `GET /api/playbook`, `POST /api/dispatch` |
| Auth | `POST /api/auth/login`, `logout`, `me`, `change-password`, `sessions` |
| Users | `GET/POST/PATCH/DELETE /api/users…` |
| Generative | `POST /api/generate`, `GET/POST/DELETE /api/candidates…` |
| Alerting | `GET /api/alerts`, `/api/alerts/summary`, `/api/alerts/{id}`, `POST /api/alerts/{id}/ack`, triage `/assign` `/status` `/comment`, `GET/PUT /api/alerts/config`, `POST /api/alerts/scan` |

CSRF protection is applied to all mutating endpoints. The React SPA is served from `frontend/dist` with SPA fallback routing.

---

## Frontend (React SOC Console)

The frontend is a dark SOC console built with React 19, Vite, TypeScript, Tailwind CSS, zustand for state management, react-router v7, and i18next with English and Vietnamese localisations. The console is **PWA-installable** and **fully responsive** (hamburger drawer on small screens).

Pages: Dashboard, Scenarios, Topology, Host Risk, Coverage Gaps, Detection Health, Incidents, Intel, Drill, Generated, Alerts, Users, Sessions, Account, Audit.

- **Dashboard** — ranked detection cards with proximity bars, per-step breakdown, and KQL/Sigma queries
- **Scenarios** — browse the full scenario library
- **Topology** — visualise the network zone map
- **Host Risk** — Host Risk Board: hosts ranked by Σ(proximity × criticality × severity)
- **Coverage Gaps** — Coverage-Gap Matrix: a tactics×OS grid of where the library has no coverage for the deployed OS families (no Cloud column — cloud-stub folds into Windows/Linux)
- **Detection Health** — per-scenario liveness board: which scenarios are firing, partial, silent, or never over the corpus
- **Incidents** — the SOC IR loop: correlated detections clustered into incidents, each with a consolidated response runbook and a post-incident report (markdown export)
- **Intel** — threat-intel overlay: a CTI watchlist (process/image/command/technique + hash/domain/ip/CIDR/IPv6) or the matchable IOCs extracted from a pasted report (hash/domain/ip/IPv6) → matched across Windows/Linux/macOS synthetic telemetry (honest by construction — documentation-range addresses only)
- **Drill** — Purple-Team Drill: pick a scenario + host → the deterministic simulator injects it into a benign feed → the read-only engine runs → the detection surfaces (training / coverage proof)
- **Generated** — review and approve/reject LLM-generated candidate scenarios
- **Alerts** — SOC inbox with badge + toast notifications and full triage workflow: assignee + status (open → ack → in_progress → resolved → closed), comments, time filters, summary cards, SLA chip, bulk actions
- **Users / Sessions** — admin management
- **Account / Audit** — personal settings and auth event log

The shared **DetectionCard** now also shows next-step guidance, "why it stalled" near-miss diagnostics, a proximity-momentum sparkline, a response-playbook panel, and an "Export ATT&CK Layer" action.

The frontend build is separate from the Python package. `make demo` serves the pre-built `frontend/dist`. To develop the UI, run `pnpm dev` inside `frontend/`.

---

## Quickstart

### Prerequisites

- **Python 3.14+** and **[uv](https://docs.astral.sh/uv/)** — the project's environment manager.

```bash
# Install uv (macOS / Linux)
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Never use bare `pip` or `python -m venv`** — the project is managed exclusively with `uv`.

### Install

```bash
git clone <repo-url> augur
cd augur
make install     # uv sync — creates venv, installs project + dev deps
make ui-build    # pnpm i && pnpm build — compile the React console into frontend/dist
```

> `frontend/dist` is gitignored, so `make ui-build` is required **once** (and after UI changes) before
> the console will be served. Without it the API still runs but serves only a minimal fallback page.
> Prerequisite: **[pnpm](https://pnpm.io/)** (Node ≥ 20).

### Run

**Single process — API + console on one port** (the usual demo):

```bash
make ui-build    # once — compile the console (skip if already built)
make demo
# → http://127.0.0.1:8000  (log in as admin / dev-password-123)
```

`make demo` bootstraps an `admin` / `dev-password-123` login on a fresh DB; override with
`make demo AUGUR_ADMIN_PASSWORD=…` (password ≥ 12 chars, must not contain the username).

**Frontend hot-reload** (UI development) — `make dev` runs the API (`:8000`) and the Vite dev server
(`:5173`) together; no `make ui-build` needed:

```bash
make dev
# → http://localhost:5173   (live reload; Ctrl-C stops both)
```

**Headless / other entrypoints** (no UI, no login):

```bash
make test        # ~1164 passed, 3 skipped (Neo4j + AI opt-in)
make engine      # headless engine run → print ranked detections, exit
```

Direct equivalents (no make):

```bash
uv run pytest -q
uv run python -m augur.demo --no-serve
uv run python -m augur.demo --logs sample_data/acceptance/demo_multi_os.jsonl --min-proximity 0.20
uv run python -m augur.demo --logs sample_data/corpus/enterprise_day.jsonl
```

### Full Docker stack (optional)

```bash
make up     # docker compose up -d --build — FastAPI app + Neo4j 5.26
make down   # docker compose down (named volumes persist)
make logs   # tail app container logs
```

The compose stack runs two services on a dedicated `augur` bridge network:

- **app** (http://localhost:8000) — FastAPI + React console, Python 3.14, `AUGUR_BACKEND=neo4j`, waits for Neo4j healthy.
- **neo4j** (http://localhost:7474 browser, bolt 7687) — Neo4j 5.26, named volumes `neo4j_data`/`neo4j_logs`, credentials `neo4j`/`augur`.

`make test`, `make engine`, and `make demo` **never require Docker or Neo4j** — they use the NetworkX in-memory backend.

---

## Worked Example: A Detection End-to-End

Running `make engine` against `sample_data/acceptance/demo_multi_os.jsonl` produces:

```
========================================================================
Augur — 2 scenario(s) matched (min_proximity=0.3)
========================================================================
[CRITICAL ] Credential Theft via LSASS comsvcs MiniDump
           SCEN-WIN-001 — 5/5 steps — 100% — hosts: HR_User_PC
[CRITICAL ] Ransomware Staging via Shadow Copy Deletion and Mass File Rename
           SCEN-WIN-009 — 3/4 steps — 75% — hosts: File_Server_01
           missing: Ransom_Note_Drop
========================================================================
```

What happened:

1. **SCEN-WIN-001** — all 5 steps (dropper execution → DLL load → LSASS access → credential staging → exfil) matched on `HR_User_PC` (zone: `User_Endpoint`) within their temporal windows. Proximity = 100%. The scenario fires fully confirmed.

2. **SCEN-WIN-009** — 3 of 4 steps matched on `File_Server_01` (zone: `Internal_Server`); the `Ransom_Note_Drop` step was not observed. Proximity = 75%. The attacker has started the ransomware chain but hasn't dropped the ransom note yet — an early warning while there is still time to respond.

3. `Finance_User_PC` showed normal activity (Chrome, Notepad, signed DLLs). **Zero detections** for that host — the engine does not fire on noise.

The dashboard at `http://127.0.0.1:8000` renders each detection as a card with a proximity progress bar, a per-step breakdown (green = matched, grey = missing, each showing host + timestamp + matched evidence), and copyable KQL/Sigma hunting queries. The min-proximity slider can be lowered to surface weaker, earlier-stage signals.

---

## Pipeline Architecture

One direction, each stage behind a clear interface:

```
JSONL logs
    │
    ▼  ingest/jsonl.py          read_jsonl() → list[dict]
    │
    ▼  normalize/<os>.py        normalize_events() → list[NormalizedEvent]
    │                           (multi-OS: windows_sysmon / linux_auditd / macos_esf)
    │
    ▼  graph/builder.py         build_graph() → GraphBackend
    │                           ◀── topology.enrich(host) → (Zone, Criticality)
    │
    ▼  engine/matcher.py        match_scenario() → (matched_len, chain)
    │                           [spatial + temporal + link-scope gates]
    │
    ▼  engine/scoring.py        build_detection() → Detection → rank()
    │
    ▼  api/app.py               FastAPI /api/detections + React SPA
```

The graph layer is abstracted behind `GraphBackend` (ABC in `graph/interface.py`):

| Backend | Module | When to use |
|---------|--------|-------------|
| **NetworkXBackend** | `graph/networkx_backend.py` | Default — zero external deps, all unit tests |
| **Neo4jBackend** | `graph/neo4j_backend.py` | Opt-in via `AUGUR_BACKEND=neo4j` |

Scenario matching, scoring, and API output are identical regardless of backend. Only the graph storage layer changes.

---

## Project Layout

| Path | Responsibility |
|------|----------------|
| `pyproject.toml` | Package metadata, deps, optional extras (`neo4j`, `ai`), pytest config |
| `Makefile` | `install`, `test`, `engine`, `demo`, `up`, `down`, `logs`, `clean`, `neo4j-local` |
| `Dockerfile` | App image (Python 3.14, uv, `neo4j` extra) |
| `docker-compose.yml` | Full app + Neo4j 5.26 stack with persistent named volumes |
| `src/augur/enums.py` | `Severity`, `Criticality`, `Zone`, `LinkScope`, `SEVERITY_RANK` |
| `src/augur/topology/` | `load_topology()`, `Topology.enrich()`, `standard_topology.yaml` |
| `src/augur/scenarios/schema.py` | Pydantic scenario object model (`extra=forbid` throughout) |
| `src/augur/scenarios/loader.py` | `load_scenarios()` — recursive YAML loader with dup-ID guard |
| `scenarios/<tactic>/*.yaml` | 40 scenario definitions across 14 ATT&CK tactic subfolders |
| `src/augur/ingest/jsonl.py` | `read_jsonl()`, `IngestError` |
| `src/augur/normalize/` | Multi-OS normalizer registry: `windows_sysmon`, `linux_auditd`, `macos_esf`, `ecs.py` shim |
| `src/augur/graph/` | `GraphBackend` ABC, `NetworkXBackend`, `Neo4jBackend`, `builder.py`, node/edge models |
| `src/augur/engine/` | `criteria.py`, `matcher.py`, `scoring.py`, `diagnose.py`, `runner.py` |
| `src/augur/connectors/` | `Source`/`Sink` protocols, `sources.py`, `sinks.py`, `runner.py` |
| `src/augur/auth/` | argon2id, sessions, RBAC, CSRF, rate-limit, `router.py`, `users_router.py`, `store.py` |
| `src/augur/generative/` | LLM candidate generation, guardrail gauntlet, `router.py`, `eval.py`, `synth.py` |
| `src/augur/alerting/` | Stateful alert lifecycle + triage workflow, bands, `monitor.py`, `notify.py`, `router.py`, `store.py` |
| `src/augur/response/` | Response Playbooks: `playbook.py` (tactic-derived runbooks), connector-Sink dispatch (preview default) |
| `src/augur/simulator/` | Multi-OS log generator, `profiles.py`, `emitters.py`, `realism.py`, `inject.py` |
| `src/augur/metrics/` | MITRE coverage, FP rate, detectability, `robustness.py` (gate-rejection mutations), `coverage.py` (`coverage_gap_matrix`), `report.py` |
| `src/augur/api/app.py` | FastAPI app, route wiring, SPA fallback; analyst routes `momentum.py`, `host_risk.py`, `navigator.py`, `drill.py`, `detection_health.py`, `incidents.py`, `incident_response.py`, `incident_report.py`, `ioc.py`, `ioc_extract.py` |
| `src/augur/pipeline.py` | `build_backend()`, `_select_backend()` |
| `src/augur/demo.py` | `main()` CLI: `--logs`, `--min-proximity`, `--no-serve`, `--port` |
| `frontend/` | React 19 + Vite + TS + Tailwind + zustand + react-router v7 + i18next |
| `sample_data/` | Per-scenario TP fixtures (40), acceptance fixtures (6), corpus (9,616 events) |
| `tests/` | ~1164 passed, 3 skipped (Neo4j + AI opt-in integration tests) |
| `docs/en/` | This doc set |

---

## Scoring Rule

```
proximity = round(matched_prefix_length / total_steps, 4)
```

- Only a **contiguous prefix** counts. Step 3 failing suppresses steps 4 and 5 entirely.
- Default reporting threshold: **0.30** (configurable: `--min-proximity 0.10` on CLI, `?min_proximity=0.10` on API).
- Ranking: **proximity descending** → **severity descending** (CRITICAL > HIGH > MEDIUM > LOW) → **latest matched event first**.

See [ENGINE.md](ENGINE.md) for the full algorithm description, worked example, and determinism guarantees.

---

## Testing

```bash
make test                                          # ~1164 passed, 3 skipped
uv run pytest -q                                   # same
uv run pytest -v tests/test_acceptance.py          # acceptance surface only
uv run pytest tests/test_scenario_library.py       # validate all 40 scenario YAML files
uv run pytest tests/test_enterprise_corpus.py      # 9,616-event corpus, 5 planted attacks
AUGUR_NEO4J_TEST=1 uv run pytest tests/test_neo4j_backend.py  # Neo4j integration (requires running Neo4j)
```

Key acceptance assertions:

| Test | Assertion |
|------|-----------|
| `test_true_positive` | `full_detection.jsonl` → SCEN-WIN-001 proximity == 1.0 on HR_User_PC |
| `test_partial_proximity` | `partial_detection.jsonl` → SCEN-WIN-001 proximity == 0.6 (3/5 steps) |
| `test_benign_no_detection` | `no_detection_benign.jsonl` → zero detections ≥ 0.30 |
| `test_temporal_gate` | `no_detection_temporal_gap.jsonl` → chain stops, step 5 suppressed |
| `test_spatial_gate` | `no_detection_wrong_zone.jsonl` → detection entirely suppressed |
| `test_multi_os_demo` | `demo_multi_os.jsonl` → SCEN-WIN-001 at 1.0, SCEN-WIN-009 at 0.75 |

Per-scenario TP tests (`tests/test_scenario_tp_fixtures.py`) assert that every one of the 40 `<id>_tp.jsonl` fixtures fires its scenario at exactly 1.0 proximity.

---

## Honest Caveats

These are stated clearly here rather than buried in footnotes:

- **Detectability = 100% is partly by construction.** Scenarios are authored to be synth-friendly so the PoC tooling can exercise them. This is not a claim of 100% real-world recall against adversary logs you did not generate.
- **FP rate = 0.0 is measured on a simulator-generated corpus.** The benign corpus is clean by construction. Real-telemetry validation on production EDR data has not been performed.
- **Cloud-stub scenarios approximate cloud activity via endpoint telemetry.** True CloudTrail, M365, or network normalizers are a future project. `SCEN-CLD-*` scenarios fire based on host-level events that correlate with cloud-targeting behaviour, not native cloud API logs.
- **The simulator and sample data are PoC stand-ins** for real machine logs, not a replacement for integrating Augur with a production SIEM or EDR.

---

## Generative Layer (opt-in)

Augur includes an optional AI-assisted scenario-generation subsystem (`augur.generate`, requires `uv sync --extra ai`). It uses an LLM (`claude-opus-4-8`) to propose candidate mutation scenarios as schema-valid YAML. Before any candidate reaches the library it must pass a deterministic guardrail gauntlet:

1. Schema validation (Pydantic, `extra=forbid`)
2. Deduplication check against existing scenario IDs and names
3. Fires-on-benign guard (the candidate must not fire on the benign corpus)
4. Detectability check (the candidate must fire on a generated TP trace)
5. Human approval via the `/api/candidates` workflow and the Generated page in the React console

Nothing auto-enters the library. The deterministic engine that consumes scenarios is unchanged — generated scenarios flow through the same loader, matcher, and scorer as hand-authored ones.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUGUR_BACKEND` | `networkx` | `neo4j` to use the Neo4j backend |
| `AUGUR_NEO4J_TEST` | unset | Set to `1` to enable Neo4j integration tests |
| `AUGUR_SECRET_KEY` | **required in prod** | Session signing key; fail-closed (no default) |
| `AUGUR_ADMIN_USER` | unset | Bootstrap admin username (env/CLI, no default password) |
| `AUGUR_ADMIN_PASSWORD` | unset | Bootstrap admin password |
| `AUGUR_COOKIE_SECURE` | `false` | Set `true` behind a TLS proxy in production |
| `AUGUR_MONITOR_ENABLED` | unset | Set to `1` to start the autonomous background alert monitor |
| `AUGUR_AI_MODEL` | `claude-opus-4-8` | LLM model for generative subsystem (opt-in) |

---

## Documentation

| Document | Description |
|----------|-------------|
| [EXPLAINER.md](EXPLAINER.md) | Plain-language ELI5 tour: the "smoke-detector for cyber attacks" framing, proximity explained simply, walked through with a concrete example |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Full pipeline design, GraphBackend abstraction, data flow, design decisions, Phase 2 generative seam |
| [ENGINE.md](ENGINE.md) | Matching algorithm deep-dive, scoring formula, criteria operators, determinism guarantees, worked example |
| [DATA_MODEL.md](DATA_MODEL.md) | Log event schema, NormalizedEvent fields, multi-OS normalizer details, graph node/edge models, topology |
| [API.md](API.md) | REST endpoint reference, request/response shapes, curl examples, RBAC notes |
| [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) | Full YAML schema reference, matching operators, `temporal_link` semantics, step-by-step checklist for adding a scenario |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev workflow, TDD expectations, adding log sources, adding behavior markers, commit conventions |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Security threat model for the Augur service itself: auth, CSRF, session management, trust boundaries |

## Running a real dataset in the console

Augur ships a deterministic real-data validation path: a real OTRF Security-Datasets Sysmon capture
(`empire_mimikatz_logonpasswords`) detected by `SCEN-REAL-WIN-T1003-001` (Real LSASS Credential Dump,
T1003.001) at proximity 1.0 CRITICAL on `WORKSTATION5.theshire.local`.

```bash
# 1. Fetch + tag the real OTRF dataset (idempotent; into gitignored datasets/real/).
#    --tag injects "source_type": "windows_sysmon_real" on each record so the registry routes it
#    through the real-Sysmon normalizer.
uv run python scripts/fetch_real_datasets.py --tag empire_mimikatz_logonpasswords

# 2. Serve the console on the real dataset (auto-fetches+tags if step 1 was skipped).
uv run python -m augur.demo --real            # default dataset: empire_mimikatz_logonpasswords
#   → bootstraps admin / dev-password-123, serves http://127.0.0.1:8000
```

Log in (`admin` / `dev-password-123`) and open the Dashboard: `SCEN-REAL-WIN-T1003-001` fires CRITICAL at
1.0 on `WORKSTATION5.theshire.local`, a read-only **REAL DATASET** banner appears, and the IOC overlay's
honesty note reflects real telemetry (destination IPs are real, not RFC-5737 documentation ranges).

**Makefile shortcuts:** `make demo-real` (serve the real-dataset console) · `make dev-real` (hot-reload API + Vite :5173 on the real dataset).

**Wave 1 — six more real detections (EID-1 `process_create` command-line rules):** `SCEN-REAL-WIN-T1003-003-001`
(NTDS.dit via `ntdsutil` IFM, CRITICAL), `SCEN-REAL-WIN-T1003-002-001` (SAM via `esentutl /vss`, HIGH),
`SCEN-REAL-WIN-T1218-005-001` (`mshta vbscript:`, HIGH), `SCEN-REAL-WIN-T1548-002-001` (`fodhelper` UAC bypass —
2-step powershell→fodhelper lineage, HIGH), `SCEN-REAL-WIN-T1197-001` (BITS `bitsadmin /transfer`, MEDIUM),
`SCEN-REAL-WIN-T1053-005-001` (`schtasks /ru system`, HIGH).
Each is validated to fire at proximity 1.0 on its own public OTRF capture and lives in `scenarios_real/`
(never auto-merged into the synth-gated default library). Each carries a top-of-file honesty header:
**real detection on a public capture, demo-clean ≠ production-tuned — needs a production allowlist.**

**Wave 2 — three behavior detections (beyond `process_create` command lines).** These map new Sysmon /
PowerShell EIDs onto the engine's existing `behavior` kind, so they match with **no engine change**:
`SCEN-REAL-WIN-T1055-001` (process injection — Sysmon EID 8 `CreateRemoteThread`, `powershell→LoadLibraryA→notepad`),
`SCEN-REAL-WIN-T1547-001` (Run-key persistence — Sysmon EID 13 `RegistryEvent` SetValue under `CurrentVersion\Run`),
`SCEN-REAL-WIN-T1059-001` (malicious PowerShell ScriptBlock — **EID 4104**, the `System.Management.Automation.Utils`
AMSI/logging-bypass reflection). **Honesty note that shaped Wave 2:** the Wave-1 captures carry EID 8/13 only as
*benign baseline* (csrss→svchost CtrlRoutine, W32Time writes), so Wave 2 fetched **new** OTRF captures where the
technique is the actual malicious instance; the tests assert the malicious instance fires **and** the benign
baseline does not. EID 4104 carries no Sysmon GUID, so its behavior anchors on a deterministic synthetic
per-`(host,PID)` node — an honest "malicious script block seen" signal, not a process-tree claim.

**Real SUITE (all 10 at once):**

```bash
# Fetch + tag every capture (idempotent), then serve all 10 real detections on one Dashboard:
uv run python scripts/fetch_real_datasets.py --suite all
uv run python -m augur.demo --real all          # combined topology, all feeds, non-reload
#   headless gate: uv run python -m augur.demo --real all --no-serve   # prints all 10 real detections
```

`make demo-real-all` is the shortcut. The suite loads the committed combined topology
`datasets/real/topology_wave1.yaml` (a superset of the theshire topology that also declares the
`pandalab.com` DC and both the short + FQDN forms of `WORKSTATION5`). `--real all` is non-reload
(the multi-feed suite can't use the single-path `AUGUR_LOGS` hot-reload); `make dev-real` stays single-dataset.

Headless verification (no browser):

```bash
uv run python -m augur.demo --real --no-serve   # prints the real detection then exits
```

**Known limitation (v1):** the manual alert-scan endpoint and the env-gated background monitor still default
to the synthetic scenarios/topology, so they will not surface the real scenario in `--real` mode. The
Dashboard analyst routes (detections / host risk / timeline / pivot / IOC / rarity) are the v1 deliverable;
threading scenarios/topology into the alerting scan is a clean follow-up.
