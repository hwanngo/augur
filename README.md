# 🔭 Augur

**Deterministic, AI-free threat-hunting & risk validation.** Augur ingests security logs, projects them
onto a temporal knowledge graph, and scores **how much of each known attack scenario is already present** —
answering one question:

> *"Is this disaster scenario plausibly unfolding inside my org right now — and if so, exactly which one,
> and how far along?"*

The name is the idea: an *augur* reads concrete signs to call what's coming. Augur reads real telemetry —
no LLM, no guessing — and reports a ranked, explainable verdict with ready-to-run KQL/Sigma hunting queries.

---

## 🎯 The one thing that makes Augur different

A **deterministic, longest-valid-prefix proximity engine.** Given an ordered attack scenario (steps 1…N)
and a graph of activity, it finds the longest *contiguous prefix* of steps that all match — each gated by
**spatial** (zone/criticality), **temporal** (time window between steps), and **host-relationship**
(same-host / cross-host) constraints — and scores it:

```
proximity = matched_steps / total_steps        # e.g. 4 of 5 steps present → 0.80
```

There is **no LLM, no randomness, and no wall-clock** anywhere in the scoring path: identical inputs always
produce identical, fully explainable results. Detections are ranked by `(proximity, severity, recency)`.

Everything else in this repo — multi-OS log normalization, auth/RBAC, the connector layer, an optional
generative scenario-authoring assistant, an alerting subsystem, a log simulator, a React console — is
**supporting platform built around that engine**, under a hard invariant: *none of it ever changes the
engine's behavior.*

---

## 📖 Documentation (English · Tiếng Việt)

| | English | Tiếng Việt |
|---|---------|-----------|
| **Start here** | [docs/en/README.md](docs/en/README.md) | [docs/vi/README.md](docs/vi/README.md) |
| 🧸 Explained simply | [docs/en/EXPLAINER.md](docs/en/EXPLAINER.md) | [docs/vi/EXPLAINER.md](docs/vi/EXPLAINER.md) |
| Architecture | [docs/en/ARCHITECTURE.md](docs/en/ARCHITECTURE.md) | [docs/vi/ARCHITECTURE.md](docs/vi/ARCHITECTURE.md) |
| Engine deep-dive | [docs/en/ENGINE.md](docs/en/ENGINE.md) | [docs/vi/ENGINE.md](docs/vi/ENGINE.md) |
| Data model | [docs/en/DATA_MODEL.md](docs/en/DATA_MODEL.md) | [docs/vi/DATA_MODEL.md](docs/vi/DATA_MODEL.md) |
| API reference | [docs/en/API.md](docs/en/API.md) | [docs/vi/API.md](docs/vi/API.md) |
| Scenario format | [docs/en/SCENARIO_FORMAT.md](docs/en/SCENARIO_FORMAT.md) | [docs/vi/SCENARIO_FORMAT.md](docs/vi/SCENARIO_FORMAT.md) |
| Contributing | [docs/en/CONTRIBUTING.md](docs/en/CONTRIBUTING.md) | [docs/vi/CONTRIBUTING.md](docs/vi/CONTRIBUTING.md) |
| 🔐 Threat model | [docs/en/THREAT_MODEL.md](docs/en/THREAT_MODEL.md) | — |

---

## 🚀 Quick start

Two toolchains: [**uv**](https://docs.astral.sh/uv/) (Python 3.14 + venv + deps) and
[**pnpm**](https://pnpm.io/) (the React console). Install both, then:

```bash
make install   # uv sync — Python deps + venv
make test      # uv run pytest  → 634 passed, 3 skipped
make ui-build  # compile the React console into frontend/dist (pnpm; deps auto-installed)
```

> `frontend/dist` is **gitignored**, so run `make ui-build` **once** (and after UI changes) before
> serving the console. Skip it and the API still runs, but serves only a minimal fallback page.

### Spin up the services

**1 · Single process — API + console on one port** (the usual way to demo Augur):

```bash
make ui-build    # once — compile the console (skip if already built)
make demo
# → http://127.0.0.1:8000   (log in as admin / dev-password-123)
```

`make demo` runs the engine on the ~9.6k-event "enterprise day" corpus, then serves the SOC console so
it looks like a live feed. It bootstraps an `admin` / `dev-password-123` login on a fresh DB — override
with `make demo AUGUR_ADMIN_PASSWORD=…` (password ≥ 12 chars, must not contain the username).

**2 · Full hot-reload** (for development) — one command runs both the API (`:8000`, **auto-reloads** on
`src/augur/*.py` changes) and the Vite dev server (`:5173`, **HMR** on UI changes); no `make ui-build`
needed in this mode:

```bash
make dev
# → http://localhost:5173   (edit Python → API restarts; edit UI → instant HMR; Ctrl-C stops both)
```

Prefer two terminals? Run `make dev-api` (auto-reloading API) and `make ui-dev` (Vite) separately — same
result. Note: `make demo` (showcase mode) serves a **static build** with **no** reload — use `make dev`
for development.

**3 · Full container stack — FastAPI + Neo4j:**

```bash
cp .env.example .env     # set AUGUR_SECRET_KEY + AUGUR_ADMIN_PASSWORD
make up                  # builds the UI, runs app (:8000) + Neo4j browser (:7474); make down to stop
```
In prod (`AUGUR_ENV=prod`, as in Docker) the app **fails closed** without `AUGUR_SECRET_KEY` and ships
**no default admin password**. Front it with a TLS-terminating proxy and set `AUGUR_COOKIE_SECURE=true`.

**Headless — no UI, no login** (CI / a quick proof the engine works end-to-end):

```bash
make engine    # run the engine on a planted-attack feed and print ranked detections, then exit
```

```
[CRITICAL] LSASS Credential Dump via comsvcs.dll MiniDump
           SCEN-WIN-001 — 3/3 steps — 100% — hosts: HR_User_PC
[HIGH]     Linux Cron Persistence via Dropped Reverse-Shell Script
           SCEN-LNX-001 — 3/3 steps — 100% — hosts: CORP-JENKINS01
```

Point `--logs` at your own JSONL to hunt real data:
`uv run python -m augur.demo --logs path/to/your.jsonl --min-proximity 0.30 --no-serve`.
`make test` / `make engine` / `make demo` stay infra-free on the NetworkX backend (no Docker/Neo4j).

---

## 🧭 What's in the box

**Core (the differentiator):**
- **Deterministic proximity engine** — longest-valid-prefix scoring with spatial/temporal/host gates.
- **40 real-technique scenarios** across Windows / Linux / macOS (+ cloud-stub), **all 14 MITRE ATT&CK
  tactics**, OS-prefixed IDs (`SCEN-WIN/LNX/MAC/CLD-NNN`), 100% exercisable by the tooling.
- **Multi-OS normalizer** — Windows Sysmon, Linux auditd, macOS ESF → one canonical event model (engine
  untouched; `source_type`-keyed registry, legacy Windows path when absent).
- **Temporal knowledge graph** behind a `GraphBackend` interface — NetworkX (default, infra-free) + Neo4j (opt-in).

**Platform (each built with zero engine change):**
- **Auth/RBAC** (argon2id, server-side sessions, CSRF, viewer/analyst/admin) + a **connector layer**
  (Source/Sink → Slack / Jira / Webhook / Cortex XSOAR / JSONL).
- **Generative assist** (opt-in `[ai]` extra) — an LLM proposes *candidate* scenarios behind a deterministic
  guardrail gauntlet + human approval; nothing auto-enters the library.
- **Alerting** — deduplicated, banded, lifecycle-tracked alerts; notify via the Sinks; a read-only SOC inbox
  (badge + toast); an autonomous, env-gated background monitor.
- **Multi-OS log simulator** — deterministic Windows/Linux/macOS feeds with realistic command lines + attack
  injection (a PoC stand-in for real telemetry).
- **Eval harness** — MITRE coverage, false-positive rate, per-scenario detectability (`python -m augur.metrics`).
- **React SOC console** (Vite + TS, en/vi i18n) served by FastAPI.

**Detection intelligence & response (all additive + read-only — the scoring path is untouched):**
- **Next-step hunting** — each partial detection surfaces the *missing* steps' criteria + timing ("what to
  hunt for next").
- **Explainable near-misses** — *why* a detection stalled (the gate the next step failed + the concrete
  delta), via a read-only `engine/diagnose.py` that reuses the matcher's gate helpers.
- **Proximity momentum** — an honest rising/flat/falling sparkline from running the read-only engine over the
  same corpus at growing time bounds (no fabricated history).
- **Host Risk Board** (`/host-risk`) — hosts ranked by Σ(proximity × criticality × severity).
- **Coverage-Gap Matrix** (`/coverage-gaps`) — a tactics × OS grid of where the library has no coverage for
  the OS families deployed.
- **ATT&CK Navigator export** — a MITRE Navigator v4.5 JSON layer (detections or coverage) that opens in the
  official Navigator.
- **Purple-Team Drill** (`/drill`) — pick a scenario + host; the deterministic simulator injects it, the
  read-only engine runs, the detection surfaces (prove coverage / train).
- **Response Playbooks** — a standard tactic-derived contain/eradicate/recover/validate runbook per detection
  + one-click dispatch through the connector Sinks (infra-free preview default).
- **Alert triage workflow** — assign / resolve / comment, time filters, summary cards, SLA chip, bulk actions.
- **Console quality-of-life** — CSV export, saved filters, keyboard shortcuts, time-range filter,
  PWA-installable, fully responsive.

## 📊 Measured (honestly)

`python -m augur.metrics` reports: **40 scenarios · 14/14 tactics · FP 0.0 · detectability 100%.** Read the
caveats before quoting these: detectability is 100% *by construction* (scenarios authored so the PoC tooling
can exercise them, not a claim of 100% real-world recall); FP is measured on a *simulator-generated* benign
corpus (clean by construction); cloud-stub scenarios approximate cloud activity via endpoint telemetry. The
top follow-up is validating against real telemetry. See [THREAT_MODEL](docs/en/THREAT_MODEL.md) for the
platform's own security surfaces.

## 📂 Layout

```
augur/
├── src/augur/        # ingest · normalize (multi-OS) · graph · topology · scenarios · engine
│                     # + connectors · auth · api · generative · alerting · simulator · metrics
├── scenarios/        # 40 *.yaml across 14 ATT&CK tactic folders (SCEN-WIN/LNX/MAC/CLD-*)
├── sample_data/      # per-scenario TP traces + acceptance fixtures + enterprise_day corpus
│                     # (all regenerable: python -m scripts.regen_sample_data)
├── frontend/         # React + Vite + TS SOC console (en/vi); pages incl. /host-risk · /coverage-gaps · /drill
├── tests/            # pytest suite (infra-free by default: 634 passed, 3 skipped)
├── docs/en · docs/vi # bilingual documentation
└── Makefile · pyproject.toml · Dockerfile · docker-compose.yml
```
