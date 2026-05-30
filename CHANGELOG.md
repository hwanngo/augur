# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Augur is pre-1.0: minor versions may include breaking changes to the API and configuration surface.

## [Unreleased]

### Added
- **Real public-dataset detection.** A real-Sysmon/PowerShell normalizer (`windows_sysmon_real`) and **10
  end-to-end detections** validated on real OTRF / Security-Datasets captures — LSASS dump (T1003.001),
  NTDS.dit & SAM theft (T1003.003 / T1003.002), scheduled-task & Run-key persistence (T1053.005 / T1547.001),
  mshta & BITS proxy-exec (T1218.005 / T1197), fodhelper UAC bypass (T1548.002), process injection
  (T1055, Sysmon EID 8) and malicious PowerShell ScriptBlock (T1059.001, EID 4104). Datasets are fetched at
  runtime (`scripts/fetch_real_datasets.py --suite all`, gitignored) and served via `demo --real all`. Each
  rule maps onto the existing engine with no scoring change and carries an honest "validated on one capture,
  needs a production allowlist" caveat; tests assert the malicious instance fires while the benign baseline does not.
- **FP-tuning allowlist layer** (`augur/tuning/`, `/tuning` console page, `/api/tuning`). A deterministic
  post-engine policy layer to suppress or downgrade known-good detections, with a full always-visible audit
  ledger and a human-gated triage→propose loop (with an advisory rarity baseline hint). An empty allowlist is
  a provable no-op; the engine, scoring, and analysis surfaces always see raw reality.
- **Windowed / streaming graph** (`augur/streaming/`). An opt-in `StreamingGraph` holds a bounded rolling
  time window (O(window) memory, not O(all-history)) via `NetworkXBackend.prune_before`; the eviction cutoff
  derives from event time, never wall-clock. Disabled by default — byte-identical to the full build.
- **Detection-health board, incident clustering / consolidated response / post-incident report, and a hunt
  hypothesis workbench** — additional read-only, deterministic SOC surfaces over the existing detection feed.
- **Threat-intel IOC layer extended** — hash + domain + IP matching with CIDR, IPv6, and URL-host support,
  across multi-OS DNS and network-connect telemetry (engine-blind fields), with honest matchable-vs-unmatchable splits.
- **Modern Cytoscape graph views** — Pivot graph (labels inside nodes, module declutter, hover focus, and a
  detection picker), an Attack Paths kill-chain graph, and a Topology network-map view.
- **Risk-validation harness** — per-step robustness mutations (`--fail-on-robustness`, `--all-steps`) and a
  cross-step criteria-overlap precision diagnostic.
- Frequency-stacking / least-frequency-of-occurrence rarity engine and `/stack` console page (`GET /api/rarity`).
- Production-readiness documentation: `docs/en/CONFIGURATION.md` (+ `docs/vi/` mirror) enumerating every
  environment variable, expanded `.env.example`, `SECURITY.md`, and the Vietnamese `THREAT_MODEL.md` mirror.
- Observability: Prometheus `GET /metrics` (request counts + latency), structured JSON logging
  (`AUGUR_LOG_FORMAT=json`, `AUGUR_LOG_LEVEL`), per-request access log, and `GET /api/ready` readiness probe.
- Operations: `augur.maintenance backup --out` (WAL-safe sqlite online backup) and schema version stamping
  (`PRAGMA user_version`) with a downgrade guard that refuses a DB written by a newer schema.

### Security
- Upgraded the `vitest` dev dependency to 4.1.x, closing the Vitest UI-server arbitrary-file-read/execute
  advisory (the project runs `vitest run` with no UI server, so the risk was not exposed).
- Fixed an unauthenticated path-traversal in the SPA fallback; SSRF guard on sink URLs; per-IP login
  throttle + DB-backed (cross-worker, restart-persistent) rate limiting; strict security headers
  (CSP/HSTS/nosniff/frame-ancestors); pre-auth password-length cap.

### Changed
- CI: parallel test execution (`pytest -n auto`); a per-push fast subset with the full coverage-gated suite
  on a weekly schedule + manual dispatch; cancel-in-progress; docs-only changes skip CI; compact logs.
- The static log feed is read+normalized once (cached) instead of per request, removing a full-corpus
  recompute on windowed / IOC / rarity / timeline endpoints.

## [0.1.0]

Initial public platform release: a deterministic, AI-free proactive threat-hunting and risk-validation
engine, with a platform built *around* it that never changes the engine's behavior.

### Added
- **Engine** — JSONL ingestion → multi-OS normalization (Windows Sysmon, Linux auditd, macOS ESF) →
  temporal knowledge graph (NetworkX default, opt-in Neo4j backend) → deterministic longest-valid-prefix
  scenario matching → proximity-scored, ranked detections. Deterministic by construction (no wall-clock /
  randomness in the scoring path).
- **Scenario library** — 40 OS-prefixed scenarios across all 14 ATT&CK tactics, with a strict pydantic
  schema and a fully regenerable `sample_data/` tree.
- **API + console** — FastAPI app serving data and SOC-analyst routes (detections, host risk, coverage
  gaps, MITRE Navigator export, drill, momentum, handover, attack paths, campaign, timeline, IOC match /
  extract, pivot graph, rarity, playbook, Sigma export, scenarios, topology, metrics) and the React console.
- **Auth** — session-cookie auth with argon2id hashing, RBAC (viewer < analyst < admin), CSRF protection,
  rate-limit/lockout, fail-closed secret key, and env/CLI admin bootstrap.
- **Alerting** — stateful alerts with dedup, severity bands, lifecycle, notify-via-Sinks, a triage workflow,
  inbox UI, and an env-gated background monitor.
- **Hunts** — Hunt Hypothesis Workbench: saved hypotheses with live-recomputed evidence and as-of-verdict snapshots.
- **Generative (opt-in `[ai]` extra)** — LLM candidate scenarios behind a deterministic gauntlet
  (schema → dedup → FP-guard → detectability) plus human approval; never imported by the default path.
- **Simulator** — deterministic multi-OS log generator with profiles, emitters, baseline, injection, and realism.
- **Metrics & exports** — MITRE coverage / FP-rate / detectability reporting and Sigma rule export.
- **Connectors** — Source/Sink protocols with a `run_hunt` CLI (Jsonl/Directory/Stdin/Http sources;
  Stdout/JsonlFile/Webhook/Slack/Jira/CortexXsoar sinks).
- **Docs** — bilingual (English + Vietnamese) README, EXPLAINER, ARCHITECTURE, ENGINE, DATA_MODEL, API,
  SCENARIO_FORMAT, CONTRIBUTING, and THREAT_MODEL.

[Unreleased]: https://github.com/your-org/augur/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/augur/releases/tag/v0.1.0
