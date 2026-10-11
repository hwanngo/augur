**English** | [Tiếng Việt](../vi/CONFIGURATION.md)

# Augur — Configuration Reference

> Every runtime knob is an environment variable. There is no config file; the app reads `os.environ`
> at startup (or per-CLI-invocation). This page enumerates **all** `AUGUR_*`, `NEO4J_*`, and
> `ANTHROPIC_API_KEY` variables, traced to the consuming module in `src/augur/`. Defaults shown are the
> literal fallbacks in code. See [`.env.example`](../../.env.example) for a copy-ready template and
> [THREAT_MODEL.md](THREAT_MODEL.md) for the security posture behind these defaults.

**Required-in-prod legend:** **Yes** = the app fails closed or is unsafe without it when `AUGUR_ENV=prod`.
**Bootstrap** = only consumed once, on a fresh empty user table. **No** = optional / has a safe default.

---

## Core / auth

| Variable | Default | Module | Required in prod |
|---|---|---|---|
| `AUGUR_ENV` | `dev` | `auth/config.py` | Yes — must be one of `dev` / `prod` / `test`; invalid value raises at startup. Drives cookie-secure + secret-key fail-closed. |
| `AUGUR_SECRET_KEY` | *(none)* | `auth/config.py` | **Yes** — session/CSRF signing key. In `prod` a missing value raises `RuntimeError`. In `dev`/`test` an ephemeral key is generated (sessions don't survive restart). |
| `AUGUR_DB` | `data/augur.db` | `auth/config.py`, `generate.py`, `maintenance.py` | No — sqlite path for the shared per-thread connection (auth, alerts, hunts, generative). |
| `AUGUR_COOKIE_SECURE` | *(unset → derived)* | `auth/config.py` | No — overrides the derived default. Defaults to `true` when `AUGUR_ENV=prod`, else `false`. Set to `false` only when prod sits behind a TLS-terminating proxy on plain HTTP. Truthy = `1`/`true`/`yes`/`on`. |
| `AUGUR_ADMIN_USER` | *(none)* | `auth/bootstrap.py` | Bootstrap — initial admin username, created only while the user table is empty. |
| `AUGUR_ADMIN_PASSWORD` | *(none)* | `auth/bootstrap.py` | Bootstrap — initial admin password (paired with `AUGUR_ADMIN_USER`). There is **no** default admin password. |
| `AUGUR_LOGS` | `sample_data/corpus/enterprise_day.jsonl` | `api/app.py`, `alerting/router.py`, `demo.py` | No — JSONL log feed the API/alerting scan reads. Point at your real corpus in prod. |
| `AUGUR_LOG_FORMAT` | `text` | `api/observability.py` | No — `json` for structured log shipping; applied outside the test env. |
| `AUGUR_LOG_LEVEL` | `INFO` | `api/observability.py` | No — root log level (`DEBUG`/`INFO`/`WARNING`/`ERROR`). |
| `AUGUR_TRUST_PROXY` | *(unset → off)* | `auth/config.py` | No — truthy honors `X-Forwarded-For` (first hop) for client-IP/rate-limit. Enable ONLY behind a trusted proxy; otherwise XFF is spoofable. |
| `AUGUR_RL_IP_MAX` | `50` | `auth/config.py` | No — per-IP failed-login cap (across usernames) before lockout; defends password-spray without locking out NAT'd users. |

## Observability

- `GET /metrics` — Prometheus text exposition (HTTP request counts + latency by route template). Unauthenticated like `/api/health` and `/api/ready`; **restrict at the network layer**.
- `GET /api/health` — cheap liveness. `GET /api/ready` — readiness (verifies the auth DB + graph backend; `503` when a dependency is down).

## Graph backend

| Variable | Default | Module | Required in prod |
|---|---|---|---|
| `AUGUR_BACKEND` | *(unset → NetworkX)* | `pipeline.py` | No — set to `neo4j` to use the opt-in Neo4j backend; any other value (or unset) selects the in-memory NetworkX default. |
| `NEO4J_URI` | `bolt://localhost:7687` | `pipeline.py` | Only if `AUGUR_BACKEND=neo4j`. |
| `NEO4J_USER` | `neo4j` | `pipeline.py` | Only if `AUGUR_BACKEND=neo4j`. |
| `NEO4J_PASSWORD` | `augur` | `pipeline.py` | Only if `AUGUR_BACKEND=neo4j` — change the default. |

## Alerting

| Variable | Default | Module | Required in prod |
|---|---|---|---|
| `AUGUR_MONITOR_ENABLED` | *(unset → off)* | `alerting/monitor.py` | No — truthy (`1`/`true`/`yes`/`on`) enables the background monitor loop. |
| `AUGUR_MONITOR_INTERVAL` | `60` | `alerting/monitor.py` | No — monitor poll interval in seconds (float). |
| `AUGUR_MONITOR_DIR` | *(none)* | `alerting/monitor.py` | No — drop-feed directory the monitor scans. **Must be access-controlled** (anyone who can write here can inject logs; see THREAT_MODEL T8). |
| `AUGUR_ALERT_MIN_PROXIMITY` | `0.6` | `alerting/config.py` | No — minimum proximity to raise an alert (clamped `0.0`–`1.0`). |
| `AUGUR_ALERT_AUTO_RESOLVE_CYCLES` | `0` | `alerting/config.py` | No — cycles before an unseen alert auto-resolves (`0` = never). |
| `AUGUR_ALERT_SINKS` | *(none)* | `alerting/acfg.py` | No — JSON object of sink definitions, used only to **seed** alert config on a fresh DB (`{name: {type, ...}}`). |
| `AUGUR_ALERT_RULES` | *(none)* | `alerting/acfg.py` | No — JSON array of alert rules, used only to **seed** alert config on a fresh DB. |
| `AUGUR_SCAN_WINDOW_SECONDS` | `0` | `alerting/router.py` | No — sliding scan window in seconds; `0` or unset = whole feed. |

## Connector CLI (`augur.hunt`)

| Variable | Default | Module | Required in prod |
|---|---|---|---|
| `AUGUR_WEBHOOK_URL` | *(none)* | `hunt.py` | No — default URL injected into the `webhook` sink when `--sink-arg url=...` is omitted. |
| `AUGUR_SLACK_WEBHOOK_URL` | *(none)* | `hunt.py` | No — default URL injected into the `slack` sink when `--sink-arg url=...` is omitted. |

## Retention / maintenance

| Variable | Default | Module | Required in prod |
|---|---|---|---|
| `AUGUR_RETENTION_DAYS` | `90` | `maintenance.py` | No — default age cutoff for the `augur.maintenance prune` CLI (override with `--days`). |

## Generative / AI — opt-in `[ai]` extra

> The generative layer is **never imported by the default path**. These variables matter only when the
> `[ai]` extra is installed and `AUGUR_AI_GENERATOR=claude`. Enabling it causes scenario egress to
> Anthropic (see THREAT_MODEL T5).

| Variable | Default | Module | Required in prod |
|---|---|---|---|
| `AUGUR_AI_GENERATOR` | `fake` | `generative/config.py` | No — `fake` (deterministic stub, default) or `claude` (live LLM). |
| `ANTHROPIC_API_KEY` | *(none)* | `generative/config.py` | Only if `AUGUR_AI_GENERATOR=claude` — billable egress credential; read from env only, never persisted. |
| `AUGUR_AI_MODEL` | `claude-opus-4-8` | `generative/config.py` | No — model id used by the `claude` generator. |
| `AUGUR_AI_MAX_N` | `10` | `generative/config.py` | No — max candidate scenarios requested per generation. |
| `AUGUR_AI_MAX_TOKENS` | `4096` | `generative/config.py` | No — max output tokens per LLM call. |
| `AUGUR_AI_MAX_CALLS` | `30` | `generative/config.py` | No — generation calls per window before a per-admin lockout. |
| `AUGUR_AI_WINDOW_SECONDS` | `900` | `generative/config.py` | No — rate-limit window in seconds for `AUGUR_AI_MAX_CALLS`. |

---

## Minimal production set

For a typical prod deployment (NetworkX backend, no AI, TLS at a reverse proxy):

```bash
AUGUR_ENV=prod
AUGUR_SECRET_KEY=<48+ random bytes>          # required, fails closed
AUGUR_ADMIN_USER=admin                        # first-run bootstrap
AUGUR_ADMIN_PASSWORD=<strong password>        # first-run bootstrap
AUGUR_DB=/data/augur.db                        # persistent, access-controlled volume
AUGUR_LOGS=/data/feed/enterprise_day.jsonl     # your real corpus
AUGUR_COOKIE_SECURE=true                        # or false if proxy serves plain HTTP
```

Everything else has a safe default. Add the Neo4j, alerting, retention, or AI blocks only if you use
those subsystems.
