**English** | [Tiếng Việt](../vi/THREAT_MODEL.md)

# Augur — Platform Threat Model

> Threat model for the **Augur platform itself** (not the threats it detects). Scope: the self-hosted
> service — engine, ingestion, web API/UI, auth, the generative (Phase 2) layer, the alerting subsystem,
> and the log simulator. Written against the actual code; residual risks and recommendations are explicit.

Related docs: [ARCHITECTURE.md](ARCHITECTURE.md) | [API.md](API.md) | [CONTRIBUTING.md](CONTRIBUTING.md)

## System assumptions / deployment posture
- **Single-tenant, self-hosted**, run by a trusted operator. No multi-tenant isolation is claimed.
- **TLS is terminated by a reverse proxy** in front of the app; set `AUGUR_COOKIE_SECURE=true` so
  session cookies are HTTPS-only. The app speaks plain HTTP behind the proxy.
- The host OS, filesystem, and the sqlite database file are trusted (filesystem ACLs protect them).
- Operators with `admin` role are trusted; the model defends the boundary *below* admin (viewer/analyst →
  admin, and unauthenticated → authenticated), plus the data/egress surfaces admins can configure.

## Assets
| Asset | Why it matters |
|---|---|
| **Engine + scenario library integrity** | Detection correctness. Tampering = missed/false detections. |
| **Auth store** (`users`, `sessions`, `auth_events`) | Account credentials (argon2id hashes), session tokens. |
| **`AUGUR_SECRET_KEY`** | Session integrity. |
| **`ANTHROPIC_API_KEY`** | Billable, and an egress credential (generative layer). |
| **Alert routing config** (sink definitions in `alert_config`) | May embed webhook tokens/URLs → outbound egress. |
| **Topology + logs** | Hostnames/zones (mildly sensitive); ingested logs (potentially sensitive customer telemetry). |

## Trust boundaries
1. **Unauthenticated → authenticated** (the login boundary; every `/api/*` data route is role-gated).
2. **viewer < analyst < admin** (RBAC via `require_role`).
3. **Untrusted log data → the engine** (ingested JSONL / monitor drop-feed is attacker-influenceable).
4. **The platform → external services** (LLM egress to Anthropic; alert egress to configured Sinks).
5. **Generated/LLM content → the live scenario library** (Phase 2 approval path).

---

## Threats, mitigations, residual risk

### T1 — Authentication & session abuse  *(boundary 1)*
- **Mitigations (in code):** argon2id password hashing; server-side session cookies (`HttpOnly`, `SameSite=Strict`, `Secure` in prod); a fresh session id is minted on login (no fixation); per-username rate-limit + lockout; a constant-time dummy-hash verify for unknown/disabled users (login timing-oracle defense); `AUGUR_SECRET_KEY` **fails closed** in prod; **no default admin password** (env/CLI bootstrap only); CSRF double-submit (`X-CSRF-Token` + `hmac.compare_digest`) on every mutation.
- **Residual risk:** the rate-limiter and lockout are **in-process** (single-box only) — a multi-worker/multi-instance deployment under-counts and weakens brute-force protection. No account-lockout notification, no 2FA.
- **Recommend:** document single-instance-only for the limiter, or move rate-limit/lockout to a shared store; consider optional TOTP for admin.

### T2 — Authorization / privilege escalation  *(boundary 2)*
- **Mitigations:** consistent `require_role` gating; the "cannot disable/delete the last enabled admin" guard; analyst = triage, admin = configure/operate split is applied uniformly (auth, generative, alerting routers).
- **Residual risk:** low. Worth a periodic audit that no new endpoint ships without a role guard (a test that asserts every `/api` route carries a `Depends`).

### T3 — Untrusted log ingestion → engine  *(boundary 3)*  ⭐ key surface
- **Mitigations:** logs are **data, never code** — parsed with `json.loads`/`yaml.safe_load`, normalized into dataclasses, and only *matched against* the graph; no `eval`/`exec`/template execution anywhere in the engine path. Malformed lines raise `IngestError` with a line number. The KQL/Sigma queries in scenarios are **handed to analysts, never executed** by Augur.
- **Note — IOC overlay is engine-blind:** the threat-intel overlay (`/api/ioc_match`) and its backing `NormalizedEvent` fields (`hashes`/`domain`/`dest_ip`/`dest_port`) and event kinds (`dns_query`/`network_connect`) are **read-only and additive**. These fields are deliberately kept out of `criteria.py`'s `PROCESS_KEY_MAP`/`FILE_KEY_MAP`, and `build_graph` drops the new kinds — so the engine/matcher/scoring path never reads them and they **cannot affect detection behavior**. The new telemetry preserves the boundary-3 posture (untrusted log data stays data; the overlay only counts it).
- **Residual risk:** **resource exhaustion / DoS.** A very large or pathological log feed builds an unbounded in-memory NetworkX graph; a scenario regex could be catastrophically backtracking (the generative gauntlet rejects over-broad regexes, but hand-authored scenarios are not regex-DoS-checked). No per-feed size/time budget.
- **Recommend:** cap ingest size/event count per scan; add a regex-safety lint to the scenario loader (timeout or `re2`-style); windowed graph with eviction (see roadmap).

### T4 — Outbound egress via alert Sinks  *(boundary 4)*  ⭐ key surface
- **What:** admins configure alert routing as `{type, url, ...}` sink definitions persisted in `alert_config`; on a scan, the app constructs the Sink and **POSTs to the configured URL** (webhook/Slack/Jira/XSOAR). 
- **Risk:** **SSRF** — an admin (or anyone who reaches admin) can point a sink at internal/cloud-metadata URLs and make the server issue requests to them. Sink **credentials/tokens live in the URL and are stored plaintext** in sqlite. Per-sink failures are isolated (one bad sink can't block others), which is good, but there is **no URL allowlist, no SSRF guard, no secret encryption.**
- **Recommend:** an egress allowlist (scheme/host) for sink URLs; store sink secrets in a secret field, redacted in API responses and audit; block link-local/metadata ranges.

### T5 — Generative (LLM) layer  *(boundaries 4 & 5)*
- **Mitigations:** the `anthropic` SDK is an **opt-in `[ai]` extra**, never imported by the default path; generation is **admin-gated + CSRF + rate-limited + `n`-capped + audited**; the prompt carries only the **public** scenario schema, topology, and exemplars — **no tenant logs, no secrets**; the API key is read only from `ANTHROPIC_API_KEY`. LLM output is **untrusted** and runs the full deterministic gauntlet (schema → dedup → FP-guard → detectability) before a human can approve it; nothing auto-enters the library.
- **Residual risk:** **data egress** — scenario definitions + topology hostnames/zones leave the boundary to Anthropic when generation is enabled (acceptable for many, a non-starter for air-gapped/classified). Prompt-injection of the *library/topology* into the model can't exfiltrate secrets (none are in the prompt) but could bias generated candidates — caught by human approval. Cost abuse is bounded by the rate-limit + cap.
- **Recommend:** make the egress explicit in docs (it already is opt-in); add an org-level "AI disabled" hard switch; log a hash of the prompt context for audit.

### T6 — Generated/approved content → live library  *(boundary 5)*
- **Mitigations:** approval is **admin + CSRF + audited**; the candidate YAML is **re-validated** against the schema at approve time; the write target is constrained — `category` is validated `^[a-z0-9_]+$` at the API boundary **and** the resolved destination is confirmed to be *inside* `scenarios/` (path-traversal blocked), with a `dest.exists()` → 409 guard (no silent clobber). *(These were hardened during Phase 2 review.)*
- **Residual risk:** low. A malicious admin can still author a deliberately bad scenario (any admin can write `scenarios/` directly anyway) — out of model scope (admin is trusted).

### T7 — Secrets at rest
- **Mitigations:** passwords are argon2id (never plaintext). The secret key and API key come from env, not the DB; never logged (audit `detail` carries only non-sensitive fields).
- **Residual risk:** **sink configs (T4) and any future integration creds are stored plaintext in sqlite.** The DB file's confidentiality rests entirely on filesystem ACLs + disk encryption.
- **Recommend:** encrypt sink secrets at rest (or reference an external secret store); document that the sqlite file must be on an access-controlled, ideally encrypted, volume.

### T8 — Monitor drop-feed *(boundary 3 variant)*
- The 3d monitor reads every file in `AUGUR_MONITOR_DIR`. Anyone who can write that directory can inject arbitrary "logs" (→ T3 surface) and could fabricate or suppress detections.
- **Recommend:** the drop-dir must be access-controlled to the same trust level as the operator; document this.

---

## Out of scope (explicit)
Multi-tenant isolation; host/OS hardening; the reverse proxy / TLS config; supply-chain of dependencies;
physical access; a malicious `admin` (admins are trusted by assumption); DoS at the network layer.

## Priority recommendations (highest leverage first)
1. **SSRF guard + secret-at-rest for alert sinks** (T4/T7) — the clearest real gap for a security product.
2. **Ingest resource budgets + scenario regex-safety lint** (T3) — DoS resilience on untrusted input.
3. **Shared rate-limit/lockout store** for multi-instance auth (T1).
4. **An "AI hard-off" switch + prompt-context audit hash** (T5) for regulated/air-gapped deployments.
5. **A route-guard coverage test** (T2) so no future endpoint ships unauthenticated.

**Open items as of this writing:** recommendations 1 (sink SSRF guard + secret-at-rest), 2 (ingest resource budgets + regex-safety lint), and 4 (ingest-DoS budget) above remain unimplemented and are tracked on the roadmap.

*This document reflects the code as of the eval/hardening branch. Re-review when the egress (sinks/LLM)
or ingestion surfaces change.*
