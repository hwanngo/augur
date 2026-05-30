**English** | [Tiếng Việt](../vi/API.md)

# Augur — REST API Reference

The Augur API is a FastAPI application (`src/augur/api/app.py`). By default it listens on port
**8000** (`make demo` / `uvicorn augur.api.app:create_app --factory`).

---

## Authentication Model

Augur uses **server-side session cookies** — there are no bearer tokens or API keys.

- **Cookie:** `fs_session` (HttpOnly, SameSite=Strict; Secure in production when
  `AUGUR_COOKIE_SECURE=true`).
- **Passwords** are hashed with argon2id. A timing-equalization dummy verify runs for unknown or
  disabled users to prevent timing-based username enumeration.
- **CSRF protection:** double-submit pattern. `POST /api/auth/login` returns a `csrf_token` in its
  JSON body. All mutating requests (POST/PUT/PATCH/DELETE, except `/login`) must include this token
  in the `X-CSRF-Token` request header. Read-only GETs do not require the CSRF header.
- **Rate limiting / lockout:** in-process per-username counter. Exceeding the configured threshold
  returns `429 Too Many Requests` until the lockout window expires.
- **Roles (RBAC):** `viewer` < `analyst` < `admin`. A higher role satisfies any lower-role gate.
  Unauthenticated requests to gated endpoints return `401 Unauthorized`.

### Login Flow

```
POST /api/auth/login          (form data: username, password)
← 200  { "user": "alice", "role": "admin", "csrf_token": "<token>" }
        Set-Cookie: fs_session=<sid>; HttpOnly; SameSite=Strict

# All subsequent mutating requests:
X-CSRF-Token: <token>
Cookie: fs_session=<sid>
```

---

## SPA and Static Files

When `frontend/dist/` exists (React build output), the app serves it at `/`. Any GET that does not
match an `/api/*` route returns `index.html` (SPA fallback for React Router deep-links). When only
the legacy `src/augur/web/` directory exists, it is served via FastAPI `StaticFiles` with
`html=True`.

---

## Endpoint Reference

Routes are grouped below by functional area. Required roles are the **minimum** needed; admins
always satisfy analyst and viewer gates.

### Health

#### `GET /api/health`

No authentication required.

**Response `200`:**
```json
{ "status": "ok" }
```

---

### Detection Data

All data endpoints require at least `viewer` role.

#### `GET /api/detections`

Returns ranked detections from the current log feed. The detection list is computed once at startup
and filtered per request.

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `min_proximity` | `float` | `0.30` | Minimum proximity score (0.0–1.0); filters the pre-computed list |
| `from` | `str \| null` | `null` | Absolute lower time bound (ISO 8601). Detections whose latest event is before this are excluded |
| `to` | `str \| null` | `null` | Absolute upper time bound (ISO 8601). Detections whose latest event is after this are excluded |

When both `from` and `to` are omitted, the request uses the fast path over the precomputed
detection list. When either is supplied, detections are recomputed for that absolute window.

**Determinism note:** `from`/`to` must be **absolute** ISO 8601 timestamps — the engine never
observes a wall-clock "now". Relative windows (e.g. "last 24h") are resolved by the caller into
absolute bounds before the request. Naive timestamps (no offset) are interpreted as UTC. When only
one bound is given, the other defaults to an open bound (epoch / far future). `min_proximity` is
applied **after** windowing.

**Role required:** `viewer`

**Error responses:**
- `422 Unprocessable Entity` — an unparseable ISO timestamp, or inverted bounds (`from` > `to`)

**Response `200`** — array of detection objects:

| Field | Type | Description |
|---|---|---|
| `scenario_id` | `str` | e.g. `"SCEN-WIN-001"` |
| `scenario_name` | `str` | Human-readable name |
| `severity` | `str` | `"LOW"` / `"MEDIUM"` / `"HIGH"` / `"CRITICAL"` |
| `proximity` | `float` | `round(matched / total, 4)` |
| `matched_steps` | `int` | Contiguous prefix steps matched |
| `total_steps` | `int` | Total steps in the scenario |
| `affected_hosts` | `list[str]` | Hostnames in the matched chain |
| `chain` | `list` | Ordered matched graph nodes |

Private detection fields (`_latest_ts`, `_latest_ts_epoch`, `_severity_rank`) are stripped
by `_public()` and never appear in responses.

**Next-step hunting (F1).** Each entry in `missing_steps` additively carries — alongside the
existing `step_id` and `name` — the step's `matching_criteria` (the field/operator/value dict, with
JSON-native scalars) and `temporal`: the serialized temporal link (`previous_step`, `link_scope`,
`min_time_delta_seconds`, `max_time_delta_seconds`) or `null` for step 1 / steps without a link.
This lets the console render *what to look for next* on a partial detection. Consumers that read only
`step_id`/`name` are unaffected (the keys are purely additive).

**Stall diagnosis (F3).** A sub-100% detection (proximity `< 1.0`, with `matched_len ≥ 1`)
additionally carries an additive read-only `stall` object explaining why the **first un-matched step
(k+1)** stalled. It is **absent on full (100%) detections**. The diagnosis is computed **once per
window and cached** (inside the detection builders — never on the hot per-request path) and never
mutates the scoring path. Its `kind` is one of:

| `kind` | Extra fields | Meaning |
|---|---|---|
| `no_candidate` | `step_id`, `step_name` | No event resembling the step was seen at all |
| `temporal` | `step_id`, `host`, `delta_seconds`, `window_seconds` | Closest candidate overshot the temporal window |
| `spatial` | `step_id`, `host`, `zone`, `applicable_zones` | Candidate host is in a non-applicable zone |
| `link` | `step_id`, `host`, `link_scope` | Candidate violates the step's same/cross-host link scope |

**Proximity momentum (F2) is deferred** — there is no momentum/trend field on this response today.

#### `GET /api/host_risk`

Returns a ranked **per-host risk board** answering *"which host do I investigate first?"*. Risk is
aggregated over the same detection feed as `/api/detections`, joined against the authoritative
topology, and **server-sorted by risk descending**.

**Query parameters:** identical to `GET /api/detections` (the same source-selection and windowing
branch is reused):

| Parameter | Type | Default | Description |
|---|---|---|---|
| `min_proximity` | `float` | `0.30` | Minimum proximity score; filters detections **before** aggregation |
| `from` | `str \| null` | `null` | Absolute lower time bound (ISO 8601) |
| `to` | `str \| null` | `null` | Absolute upper time bound (ISO 8601) |

When both `from`/`to` are omitted the fast path over the precomputed detection list is used; when
either is supplied detections are recomputed for that absolute window. `min_proximity` is applied
**after** windowing, before aggregation.

**Role required:** `viewer`

**Error responses:**
- `422 Unprocessable Entity` — an unparseable ISO timestamp, or inverted bounds (`from` > `to`)

**Scoring formula.** Each detection contributes to every host in its `affected_hosts`:

```
contribution = proximity × CRIT_WEIGHT[criticality] × SEV_WEIGHT[severity]
host.score    = round(SUM of contributions, 4)
```

with `SEV_WEIGHT = {LOW:1, MEDIUM:2, HIGH:3, CRITICAL:4}` (string-keyed) and
`CRIT_WEIGHT = {CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, UNKNOWN:1}` (criticality from the topology,
which is authoritative — event zones are ignored). Rows are sorted by `(-score, hostname asc)`, so
clean hosts (`score == 0`) sort to the bottom.

**Bands** are derived from the score: `CRITICAL` ≥ 8, `HIGH` ≥ 4, `WATCH` ≥ 1.5, `LOW` > 0,
`CLEAR` = 0.

**Host set.** Every topology asset is returned (clean hosts appear as `CLEAR`), plus any
off-topology hosts that appear in detections (returned with zone `Unknown` / criticality `UNKNOWN`).
Hostnames are matched case-insensitively; the topology's canonical casing is used for display.

**Response `200`** — `{ "hosts": [...] }` where each host object is:

| Field | Type | Description |
|---|---|---|
| `hostname` | `str` | Canonical (topology) display name, or first-seen casing if off-topology |
| `zone` | `str` | Zone from `Topology.enrich` (`Unknown` if off-topology) |
| `criticality` | `str` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `UNKNOWN` |
| `score` | `float` | `round(SUM(proximity × CRIT_WEIGHT × SEV_WEIGHT), 4)` |
| `band` | `str` | `CRITICAL` / `HIGH` / `WATCH` / `LOW` / `CLEAR` |
| `detection_count` | `int` | Number of contributing detections |
| `max_proximity` | `float` | Highest proximity among contributing detections (`0` if clean) |
| `top_severity` | `str \| null` | Highest severity among contributing detections (`null` if clean) |
| `top_scenarios` | `list` | Up to 3 top contributors, ordered by `(contribution desc, scenario_id asc)` |

Each `top_scenarios` entry is `{ scenario_id, name, severity, proximity }`.

This endpoint is **read-only and additive**: it runs no engine pass and never imports the scoring /
matcher path, so engine determinism is preserved. Two identical calls return identical output.

#### `GET /api/momentum`

Returns a per-scenario **proximity-momentum** signal answering *"is this attack still advancing right
now?"*. For each scenario it reports whether proximity is *rising / flat / falling* across time, plus a
sparkline-ready point series, a delta and a velocity. The series is a **genuine** time series built from
real windowed engine runs over the same corpus feed — nothing is invented, interpolated, or persisted.

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `min_proximity` | `float` | `0.30` | Floor on the full-window proximity; selects the scenario set projected into series |
| `steps` | `int` | `6` | Number of time bounds (sparkline points); **clamped to 3–12** |
| `from` | `str \| null` | `null` | Absolute lower bound (ISO 8601) — **clamps the grid span only** (see below) |
| `to` | `str \| null` | `null` | Absolute upper bound (ISO 8601) — clamps the grid span only |

**Role required:** `viewer`

**Error responses:**
- `422 Unprocessable Entity` — an unparseable ISO timestamp, or inverted bounds (`from` > `to`)

**Response `200`:**

```json
{
  "from": "1970-01-01T00:00:00+00:00",
  "to":   "9999-12-31T00:00:00+00:00",
  "bounds": ["<iso>", "... × N"],
  "series": [
    {
      "scenario_id": "SCEN-WIN-001",
      "points": [0.25, 0.5, 0.75, 1.0],
      "trend": "rising",
      "delta": 0.75,
      "velocity": 0.25
    }
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `from` / `to` | `str` | The (echoed) request bounds, ISO 8601 |
| `bounds` | `list[str]` | The `N == steps` cumulative upper bounds, ISO 8601, strictly ascending |
| `series[].scenario_id` | `str` | Scenario id (joined onto `/api/detections` by the Dashboard) |
| `series[].points` | `list[float]` | `round(proximity_at_bound_i, 4)`, or `0.0` if absent at that bound (length `N`) |
| `series[].trend` | `str` | `"rising"` (delta > 0.05) / `"falling"` (delta < −0.05) / `"flat"` |
| `series[].delta` | `float` | `round(points[-1] - points[0], 4)` |
| `series[].velocity` | `float` | `round(delta / (N - 1), 4)` |

**Semantics.** Windows are **cumulative**: every window's lower bound is `_EPOCH_MIN` (epoch); the `N`
upper bounds are evenly spaced over the corpus event-time span `[min_ts, max_ts]` with `t_N == max_ts`
(`t_i = min_ts + (max_ts − min_ts) × i / N`). Because a multi-step attack's events accrue over time,
widening the window reveals more matched prefix steps → a real ascending curve. Each `t_i` keys the
shared, LRU-cached `_windowed_cached(_EPOCH_MIN, t_i)` (maxsize bumped 16→32 so momentum's ≤12 bounds
plus detection windows don't thrash) — so the cost is **N engine passes total**, scenario-independent,
not N × scenarios. The scenario set is the full-window result at `t_N` whose proximity ≥ `min_proximity`.

Honesty / edge notes:
- `from`/`to` clamp **only the grid span** `[min_ts, max_ts]` (intersected with `[from, to]`); the window
  lower bound stays `_EPOCH_MIN` (the series remains cumulative).
- A single-timestamp feed (`min_ts == max_ts`) collapses every bound to `max_ts` → a flat full-height
  line, `trend = "flat"` (the honest signal, not a bug); no divide-by-zero.
- Offset-less ("naive") source timestamps are assumed-UTC so the windowed comparison never raises.
- An empty feed returns `{ "bounds": [], "series": [] }`.

**Determinism.** Absolute bounds only — the grid is derived from event timestamps (startup-cached
`corpus_time_span`), **never `now`**. Same feed + same `from`/`to`/`steps`/`min_proximity` → identical
bounds → identical cached windowed results → byte-identical series.

**Accrual path (no-op seam).** This endpoint computes momentum **live** from real windowed engine runs;
nothing is persisted. The `alerting/scan.py::record_proximity` seam stays a **no-op** — the alerting
**monitor (`alerting/monitor.py`) is the documented production accrual path** for a future persisted
`proximity_samples` build.

#### `GET /api/handover`

The **shift-handover board diff**: *"what changed on the board since the last shift?"* It re-runs the
read-only windowed engine at two shift boundaries (`to=from` vs `to=to`) and diffs the two **real** board
states — the `N=2` case of the momentum mechanism. Nothing is fabricated or persisted; both states are
genuine states of the same corpus at two real timestamps.

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `min_proximity` | `float` | `0.30` | Proximity floor (applied to both windows; a scenario in scope clears it in *either* window) |
| `from` | `str \| null` | corpus **midpoint** | Shift-start boundary (ISO 8601). Default `_corpus_min_ts + (_corpus_max_ts − _corpus_min_ts)/2` |
| `to` | `str \| null` | corpus **max** | Shift-end boundary (ISO 8601). Default `_corpus_max_ts` |

**Role required:** `viewer`

**Error responses:**
- `422 Unprocessable Entity` — an unparseable ISO timestamp, or inverted bounds (`from` > `to`)

**Response `200`:**

```json
{
  "window": { "from": "<iso>", "to": "<iso>" },
  "meta": { "min_proximity": 0.30, "basis": "corpus-windowed", "deterministic": true },
  "detections": {
    "new":       [{ "scenario_id": "...", "name": "...", "severity": "HIGH",
                    "proximity_prior": null, "proximity_current": 0.9, "proximity_delta": 0.9,
                    "band_prior": null, "band_current": "HIGH", "band_changed": true,
                    "affected_hosts": ["..."] }],
    "escalated": [], "decayed": [], "gone": [], "unchanged_count": 0
  },
  "host_risk": { "entered": [], "left": [], "escalated": [], "deescalated": [] },
  "summary": { "counts": { "new": 1, "escalated": 0, "decayed": 0, "gone": 0, "unchanged": 0,
                           "hosts_entered": 0, "hosts_left": 0,
                           "hosts_escalated": 0, "hosts_deescalated": 0 } }
}
```

| Field | Type | Description |
|---|---|---|
| `detections.new` | `list` | In the current board, absent in the prior (`proximity_prior == null`) |
| `detections.escalated` / `decayed` | `list` | In both; proximity (or band) rose / fell. Each carries `proximity_prior→current` + `proximity_delta` |
| `detections.gone` | `list` | In the prior board, no longer matching at all (`proximity_current == null`) |
| `detections.unchanged_count` | `int` | In both with identical proximity (not listed) |
| `host_risk.entered` / `left` | `list` | Hosts that crossed onto / off the risk board (`band != CLEAR`) between the two windows |
| `host_risk.escalated` / `deescalated` | `list` | On the board in both; risk score rose / fell |
| `summary.counts` | `object` | Per-bucket counts for the at-a-glance handover line |

**Semantics.** Like momentum, the two engine passes are **cumulative from `_EPOCH_MIN`** (prefix matching
needs the full pre-boundary history); the `from`/`to` bounds are the **shift edges**, not window floors.
Both passes hit the shared `_windowed_cached` LRU. A scenario that decays *below* the floor stays
`decayed` (still matching, weaker); `gone` means it no longer matches at all. This endpoint is the
**board diff** over corpus-event-time; the **triage diff** (assignments / resolutions during the shift)
lives on a separate wall-clock endpoint — see `GET /api/triage_handover` below.

**Determinism.** Absolute bounds only, derived from the startup-cached `corpus_time_span`, **never
`now`**. Same feed + same `from`/`to`/`min_proximity` → byte-identical diff. Read-only and additive — the
scoring/matcher path is untouched. An empty feed returns a well-formed all-empty diff.

#### `GET /api/triage_handover`

The **triage half** of shift handover — *"what did the team do this shift?"* — over **operator
wall-clock** time (deliberately distinct from the corpus-event-time board diff in `/api/handover`; the two
clocks are never mixed in one payload). Partitions the persisted alert lifecycle into buckets within an
explicit window.

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `from` | `str \| null` | store activity-span min | Wall-clock lower bound (ISO 8601) |
| `to` | `str \| null` | store activity-span max | Wall-clock upper bound (ISO 8601) |

**Role required:** `viewer`. **Errors:** `422` on unparseable / inverted bounds.

**Response `200`:**

```json
{
  "window": { "from": "<iso>|null", "to": "<iso>|null" },
  "meta": { "basis": "alert-lifecycle-wallclock", "deterministic": true },
  "triage": {
    "new_alerts": [{ "alert_id": "...", "scenario_id": "...", "scenario_name": "...",
                     "severity": "HIGH", "assignee": "", "status": "open",
                     "ts": "<iso>", "ts_field": "created_at" }],
    "assigned": [], "resolved": [], "reopened": []
  },
  "summary": { "counts": { "new_alerts": 1, "assigned": 0, "resolved": 0, "reopened": 0 } }
}
```

`new_alerts` = `created_at` in window; `assigned` = `assigned_at`; `resolved` = `resolved_at`; `reopened`
= a terminal→non-terminal status transition (from the event log; covers manual `set_status` and engine
`auto_resolved`/reappearance). Each row's `ts_field` names which lifecycle clock placed it in the bucket.
An alert assigned **and** resolved in the same window appears in both buckets (two honest facts). The
default window is the alert-store activity span (`AlertStore.activity_span()`) — deterministic, never
`now`; an empty store yields `window {from:null,to:null}` and empty buckets. Read-only and additive; the
engine scoring path is untouched.

#### `GET /api/attack_paths`

**Crown-Jewel Technique Paths** — for each CRITICAL asset, a plausible kill-chain technique progression
across a *declared zone model* (`ZONE_SPINES`), each zone a **stop** that is **observed** (a real engine
detection fired in that zone) or **hypothetical** (a library technique applicable to that zone, not yet
seen). **Not a network-reachability or exploitability claim** — the topology carries no host adjacency and
every scenario link is same-host. Read-only, deterministic.

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `min_proximity` | `float` | `0.30` | Floor; a detection below it is not counted as an "observed" stop |
| `from` / `to` | `str \| null` | full span | Absolute ISO bounds for the detection window (never `now`) |
| `entry_zone` | `str \| null` | spine entry | Start zone (a `Zone` value); must be earlier on the target's spine |
| `target` | `str \| null` | all CRITICAL | A single target hostname instead of every CRITICAL asset |

**Role required:** `viewer`. **Errors:** `422` on unknown `entry_zone`/`target` or unparseable/inverted bounds.

**Response `200`:**

```json
{
  "paths": [{
    "entry": { "zone": "DMZ" },
    "target": { "hostname": "DC01", "zone": "Active_Directory", "criticality": "CRITICAL" },
    "realized_pct": 0.1538, "mean_observed_proximity": 0.165,
    "observed_stop_count": 1, "total_stop_count": 4, "max_severity": "HIGH",
    "stops": [{ "zone": "DMZ", "scenario_id": "...", "scenario_name": "...", "tactic": "TA0001",
                "severity": "HIGH", "status": "observed", "observed_proximity": 0.66,
                "matched_steps": 2, "total_steps": 3, "host": "WEB01" }],
    "honesty_note": "Plausible technique progression over the scenario library + zone model — not a network-reachability or exploitability claim. …"
  }],
  "honesty_note": "…",
  "from": "<iso>", "to": "<iso>"
}
```

A path is the contiguous slice of a declared `ZONE_SPINES` walk from an entry zone to the target's zone;
each zone is a **stop** covered by the best applicable scenario (observed beats hypothetical). `realized_pct
= round(Σ matched_steps / Σ total_steps, 4)` over the stops — "how much of the whole chain the logs already
show". One path per (entry, CRITICAL target), capped at 50, ordered by `(-realized_pct, -severity,
entry_zone, target_zone, target_hostname)`. The default window derives from the corpus, never `now`.
Read-only and additive; the engine scoring path is untouched.

#### `GET /api/campaign`

The **Purple-Team Detection-Validation Scorecard** — batch the **Purple-Team Drill** over a scenario subset
and aggregate a detected/missed scorecard. For each scenario it injects the attack into the deterministic
simulator on an eligible host and runs the read-only engine, then reports detected vs missed + the proximity
achieved, an aggregate **% detected**, and the gaps. **HONESTY (read this):** a "detected" cell means the
simulator's *injected* attack fired the scenario at/above the threshold — a **regression + cross-technique
coverage + topology-gap check on the library+simulator, NOT a real-world detection-efficacy claim** (a
scenario authored to be detectable detects its own emitter). The caveat is carried in the response
`honesty` field and rendered as a persistent banner in the console.

**Query parameters** (one primary selector; precedence `scenario_ids` > `tactic` > `os_family` > all):

| Parameter | Type | Default | Description |
|---|---|---|---|
| `scenario_ids` | `str \| null` | — | Comma-separated explicit subset (unknown id → 422) |
| `tactic` | `str \| null` | — | All scenarios whose `mitre_mappings[].tactic` includes it |
| `os_family` | `str \| null` | — | All scenarios with that `os_family` (windows/linux/macos) |
| `min_proximity` | `float` | `1.0` | "detected" = proximity ≥ this (default 1.0 = the full chain fired) |

**Role required:** `viewer`. **Errors:** `422` on unknown `scenario_ids` or a resolved scope over the
**50-scenario cap** (never silently truncated — that would make `% detected` lie). LRU-cached on the
canonical definition (deterministic → identical request returns the identical scorecard). Cold full-library
run ≈ 1–2s (~40 sequential drills); instant when cached.

**Response `200`:** `{ definition, rows, aggregate, honesty }`. Each `row` =
`{scenario_id, name, tactic, technique, os_family, host, status: "detected"|"missed"|"no_eligible_host"|"error",
detected, proximity, matched_steps, total_steps, feed_summary, note}` (sorted by scenario_id). `aggregate` =
`{runnable, detected, missed, no_eligible_host, errors, pct_detected = round(detected/runnable,4),
gaps_by_tactic, no_eligible_host_scenarios}`. **`no_eligible_host`** (a scenario with no topology host whose
OS family + zone match) is a topology/coverage gap — **excluded from the `runnable`/`% detected` denominator**,
never counted as a miss. Read-only/additive; batches `run_drill` (engine untouched); deterministic (fixed
drill seed/base-time, no `now`).

#### `GET /api/timeline`

The **Case Timeline** — the deterministic, ordered event narrative of a detection that an IR analyst builds
by hand. Returns the matched scenario steps (from the detection's own `matched_steps`) interleaved with
surrounding context events on the affected host(s), within an absolute band derived from the matched
timestamps. **Read-only, deterministic, engine untouched** (the matched backbone comes from the cached
detection; context events are re-read from the feed via the normalize path — no engine re-run).

> **HONESTY:** the timeline is the literal ordered real events. **"Context" rows are simply all normalized
> events on the affected host(s) within the band — shown for situational awareness, NOT necessarily related
> to the attack. Only the `matched_step` rows are events the engine tied to the scenario.** (Carried in the
> response `honesty_note`.)

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `scenario_id` | `str` | — (required) | The detection's scenario id |
| `host` | `str \| null` | all affected hosts | Restrict to one host (must be in the detection's `affected_hosts`) |
| `from` / `to` | `str \| null` | matched band ±300s | Absolute ISO bounds that override the auto band edge |

**Role required:** `viewer`. **Errors:** `404` unknown `scenario_id` (not in the library) **or** the scenario
produced no detection in the feed (no case to show); `422` unparseable/inverted bounds or `host ∉
affected_hosts`. LRU-cached on `(scenario_id, host, from, to)`.

**Response `200`:** `{scenario_id, name, severity, hosts, band: {from, to, pad_seconds: 300}, rows,
matched_count, context_shown, context_total, context_truncated, honesty_note}`. Each `row` =
`{timestamp, host, kind: "matched_step"|"context", event_kind, label, step_id, step_name, element_id}`,
**totally ordered** by `(timestamp, host, event_kind, label, command_line, element_id)` → byte-identical
recompute. The band is `[first_matched − 300s, last_matched + 300s]` (overridable). Context is **capped at
500** (matched rows are never capped); over the cap → `context_truncated: true` with honest
`context_shown`/`context_total` (never silently dropped). A matched event is not duplicated as a context
row (dedup by `(host, timestamp)`). The frontend reaches this from the Dashboard "View case" deep-link.

#### `POST /api/ioc_match`

The **IOC / Threat-Intel Overlay** — match an external watchlist against the loaded telemetry (the CTI →
SOC enrichment loop). Read-only, deterministic. **Role required:** `viewer` + **CSRF** (it's a POST only
because it carries a list body; it changes no state).

> **HONESTY:** the overlay only evaluates IOC types this telemetry can actually carry. **`hash`, `domain`,
> and `ip` IOCs ARE evaluated**: `hash` against the *synthetic*, deterministically-derived file hashes,
> `domain` (exact host, case-insensitive) against queried domains in the *synthetic* DNS-query telemetry
> (Sysmon EID 22), and `ip` (exact v4 string) against destination IPs in the *synthetic* network-connection
> telemetry, which uses **RFC 5737 documentation ranges** that can never collide with
> real-world addresses — DNS + dest-IP telemetry exists on **Windows, Linux, and macOS** (native on Windows
> Sysmon and the Linux auditd `connect(2)` syscall; an explicit agent/EDR overlay for Linux DNS and macOS
> DNS/connections), and a match validates the hunting pipeline, NOT real-world prevalence. **`ipv6` and CIDR IOCs are hard-rejected
> (`422`)** — the synthetic stream is v4 exact-match only (deferred). `technique` IOCs match the **scenario
> library + detections**, not raw events (a different target). The caveat is carried in
> `summary.honesty_note`.

**Body** (`extra="forbid"`): `{ "iocs": [ {"type": "...", "value": "..."} ] }`. Matchable `type` ∈
`{process_name (exact, case-insensitive), image (substring over image_loaded/process_path), command
(substring over command_line), hash (case-insensitive, any algo, vs NormalizedEvent.hashes), domain (exact,
case-insensitive, vs NormalizedEvent.domain), ip (exact v4 string, vs NormalizedEvent.dest_ip), technique
(exact, vs scenario mitre mappings)}`. **Errors (`422`):** empty `iocs`; `> 256` IOCs; an
`ipv6`/`cidr`/unknown type (with the honest reason); empty value; any extra body field. A `hash` event hit's
`matched_field` is the algorithm name (`sha256`/`md5`); a `domain` hit's `matched_field` is `domain`; an `ip`
event hit's `matched_field` is `dest_ip`.

**Response `200`:** `{ summary: {iocs_total, iocs_matched, hosts_touched, honesty_note}, iocs: [...], hosts:
[...] }`. Each `iocs[]` = `{type, value, target: "event"|"scenario", matched, hit_count, hits, truncated}`
(technique IOCs also carry `covered`/`covered_scenarios`). Event hits = `{host, timestamp, label,
matched_field, snippet}` (sorted `(timestamp, host, matched_field, snippet)`, capped at **200** per IOC with
honest `truncated`/`hit_count`); scenario hits = `{scenario_id, name, proximity, affected_hosts}`. `hosts` =
the topology-enriched rollup of every host touching ≥1 IOC `{hostname, zone, criticality, ioc_count, types}`
(sorted `(-ioc_count, hostname)`). Read-only/additive; one feed pass (reuses read+normalize); engine
untouched; deterministic (no `now`); no persistence.

#### `POST /api/ioc_extract`

**IOC Extraction from Threat Reports** — paste a CTI report / advisory / phishing email and get a
**deterministic, regex-only (no LLM)** extraction of indicators, refanged and split into matchable-here vs
extracted-for-your-other-tools. Read-only, no persistence, no engine. **Role required:** `viewer` + **CSRF**
(POST only because it carries a text body; it changes no state). This is the pre-step *in front of*
`POST /api/ioc_match`; the analyst reviews the matchable set, pushes it into the watchlist, then runs the
unchanged match.

> **HONESTY:** extraction is broad, matching is narrow. Every indicator type is extracted, but each is
> classified `matchable: true/false` against Augur's telemetry. **`technique`, `process_name`, `file_path`
> (→ `image`), `md5`/`sha1`/`sha256` (→ `hash`), `domain` (→ `domain`), and `ip` (IPv4 → `ip`)** are
> matchable — exactly the types `POST /api/ioc_match` accepts (hashes, domains, and dest IPs match the
> synthetic multi-OS (Windows/Linux/macOS) endpoint/DNS/connection telemetry using RFC 5737 documentation
> ranges, not a reputation feed). Private/reserved IPv4 is filtered out (never a CTI IOC). `ipv6` / URL / email / CVE / registry
> indicators are returned in a separate `unmatchable` array, each with the verbatim reason ("IPv6 dest
> addresses are not yet in the corpus (synthetic stream is v4-only)", "…no registry fields", "CVE is context
> only — not an Augur telemetry field"). The split is structural (two arrays), never a silent flag, and the
> non-matchable types are never auto-fed into the matcher. Plain-text paste only.

**Body** (`extra="forbid"`): `{ "text": "<pasted report, plain text>" }`. **Errors (`422`):** empty text;
text `> 200,000` chars; any extra body field.

**Response `200`:** `{ summary, matchable: [...], unmatchable: [...] }`.
`summary = {extracted_total, matchable_count, unmatchable_count, truncated, honesty_note}` (`truncated` true
when the dedup'd total exceeded the **256**-IOC cap). Each indicator = `{type, value (always refanged/live),
category, confidence ("high"|"medium" — a per-type pattern-class label, not a reputation score), matchable}`
with optional `defanged_from` (provenance when refang changed the value) and, on `unmatchable` items, `reason`.
Extracted types: `ipv4` (defanged-aware; private/reserved dropped; maps to matchable `ip`), `ipv6`, `domain` (TLD-allowlist),
`url` (`hxxp`→`http`), `email`, `md5`/`sha1`/`sha256` (FP-drop all-same-char), `cve`, `technique`
(`T####[.###]`/`TA####`), `process_name` (extension-allowlist), `file_path` (anchored Win/Unix top-level dirs;
maps to `image`), `registry_key`. Dedup `(type, value.casefold())`; output sorted `(type, value)`. Pure
regex + refang; deterministic; no `now()`, no randomness, no LLM; engine untouched.

#### `GET /api/pivot_graph`

The **Investigation Pivot Graph** — a bounded k-hop neighborhood of a detection, rendered as a static
node-link graph for SOC investigation pivoting. Seeds from the detection's `matched_steps` (resolving the
synthetic `|EXH|` behavior element_id to its owning process), BFS-expands to `hops` deep, and returns the
full Host/Process/File subgraph enriched with topology criticality. **Read-only, deterministic, engine
untouched** (no engine re-run; consumes the public detection dict + a knowledge graph built once from the
static feed at startup).

**BFS neighbor rule:** Process and File nodes expand in both directions (`edges_from + edges_to`). **Host
nodes are terminal context** — only `edges_from(host)` is followed; `edges_to(host)` (i.e. co-resident
processes via RUNS_ON) is intentionally NOT expanded. This prevents a busy host's full process roster from
consuming the `MAX_NODES` budget before the seed's causal neighbours (spawned children, loaded modules) are
discovered. The seed's host is always included in the result; click a host node to pivot into its full
process roster.

> **HONESTY:** edges are host-local causal relationships — process spawn (`SPAWNED`), module load (`LOADED`),
> exhibited behavior (`EXHIBITED`), and host membership (`RUNS_ON`). They are **NOT network reachability or
> proof of lateral movement**: the topology carries no host adjacency and every relationship shown is
> same-host. Expanded neighbors are drawn from the full knowledge graph for context, not from the matched
> detection alone. (Carried in `summary.honesty_note`.)

**Query parameters:**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `detection` | `str` | — (required) | The `scenario_id` of the detection to seed from (same key as `/api/timeline`) |
| `hops` | `int` | `2` | BFS expansion depth — clamped to `1..3`; values outside this range are clamped, never `422` |

**Role required:** `viewer`. **Errors:** `401`/`403` unauthenticated or insufficient role; `404` unknown
`detection` (not a known `scenario_id` or the scenario produced no detection in the feed); `422`
unresolvable seed (all `matched_steps` element ids resolve to graph nodes that do not exist — this is a
data-integrity edge case, not an invalid parameter). LRU-cached on `(scenario_id, hops)`.

**Response `200`:**

```jsonc
{
  "seed": {
    "scenario_id": "SCEN-WIN-001",
    "name": "Pass-the-Hash",
    "severity": "CRITICAL",
    "seed_node_ids": ["p1"],          // resolved graph node ids (post |EXH| resolution)
    "affected_hosts": ["WS-FIN-07"]
  },
  "nodes": [
    {
      "id": "p1",
      "node_type": "Process",          // "Host" | "Process" | "File"
      "label": "evil.exe",             // hostname | process name | file name
      "host": "WS-FIN-07",
      "criticality": "HIGH",           // topology.enrich value; "UNKNOWN" for off-topology hosts
      "zone": "User_Endpoint",         // topology.enrich value; "Unknown" for off-topology hosts
      "seed": true,                    // was this node a matched-step node?
      "hop": 0,                        // 0 = seed; BFS depth otherwise
      // Process-only fields:
      "name": "evil.exe",
      "command": "evil.exe --inject",
      "integrity_level": "High",
      // File-only fields:
      "path": "C:\\Windows\\x.dll",
      "is_signed": false,
      "is_injected": true,
      "extension": ".dll"
    }
  ],
  "edges": [
    {
      "id": "p1->ws-fin-07:RUNS_ON:2026-...",  // stable unique id: "{src}->{dst}:{edge_type}:{ts}"
      "src": "p1",
      "dst": "ws-fin-07",
      "edge_type": "RUNS_ON",           // "SPAWNED" | "LOADED" | "EXHIBITED" | "RUNS_ON"
      "timestamp": "2026-05-01T10:00:00+00:00",
      "is_injected": true               // LOADED edges only; boolean from edge attrs
    }
  ],
  "summary": {
    "node_count": 5,
    "edge_count": 4,
    "nodes_total": 5,                   // discovered before cap (honest pre-truncation count)
    "edges_total": 4,
    "nodes_truncated": false,           // true when > MAX_NODES (300) were discovered
    "edges_truncated": false,           // true when > MAX_EDGES (600) were discovered
    "hops": 2,
    "honesty_note": "Edges are host-local causal relationships..."
  }
}
```

- **Nodes** sorted `(hop, node_type, id)`; **edges** sorted `(timestamp, edge_type, src, dst)` — byte-identical on re-run (Invariant 1).
- **Caps:** `MAX_NODES = 300`, `MAX_EDGES = 600`; edges are only emitted if both endpoints are in the kept node set. Truncation sets `nodes_truncated`/`edges_truncated` and reports honest `nodes_total`/`edges_total`.
- **`is_injected`** appears only on `LOADED` edges (drawn from edge attrs); absent on all other edge types.
- The frontend reaches this from the Dashboard "Pivot" deep-link (`/pivot?detection=<scenario_id>`).

#### `GET /api/rarity` — Rarity / frequency-stacking (viewer)

Deterministic least-frequency-of-occurrence ("stacking") over the loaded corpus. Pure counting — no
engine, no scoring, no `now()`, no ML. **A rare value is a LEAD for triage, not a detection or
verdict.**

**Query parameters**

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `dimension` | `str` | `process` | `process` (rare binary) · `parent_child` (rare lineage `parent → child`) · `host_binary` (anomalous spread — binary seen on fewest hosts). Unknown value → **422**. |
| `max_count` | `int` | `5` | Only buckets with `occurrences ≤ max_count` are returned. Clamped to `[1, 50]` — never 422. |
| `limit` | `int` | `100` | The N rarest rows after the threshold. Clamped to `[1, 500]` — never 422. |

**Role required:** `viewer` (read-only GET; no CSRF required).

**Counts only — never a synthesised score.** Operates on `process_create` events only. Buckets are
casefolded `process_name` (process), `(parent, child)` pair (parent_child), or binary name keyed by
host spread (host_binary). For `process` / `parent_child` rows are ranked rarest-first (ascending
`occurrences`, then `host_count`, then `value`); for `host_binary` rows are ranked by fewest distinct
hosts first (ascending `host_count`, then `occurrences`, then `value`). Total ordering is
deterministic. `first_seen` / `last_seen` are min/max timestamps **within this corpus only** — first
in this data, not first ever.

**Error responses:**
- `401 Unauthorized` — unauthenticated.
- `422 Unprocessable Entity` — unrecognised `dimension` value (all other param errors are clamped, not rejected).

**Response `200`:**

```jsonc
{
  "dimension": "parent_child",
  "params": { "max_count": 5, "limit": 100 },
  "summary": {
    "total_values": 412,
    "rare_values": 87,
    "returned": 87,
    "truncated": false,
    "honesty_note": "Rarity is a LEAD for triage, not a detection or verdict. Most rare activity is benign …"
  },
  "rows": [
    {
      "value": "winword.exe → rundll32.exe",
      "occurrences": 1,
      "host_count": 1,
      "single_host": true,
      "unique": true,
      "first_seen": "2026-05-01T10:00:00+00:00",
      "last_seen":  "2026-05-01T10:00:00+00:00",
      "hosts": [
        { "hostname": "FIN-CFO-PC", "zone": "Finance", "criticality": "CRITICAL", "count": 1 }
      ],
      "hosts_truncated": false,
      "samples": [
        { "host": "FIN-CFO-PC", "timestamp": "2026-05-01T10:00:00+00:00", "command": "rundll32.exe …" }
      ],
      "samples_truncated": false
    }
  ]
}
```

| Response field | Type | Description |
|---|---|---|
| `dimension` | `str` | Echoed dimension |
| `params` | `object` | Echoed `max_count` + `limit` after clamping |
| `summary.total_values` | `int` | Total distinct buckets seen in the corpus (before threshold filter) |
| `summary.rare_values` | `int` | Buckets with `occurrences ≤ max_count` |
| `summary.returned` | `int` | Rows actually returned (≤ `limit`) |
| `summary.truncated` | `bool` | `true` when `rare_values > returned` — the long tail is longer than `limit` |
| `summary.honesty_note` | `str` | Persistent caveat surfaced in the console's honesty panel |
| `rows[].value` | `str` | Display key: casefolded binary name, or `"parent → child"` string |
| `rows[].occurrences` | `int` | Total event count for this bucket |
| `rows[].host_count` | `int` | Distinct hosts on which the bucket appeared |
| `rows[].single_host` | `bool` | `host_count == 1` |
| `rows[].unique` | `bool` | `occurrences == 1` |
| `rows[].first_seen` | `str` | ISO 8601 timestamp of earliest event in corpus |
| `rows[].last_seen` | `str` | ISO 8601 timestamp of latest event in corpus |
| `rows[].hosts` | `list` | Up to 25 hosts sorted by per-host count desc, then hostname; each `{hostname, zone, criticality, count}` |
| `rows[].hosts_truncated` | `bool` | `true` when more than 25 hosts exist; counts (`host_count`) remain accurate |
| `rows[].samples` | `list` | Up to 5 representative events sorted by `(timestamp, host)`: each `{host, timestamp, command}` |
| `rows[].samples_truncated` | `bool` | `true` when more than 5 samples exist for this bucket |

**Honesty note (carried in `summary.honesty_note` and rendered as a persistent panel in the `/stack`
console page):** Rarity is a LEAD for triage, not a detection or verdict. Most rare activity is
benign — admin tools, one-off installs, a single legitimate script. These rows are starting points for
a hunt, not findings. Counts are over this loaded corpus only: "first seen" means first in this data,
not first ever. A rare value on a CRITICAL host is a stronger lead but still needs human triage. No
scoring, no ML, no probability — just occurrence counts.

The `*_truncated` flags disclose where host or sample lists were capped while keeping the aggregate
counts (`host_count`, `occurrences`) accurate. LRU-cached on `(dimension, max_count, limit)` —
identical parameters return a byte-identical result. Engine untouched; deterministic; no `now()`, no
randomness.

The frontend reaches this from the Investigate navigation section as the `/stack` page (Stacking).

#### `GET /api/detection_health`

Per-scenario liveness over the loaded corpus. Role: `viewer`. Deterministic, read-only, corpus-time only.

For each scenario: `state` (`FIRING` / `PARTIAL` / `SILENT` / `NEVER`), `max_proximity`, `fire_count`
(growing-window snapshots in which it reached any proximity), `last_fired` (corpus timestamp or `null`),
`affected_host_count`, plus `summary.by_state` rollup and `summary.corpus_span`.

**Honesty:** `SILENT`/`NEVER` means the scenario did not fire in THIS corpus — NOT that the detection is
broken in production. `last_fired` is a corpus timestamp, not wall-clock. Fire-count is a liveness signal,
not an alert volume. The verbatim caveat ships in `summary.honesty_note`.

#### `GET /api/scenarios`

Lists all loaded scenarios.

**Role required:** `viewer`

**Response `200`** — array:

| Field | Type | Description |
|---|---|---|
| `scenario_id` | `str` | e.g. `"SCEN-WIN-001"` |
| `name` | `str` | Scenario name |
| `severity` | `str` | Severity value |
| `steps` | `int` | Total step count |
| `os_family` | `str` | Target OS family — `windows` / `linux` / `macos` (from `scenario_metadata.os_family`) |
| `applicable_zones` | `list[str]` | Zones the scenario can fire in (the spatial gate, from `spatial_constraints.applicable_zones`) |
| `mitre` | `list` | Array of `{tactic, technique}` objects |

> `os_family` and `applicable_zones` are **additive** fields (existing keys unchanged). The Purple-Team Drill
> page uses them to filter the host `<select>` to assets whose OS family matches **and** whose `zone` ∈
> `applicable_zones`, so users are only offered hosts that will actually fire.

#### `GET /api/scenarios/{id}`

Returns the full metadata **and step bodies** for a single scenario.  Read-only and deterministic — pure
read of the closure-loaded scenario list; no engine, graph, scoring, persistence, `now()`, or randomness.

**Role required:** `viewer`.

**Path parameter:**

| Param | Type | Description |
|---|---|---|
| `id` | `str` | Scenario ID, e.g. `"SCEN-WIN-001"` |

**Response `200`:**

| Field | Type | Description |
|---|---|---|
| `scenario_id` | `str` | e.g. `"SCEN-WIN-001"` |
| `name` | `str` | Scenario name |
| `severity` | `str` | Severity value (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`) |
| `os_family` | `str` | Target OS family — `windows` / `linux` / `macos` |
| `applicable_zones` | `list[str]` | Zones the scenario can fire in (from `spatial_constraints.applicable_zones`) |
| `mitre` | `list` | Array of `{tactic, technique}` objects (from `scenario_metadata.mitre_mappings`) |
| `step_count` | `int` | Total number of detection steps (integer count) |
| `steps` | `list` | Full step-body array (see shape below) — **distinct from the list endpoint's `steps` int** |

Each `steps` entry:

| Field | Type | Description |
|---|---|---|
| `step_id` | `int` | 1-based step index; contiguous `1..step_count` |
| `name` | `str` | Step name |
| `temporal_link` | `object \| null` | `null` for step 1; `{ previous_step, min_time_delta_seconds, max_time_delta_seconds, link_scope }` for later steps |
| `matching_criteria` | `object` | Raw matching-criteria dict for this step (engine uses these for candidate evaluation) |

**Errors:**

- `401` — unauthenticated.
- `404` — `id` does not match any loaded scenario.

#### `GET /api/scenarios/{id}/sigma`

Deterministically renders the scenario's steps as **vendor-neutral Sigma detection rules** — one rule
**per step**. Read-only, pure transform over the scenario schema (no engine, scoring, persistence, `now()`,
or randomness).

> **Honesty:** a flat Sigma rule is a single-event selection. It **cannot** express Augur's cross-step
> temporal correlation (`link_scope`/time-delta) or spatial zone gating (`applicable_zones`, resolved by Augur
> topology). Each rule therefore matches **one technique step in isolation** — a hunting/alerting building
> block, **not** a 1:1 reproduction of the validated Augur scenario chain. Steps with no Sigma-expressible
> fields emit a non-firing `status: unsupported` rule (sentinel selection that never matches) rather than a
> dangerous always-true rule. The honesty caveat rides in each rule's `description` + a `falsepositives`
> entry, the YAML header comment, and the `honesty_note` response field.

Convert the exported Sigma to a real SIEM dialect with [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli),
e.g. `sigma convert -t splunk` / `-t microsoft_xdr` / `-t elasticsearch`.

**Role required:** `viewer`.

**Path parameter:**

| Param | Type | Description |
|---|---|---|
| `id` | `str` | Scenario ID, e.g. `"SCEN-WIN-001"` |

**Query parameters:**

| Param | Type | Default | Description |
|---|---|---|---|
| `format` | `str` | `json` | `json` → structured body (below); `yaml` → raw `text/yaml` multi-doc body |

**Response `200` (`format=json`):**

| Field | Type | Description |
|---|---|---|
| `scenario_id` | `str` | e.g. `"SCEN-WIN-001"` |
| `rules` | `list` | One Sigma rule dict per step (in step order) |
| `yaml` | `str` | Multi-doc YAML (header comment first) — the download blob |
| `honesty_note` | `str` | The verbatim per-step caveat |

`?format=yaml` returns the same multi-doc YAML as a raw `text/yaml` body (suitable for
`curl … | sigma convert`).

**Errors:** `401` unauthenticated · `404` unknown `id`.

**CLI equivalent:** `python -m augur.sigma --scenario <ID>` (stdout) or `--out <DIR>` (one `.yml` per step).

---

#### `GET /api/sigma_pack`

Exports the **entire scenario library** as one multi-doc Sigma file. Deterministic: scenario load order,
then step order within each scenario. Same honesty caveat as the per-scenario route applies to every rule.

**Role required:** `viewer`.

**Query parameters:**

| Param | Type | Default | Description |
|---|---|---|---|
| `format` | `str` | `yaml` | `yaml` → `text/yaml` attachment (`augur-sigma-pack.yml`); `json` → `{rule_count, scenario_count, yaml, honesty_note}` |

**Response `200` (`format=yaml`):** `text/yaml` attachment (`Content-Disposition: attachment; filename=augur-sigma-pack.yml`) containing all rules as a multi-doc YAML stream.

**Response `200` (`format=json`):**

| Field | Type | Description |
|---|---|---|
| `rule_count` | `int` | Total number of rules (Σ `step_count` across all scenarios) |
| `scenario_count` | `int` | Number of scenarios in the library |
| `yaml` | `str` | The same multi-doc YAML blob |
| `honesty_note` | `str` | The verbatim per-step caveat |

**CLI equivalent:** `python -m augur.sigma` (all scenarios → stdout) or `--out <DIR>` (one `.yml` per rule).

**Errors:** `401` unauthenticated.

---

#### `GET /api/topology`

Returns zone and asset information from the topology layer.

**Role required:** `viewer`

**Response `200`:**

| Field | Type | Description |
|---|---|---|
| `zones` | `list[str]` | All Zone enum values present in the topology |
| `assets` | `list` | Asset objects as serialised from `topology.assets` |

#### `GET /api/coverage_gaps`

Returns a **tactics × OS-family** coverage-gap matrix exposing, per deployed OS family, which of the 14
ATT&CK tactics the scenario library has no coverage for. Read-only and deterministic — it reuses the
loaded scenarios + topology, runs no engine, and persists nothing.

**Role required:** `viewer`

**Parameters:** none (beyond authentication).

**Cloud exclusion:** columns are the OS families present in the topology intersected with
`{windows, linux, macos}`. Cloud/SaaS assets deliberately produce **no Cloud column** — cloud-stub
scenarios carry `os_family` of `windows`/`linux` (they approximate cloud via endpoint telemetry), so a
literal cloud column would always read 14/14 gap and misrepresent the design.

**Response `200`:**

| Field | Type | Description |
|---|---|---|
| `tactics` | `list[{id,name}]` | The 14 ATT&CK tactics in canonical order |
| `os_families` | `list[str]` | Column families present in topology ∩ `{windows,linux,macos}` |
| `cells` | `object` | `{ "TAxxxx": { "<family>": { "covered": bool, "count": int } } }` — `covered` iff ≥1 scenario of that family lists the tactic; `count` is the covering-scenario count |
| `summary` | `object` | `{ os_families, total_cells, covered_cells, gap_cells, coverage_pct }` over the 14×N grid (`coverage_pct = round(covered_cells/total_cells, 4)`) |

#### `GET /api/navigator_layer`

Serialises the current scenario coverage or live detections as a **MITRE ATT&CK Navigator layer**
(schema **v4.5**) — a JSON document the official [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
and compatible tools open directly. Read-only and deterministic — it reuses the loaded scenarios (and, for
`detections`, the exact `/api/detections` source-selection/windowing path), runs no engine of its own, and
persists nothing.

**Role required:** `viewer`

**Parameters:**

| Param | Type | Default | Description |
|---|---|---|---|
| `type` | `str` | `coverage` | `coverage` or `detections`; any other value → `422` |
| `min_proximity` | `float` | `0.30` | (`detections` only) minimum proximity for a detection to contribute |
| `from` | `str` | – | (`detections` only) inclusive ISO lower bound; windows the engine server-side |
| `to` | `str` | – | (`detections` only) inclusive ISO upper bound; unparseable or inverted bounds → `422` |

For `type=detections`, source selection is identical to `/api/detections`: with no `from`/`to` the
precomputed detection set is used; otherwise the `[from, to]` window is re-run and cached, then filtered by
`min_proximity`.

**Layer types & score scales:**

- `coverage` — one technique per `(tactic, technique)` pair that any scenario maps to; **score = 100**
  (binary "covered by the library"). `comment` lists the covering scenario IDs.
- `detections` — only techniques reached by a fired detection; **score = `round(maxProximity × 100)`**
  (0–100), taking the maximum proximity across detections that map to the pair.

Techniques are deduplicated per `(tactic, technique)` pair and sorted by `(tactic, techniqueID)`, so the
output is byte-stable across identical requests. Sub-technique IDs (`Txxxx.xxx`) are emitted as-is. A
detection whose `scenario_id` no longer resolves, or a tactic outside the 14-tactic shortname map, is
skipped defensively.

**Response `200`:** a Navigator v4.5 layer object:

| Field | Type | Description |
|---|---|---|
| `name` | `str` | `Augur — Coverage <date>` / `Augur — Detections <date>` |
| `versions` | `object` | `{ "attack": "15", "navigator": "4.9.0", "layer": "4.5" }` |
| `domain` | `str` | `enterprise-attack` |
| `description` | `str` | Human-readable export note |
| `techniques` | `list[{techniqueID, tactic, score, comment, enabled}]` | One per `(tactic, technique)` pair; `tactic` is the Navigator shortname; `score` per the scale above |
| `gradient` | `object` | `{ colors, minValue: 0, maxValue: 100 }` |
| `legendItems` | `list` | Legend entries (coverage vs. proximity bands) |
| `sorting` | `int` | `0` |
| `hideDisabled` | `bool` | `false` |

#### `GET /api/metrics`

Returns platform evaluation metrics (MITRE coverage, FP rate, per-scenario detectability).

**Role required:** `admin`

**Response `200`:** metrics object (shape depends on `augur.api.metrics_endpoint.platform_metrics`).

#### `POST /api/drill`

**Purple-Team Drill.** Synthesises a benign baseline feed with the chosen attack scenario injected onto the
chosen host, runs the standard **read-only engine** over it, and returns the resulting detection — turning a
"we can detect this" claim into a *provable* detection.

The drill is **deterministic** (fixed `seed=1337` + fixed base-time `2026-01-01T09:00:00Z`, never wall-clock),
synthesises a one-host `MachineProfile` from the topology asset, and **persists nothing** — the live
`/api/detections` precompute is never read or mutated and the scoring path runs unchanged.

**Role required:** `analyst` — **CSRF required** (`X-CSRF-Token`).

**Request body:**

| Field | Type | Description |
|---|---|---|
| `scenario_id` | `str` | Scenario to inject, e.g. `"SCEN-WIN-001"` |
| `host` | `str` | Target host (topology hostname), e.g. `"HR_User_PC"` |

**Response `200`:**

| Field | Type | Description |
|---|---|---|
| `detection` | `object \| null` | Public detection dict (same shape as `/api/detections` rows) for the injected scenario, or `null` if it did not fire |
| `feed_summary` | `object` | `{ total_events, baseline_events, injected_events }` — counts of the synthesised feed |
| `scenario_id` | `str` | Echo of the requested scenario |
| `host` | `str` | Echo of the requested host |

**Errors:**

- `403` — role below `analyst`, or missing/invalid CSRF token.
- `422` — the drill cannot fire and the reason is returned in `detail`:
  - **unknown host** — `host` is not in the topology;
  - **unknown scenario** — `scenario_id` is not loaded;
  - **OS mismatch** — the scenario's `os_family` does not match the host's OS;
  - **wrong zone** — the host's `zone` is not in the scenario's `applicable_zones` (the spatial gate).

  The Drill UI filters the host `<select>` by OS family **and** `applicable_zones` to avoid these, but the
  server-side `422` remains the backstop.

---

### Response Playbooks — `/api/playbook`, `/api/dispatch`

Every detection can be paired with a **contain / eradicate / recover / validate** standard runbook
(`GET /api/playbook`) plus a one-click **Dispatch** (`POST /api/dispatch`) that sends the *real* detection
through the existing connector Sinks. Both are **additive and read-only** against the scoring path —
`/api/detections` is unchanged and the engine is never re-run.

#### `GET /api/playbook`

Returns the standard response playbook derived from a scenario's tactic and severity.

> **Honesty note.** The playbook is a **standard template**, not authored per-scenario incident-response
> content. It is derived from the scenario's **lowest-TA-id** ATT&CK tactic (the deterministic driving
> tactic) and its `severity` — `HIGH`/`CRITICAL` scenarios prepend an escalate line to `contain`. The
> `validate` section is the scenario's own `validation_queries`.

**Role required:** `viewer`.

**Query parameters:**

| Param | Type | Description |
|---|---|---|
| `scenario_id` | `str` | Scenario to derive the playbook for, e.g. `"SCEN-WIN-001"` |

**Response `200`:**

| Field | Type | Description |
|---|---|---|
| `scenario_id` | `str` | Echo of the requested scenario |
| `derived_from` | `object` | `{ tactic, tactic_name, severity }` — the driving tactic (lowest TA-id) and the scenario severity the template was derived from |
| `label` | `str` | `"Standard playbook — <tactic name>"` |
| `sections` | `object` | `{ contain: str[], eradicate: str[], recover: str[], validate: HuntingQuery[] }` — `validate` mirrors the scenario's `validation_queries` (`{ engine, query?, query_path? }`) |

**Errors:**

- `401` — unauthenticated.
- `404` — `scenario_id` is not loaded.

#### `GET /api/incident_response`

Returns the consolidated **standard** response plan for every clustered incident — the merged,
de-duplicated contain / eradicate / recover / validate runbook across each incident's member
scenarios, scoped to the incident's hosts, with per-action provenance (`from_scenarios`) and the
driving tactics. Viewer role. LRU singleton (invalidated on restart). Read-only: a pure fold over
the cached `/api/incidents` output and `response/playbook.py::build_playbook`; no engine run.

**Honesty contract:** the plan is the UNION of STANDARD, tactic-derived template runbooks — exactly
the per-scenario standard playbook merged and de-duplicated. It is NOT a bespoke incident-response
plan, NOT a causal attribution, and NOT a containment guarantee. Hosts/zone/criticality come from
the authoritative topology over this corpus.

Response shape: `{ "responses": [ { "incident_id", "top_severity", "member_count",
"driving_tactics": [{"tactic", "tactic_name"}], "hosts": [{"hostname", "zone", "criticality"}],
"sections": { "contain"|"eradicate"|"recover": [{"action", "from_scenarios"}],
"validate": [{"engine", "query", "query_path", "from_scenarios"}] }, "unresolved_scenarios", "note",
"honesty_note" } ], "honesty_note" }`.

#### `GET /api/incident_report/{incident_id}`

Returns one deterministic **post-incident report** for a clustered incident — a single hand-off
artifact assembling the incident correlation and its consolidated response. Viewer role, read-only.
A pure fold over the SAME cached `/api/incidents` and `/api/incident_response` payloads (it never
re-clusters or re-folds the runbook); LRU is inherited from those two cached singletons. Unknown
`incident_id` → `404`. Registered before the SPA catch-all.

Two representations from one builder:
- **JSON** (default) — `{ "incident_id", "header": { "top_severity", "max_proximity", "score",
  "member_count", "host_count", "technique_count", "first_ts", "last_ts", "relations",
  "members_truncated" }, "affected_assets": [{"hostname","zone","criticality"}], "techniques": [...],
  "detection_summary": [{"scenario_id","name","severity","proximity","affected_hosts","latest_ts"}],
  "response": { …the full /api/incident_response item, embedded verbatim… },
  "source_notes": {"incident","response"}, "honesty_note", "markdown" }`. Every field is SELECTED from
  the two upstream payloads — no recomputation, no `now()`.
- **Markdown** (`?format=markdown`) — `PlainTextResponse` with `Content-Type: text/markdown` and
  `Content-Disposition: attachment; filename=augur-incident-{incident_id}.md`. Byte-identical to the
  JSON body's `markdown` field. Stable section order; honest "(N of M members shown)" line when the
  incident's members were truncated; honesty footer lifts both upstream notes verbatim.

**Honesty contract:** the report is a deterministic ASSEMBLY of an engine correlation and standard
tactic-derived templates over THIS corpus. It is NOT a confirmed adversary campaign, NOT a causal
attribution, NOT a bespoke incident-response plan, and NOT a containment guarantee. Every line is
traceable to a detection, a topology fact, or a standard playbook — no narrative is invented.
Timestamps are corpus-time (echoed); the report carries no generated-at `now()` stamp (determinism
over cosmetics — a fixed report for a fixed corpus).

#### `POST /api/dispatch`

Sends the **real** public detection for a scenario through a connector Sink, closing the loop from hunt to
response.

> **Infra-free by default.** Only `preview` (the default), `stdout`, and `jsonl` are selectable without admin
> configuration and never require network. `preview` performs **no network call** — it returns the stored
> public detection dict verbatim. `stdout`/`jsonl` emit via the connector sinks; the `jsonl` output path is
> **server-chosen** (never read from the request body). Any other sink name (`webhook`, `slack`, `jira`,
> `xsoar`, …) resolves **only** from the persisted admin `AlertConfigStore` config and returns `422` if the
> name is unknown or unconfigured — a live network sink is never driven from request-supplied URLs/kwargs.

**Role required:** `analyst` — **CSRF required** (`X-CSRF-Token`). Body is strict (`extra="forbid"`).

**Request body:**

| Field | Type | Description |
|---|---|---|
| `scenario_id` | `str` | Scenario whose stored detection to dispatch, e.g. `"SCEN-WIN-001"` |
| `sink` | `str` | Sink name; defaults to `"preview"`. `preview`/`stdout`/`jsonl` need no config; other names must be configured in `AlertConfigStore` |

**Response `200`:**

| Field | Type | Description |
|---|---|---|
| `ok` | `bool` | Always `true` on success |
| `sink` | `str` | Echo of the resolved sink |
| `payload` | `object` | The stored public detection dict (same shape as `/api/detections` rows) that was dispatched |

**Errors:**

- `403` — role below `analyst`, or missing/invalid CSRF token.
- `404` — no stored detection exists for `scenario_id`.
- `422` — extra body field, or a sink name that is unknown / not configured in `AlertConfigStore`.

---

### Authentication — `/api/auth`

#### `POST /api/auth/login`

Authenticates a user and creates a session.

**CSRF:** not required (establishes the session that issues the token).

**Request:** `application/x-www-form-urlencoded`

| Field | Description |
|---|---|
| `username` | Account username |
| `password` | Account password |

**Response `200`:**
```json
{ "user": "alice", "role": "analyst", "csrf_token": "<token>" }
```
Sets `fs_session` cookie.

**Error responses:**
- `401 Unauthorized` — invalid credentials
- `429 Too Many Requests` — rate-limit lockout active for this username

#### `POST /api/auth/logout`

Ends the current session and deletes the session cookie.

**CSRF:** required (`X-CSRF-Token` header).
**Role required:** any authenticated user.

**Response `200`:** `{ "ok": true }`

#### `GET /api/auth/me`

Returns the identity of the authenticated user.

**Role required:** any authenticated user.

**Response `200`:**
```json
{ "id": 1, "username": "alice", "role": "analyst" }
```

#### `POST /api/auth/change-password`

Changes the authenticated user's own password. Revokes all other sessions for that user on success.

**CSRF:** required.
**Role required:** any authenticated user.

**Request body (JSON):**

| Field | Type | Description |
|---|---|---|
| `current_password` | `str` | Must match the current password |
| `new_password` | `str` | New password (subject to policy check) |

**Response `200`:** `{ "ok": true }`

**Error responses:**
- `401 Unauthorized` — `current_password` is incorrect

#### `GET /api/auth/sessions`

Lists all active sessions for the authenticated user.

**Role required:** any authenticated user.

**Response `200`** — array:

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Session ID |
| `created_at` | `str` | ISO timestamp |
| `last_seen` | `str` | ISO timestamp |
| `expires_at` | `str` | ISO timestamp |
| `current` | `bool` | Whether this is the caller's own active session |

#### `DELETE /api/auth/sessions/{sid}`

Revokes a specific session belonging to the authenticated user.

**CSRF:** required.
**Role required:** any authenticated user (can only revoke their own sessions).

**Response `200`:** `{ "ok": true }`

**Error responses:**
- `404 Not Found` — session does not exist or belongs to a different user

---

### User Management — `/api/users`

All user management endpoints require `admin` role and CSRF for mutations.

#### `GET /api/users`

Lists all user accounts.

**Role required:** `admin`

**Response `200`** — array of user objects:

| Field | Type | Description |
|---|---|---|
| `id` | `int` | Internal user ID |
| `username` | `str` | Login name |
| `role` | `str` | `"viewer"` / `"analyst"` / `"admin"` |
| `disabled` | `bool` | Whether the account is disabled |
| `created_at` | `str` | ISO timestamp |
| `updated_at` | `str` | ISO timestamp |

#### `POST /api/users`

Creates a new user account.

**CSRF:** required. **Role required:** `admin`.

**Request body (JSON):**

| Field | Type | Description |
|---|---|---|
| `username` | `str` | At least 1 character |
| `password` | `str` | Subject to password policy |
| `role` | `str` | `"viewer"` / `"analyst"` / `"admin"` |

**Response `201`:** the created user object (same shape as list item above).

**Error responses:**
- `409 Conflict` — username already exists
- `422 Unprocessable Entity` — invalid role or password policy violation

#### `PATCH /api/users/{uid}`

Updates a user's role or disabled status.

**CSRF:** required. **Role required:** `admin`.

**Request body (JSON, all fields optional):**

| Field | Type | Description |
|---|---|---|
| `role` | `str \| null` | New role to assign |
| `disabled` | `bool \| null` | `true` to disable (immediately revokes all sessions) |

**Response `200`:** updated user object.

**Error responses:**
- `404 Not Found` — no user with that ID
- `409 Conflict` — operation would remove the last admin

#### `POST /api/users/{uid}/reset-password`

Admin-side password reset for any user. Revokes all sessions for that user on success.

**CSRF:** required. **Role required:** `admin`.

**Request body (JSON):**

| Field | Type | Description |
|---|---|---|
| `password` | `str` | New password (subject to policy check) |

**Response `200`:** `{ "ok": true }`

**Error responses:**
- `404 Not Found` — no user with that ID

#### `DELETE /api/users/{uid}`

Permanently deletes a user account.

**CSRF:** required. **Role required:** `admin`.

**Response `200`:** `{ "ok": true }`

**Error responses:**
- `404 Not Found` — no user with that ID
- `409 Conflict` — cannot delete the last admin

#### `POST /api/users/{uid}/revoke-sessions`

Revokes all sessions for the specified user (e.g. after a suspected compromise).

**CSRF:** required. **Role required:** `admin`.

**Response `200`:** `{ "ok": true }`

---

### Audit Log — `/api/audit`

#### `GET /api/audit`

Returns recent authentication and administrative audit events.

**Role required:** `admin`

**Query parameters:**

| Parameter | Type | Default | Constraints |
|---|---|---|---|
| `limit` | `int` | `100` | 1–1000 |

**Response `200`:** array of audit event records (shape from `AuthState.events.recent()`).

---

### Generative Scenarios — `/api/generate`, `/api/candidates`

The generative module is an opt-in feature (`[ai]` extra; requires `AUGUR_ANTHROPIC_API_KEY`).
The LLM (`claude-opus-4-8`) proposes candidate scenarios; a deterministic guardrail gauntlet
(schema validation → dedup → FP-guard → detectability check) and a mandatory human approval gate
control what enters the library. Nothing is auto-promoted.

#### `POST /api/generate`

Requests the LLM to generate candidate scenarios. Subject to a per-admin rate limit.

**CSRF:** required. **Role required:** `admin`.

**Request body (JSON):**

| Field | Type | Default | Description |
|---|---|---|---|
| `seed` | `str \| null` | `null` | Seed scenario ID to mutate from |
| `category` | `str \| null` | `null` | Tactic folder name (lowercase alphanum + `_`) |
| `technique` | `str \| null` | `null` | MITRE technique string hint |
| `n` | `int` | `5` | Number of candidates requested (capped by `AUGUR_AI_MAX_N`) |
| `axes` | `list[str]` | `[]` | Mutation axes to guide generation |

**Response `200`:**

| Field | Type | Description |
|---|---|---|
| `requested` | `int` | Number of candidates requested |
| `passed` | `int` | Candidates that passed the guardrail gauntlet |
| `candidates` | `list` | Per-candidate result: `scenario_id`, `passed`, `reject_stage`, `reason`, `plausibility`, `notes` |

**Error responses:**
- `429 Too Many Requests` — per-admin generation rate limit reached

#### `GET /api/candidates`

Lists all candidate scenarios.

**Role required:** `analyst`

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `status` | `str \| null` | Filter by status: `pending` / `approved` / `rejected` |

**Response `200`** — array of candidate objects:

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Candidate UUID |
| `scenario_id` | `str` | Proposed scenario ID |
| `category` | `str` | Tactic folder |
| `status` | `str` | `"pending"` / `"approved"` / `"rejected"` |
| `plausibility` | `float \| null` | LLM-assessed plausibility score |
| `seed_id` | `str \| null` | Source scenario ID if mutated |
| `mutation_axes` | `list` | Axes used during generation |
| `created_by` | `str` | Username who triggered generation |
| `created_at` | `str` | ISO timestamp |
| `reviewed_by` | `str \| null` | Username who approved/rejected |
| `reviewed_at` | `str \| null` | ISO timestamp of review |
| `yaml` | `str` | Full scenario YAML text |
| `gauntlet_report` | `dict \| null` | Guardrail evaluation result |

#### `POST /api/candidates/{cid}/approve`

Promotes a `pending` candidate into the live scenario library. The candidate YAML is re-validated
before being written to `scenarios/<category>/<scenario_id>.yaml`. Fails-closed if the file already
exists on disk.

**CSRF:** required. **Role required:** `admin`.

**Response `200`:**
```json
{ "status": "approved", "scenario_id": "SCEN-WIN-042", "path": "scenarios/..." }
```

**Error responses:**
- `404 Not Found` — candidate not found
- `409 Conflict` — candidate is not `pending`, or a file with that ID already exists on disk
- `422 Unprocessable Entity` — YAML no longer passes schema validation

#### `POST /api/candidates/{cid}/reject`

Marks a `pending` candidate as rejected.

**CSRF:** required. **Role required:** `admin`.

**Request body (JSON):**

| Field | Type | Default | Description |
|---|---|---|---|
| `reason` | `str` | `""` | Free-text rejection rationale |

**Response `200`:**
```json
{ "status": "rejected", "scenario_id": "SCEN-WIN-042" }
```

**Error responses:**
- `404 Not Found` — candidate not found

---

### Alerting — `/api/alerts`

Alerts are stateful objects tracking scenario detections across scan cycles. Proximity bands:
`WATCH` (≥ 0.6), `HIGH` (≥ 0.8), `CONFIRMED` (= 1.0). Each band crossing triggers a
notify-once notification via configured sinks. An autonomous background monitor runs scan cycles
automatically when `AUGUR_MONITOR_ENABLED=true`.

#### `GET /api/alerts`

Lists alerts with optional filters.

**Role required:** `analyst`

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `state` | `str \| null` | Filter by state: `open` / `acknowledged` |
| `severity` | `str \| null` | Filter by severity: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `status` | `str \| null` | Filter by workflow status: `open` / `acknowledged` / `in_progress` / `resolved` / `closed` |
| `assignee` | `str \| null` | Filter by assigned username. The literal value `me` resolves to the calling user; the empty string `""` matches unassigned alerts |
| `seen_from` | `str \| null` | Lower bound (ISO 8601) on `last_seen` (inclusive) |
| `seen_to` | `str \| null` | Upper bound (ISO 8601) on `last_seen` (inclusive) |

**Error responses:**
- `422 Unprocessable Entity` — an unparseable `seen_from` / `seen_to` ISO timestamp

**Response `200`** — array of alert objects:

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Alert UUID |
| `scenario_id` | `str` | Matched scenario ID |
| `scenario_name` | `str` | Scenario name |
| `severity` | `str` | Severity of the matched scenario |
| `affected_hosts` | `list[str]` | Hosts in the detection chain |
| `proximity` | `float` | Latest proximity score |
| `band` | `str` | Current proximity band: `WATCH` / `HIGH` / `CONFIRMED` |
| `state` | `str` | `"open"` / `"acknowledged"` |
| `first_seen` | `str` | ISO timestamp of first detection |
| `last_seen` | `str` | ISO timestamp of most recent scan |
| `count` | `int` | Number of scan cycles where this alert fired |
| `notified_band` | `str \| null` | Highest band for which a notification was sent |
| `created_at` | `str` | ISO timestamp |
| `assignee` | `str` | Assigned username, or `""` if unassigned |
| `status` | `str` | Triage workflow status: `open` / `acknowledged` / `in_progress` / `resolved` / `closed` |
| `resolution_note` | `str` | Note recorded on resolve/close, or `""` |
| `assigned_at` | `str` | ISO timestamp of the last assignment, or `""` |
| `resolved_at` | `str` | ISO timestamp of resolve/close, or `""` |
| `detection` | `dict` | The most recent detection snapshot |

#### `GET /api/alerts/summary`

Returns aggregate alert counts by band, state, and triage workflow status.

**Role required:** `analyst`

**Response `200`** — summary object (shape from `AlertStore.summary()`):

| Field | Type | Description |
|---|---|---|
| `open_count` | `int` | Alerts in state `open` |
| `acknowledged_count` | `int` | Alerts in state `acknowledged` |
| `resolved_count` | `int` | Alerts in state `resolved` |
| `in_progress_count` | `int` | Alerts with workflow status `in_progress` |
| `closed_count` | `int` | Alerts with workflow status `closed` |
| `unassigned_count` | `int` | Alerts with an empty `assignee` |
| `by_status` | `dict` | Count per workflow status: `open` / `acknowledged` / `in_progress` / `resolved` / `closed` |
| `max_alert_id` | `int` | Highest alert rowid (cheap change-detection cursor) |
| `latest_created_at` | `str` | ISO timestamp of the most recently created alert, or `""` |

#### `GET /api/alerts/{aid}`

Returns a single alert with its full event history.

**Role required:** `analyst`

**Response `200`:** alert object (same fields as list item) plus:

| Field | Type | Description |
|---|---|---|
| `events` | `list` | Chronological event log: `{ts, actor, event, detail}` |

**Error responses:**
- `404 Not Found` — no alert with that ID

#### `POST /api/alerts/{aid}/ack`

Acknowledges an open alert.

**CSRF:** required. **Role required:** `analyst`.

**Response `200`:**
```json
{ "status": "acknowledged", "id": "<aid>" }
```

**Error responses:**
- `404 Not Found` — no alert with that ID

#### `POST /api/alerts/{aid}/assign`

Assigns the alert to a user, or clears the assignment when `assignee` is empty. On success, a
best-effort notify-on-assign is sent through the configured sinks/rules (a no-op when unconfigured).

**CSRF:** required. **Role required:** `analyst`.

**Request body (JSON):**

| Field | Type | Default | Description |
|---|---|---|---|
| `assignee` | `str` | `""` | Username to assign. The empty string clears the assignment |

**Response `200`:** the updated alert object (same fields as the list item, including `assignee` and `assigned_at`).

**Error responses:**
- `404 Not Found` — no alert with that ID
- `422 Unprocessable Entity` — `assignee` names an unknown or disabled user
- `403 Forbidden` — caller is below `analyst`, or the CSRF header is missing/invalid

#### `POST /api/alerts/{aid}/status`

Sets the triage workflow status of the alert. Valid statuses are `open`, `acknowledged`,
`in_progress`, `resolved`, `closed`. Moving to a terminal status (`resolved` or `closed`) requires a
non-empty `note`, which is stored as `resolution_note`.

**CSRF:** required. **Role required:** `analyst`.

**Request body (JSON):**

| Field | Type | Default | Description |
|---|---|---|---|
| `status` | `str` | — | One of `open` / `acknowledged` / `in_progress` / `resolved` / `closed` |
| `note` | `str` | `""` | Resolution note; **required** (non-empty) when `status` is `resolved` or `closed` |

**Response `200`:** the updated alert object (same fields as the list item, including `status`, `resolution_note`, and `resolved_at`).

**Error responses:**
- `404 Not Found` — no alert with that ID
- `422 Unprocessable Entity` — invalid `status`, or a missing `note` when resolving/closing
- `403 Forbidden` — caller is below `analyst`, or the CSRF header is missing/invalid

#### `POST /api/alerts/{aid}/comment`

Appends a free-text comment to the alert's event history.

**CSRF:** required. **Role required:** `analyst`.

**Request body (JSON):**

| Field | Type | Description |
|---|---|---|
| `text` | `str` | Comment body; must be at least 1 character |

**Response `201`:** `{ "ok": true }`

**Error responses:**
- `404 Not Found` — no alert with that ID
- `422 Unprocessable Entity` — `text` is empty
- `403 Forbidden` — caller is below `analyst`, or the CSRF header is missing/invalid

#### `GET /api/alerts/config`

Returns the current alerting configuration.

**Role required:** `admin`

**Response `200`:** config object matching the `_ConfigBody` schema (see PUT below).

#### `PUT /api/alerts/config`

Replaces the alerting configuration.

**CSRF:** required. **Role required:** `admin`.

**Request body (JSON):**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `min_proximity` | `float` | yes | — | Minimum proximity for an alert to be created (0.0–1.0) |
| `auto_resolve_cycles` | `int` | no | `0` | Scan cycles of absence before auto-close; `0` disables |
| `rules` | `list` | no | `[]` | Filter rules: each `{min_severity?, min_proximity?, sinks?}` |
| `sinks` | `dict` | no | `{}` | Sink configurations (Slack, Webhook, Jira, CortexXsoar) |

Rule validation: each `min_severity` must be one of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` or null;
`min_proximity` must be in `[0.0, 1.0]` or null; `sinks` must be a list.

**Response `200`:** `{ "status": "ok" }`

#### `POST /api/alerts/scan`

Manually triggers one scan cycle against the configured log source. Results are equivalent to what
the autonomous monitor would compute on the next scheduled cycle.

**CSRF:** required. **Role required:** `admin`.

**Response `200`:** scan result counts (shape from `run_scan`): includes `created`, `notified`, and
other cycle statistics.

---

### Hunt Hypothesis Workbench — `/api/hunts`

The blue-team hypothesis-driven hunt loop as a first-class artifact. A hunt persists **only the human's**
hypothesis, scope, status, notes, and verdict — **never an engine result**. Its **evidence is recomputed
live** from the deterministic engine over the hunt's scope on every read, so a saved hunt can never show a
stale proximity as current. The only stored evidence is a labeled "as-of-verdict" snapshot captured when a
terminal verdict is recorded; it is always shown separately and timestamped, never as live. The workbench
**does not auto-conclude** — the analyst owns the verdict.

A **scope** = `{ scenario_ids?: [], tactic?, zone?, host?, from?, to? }`; evidence = the windowed engine
detections within scope, each with proximity, matched/total steps, and the **next step to hunt**
(`missing_steps[0]` + criteria/temporal) and the `stall` near-miss. Statuses:
`open · investigating · confirmed · refuted · abandoned`.

| Method | Path | Role | Notes |
|---|---|---|---|
| `POST` | `/api/hunts` | analyst | CSRF. Body `{hypothesis, scope}`; validates scope (422 on unknown zone/host/scenario or bad bounds); `owner` = caller. |
| `GET` | `/api/hunts` | viewer | Filters `status`, `owner` (`owner=me`). List view (no evidence). |
| `GET` | `/api/hunts/{id}` | viewer | Detail with **live-recomputed** `evidence`, `scope_resolved`, `honesty_note`, the labeled `verdict_evidence` (+ `verdict_evidence_at`), and `events`. |
| `PATCH` | `/api/hunts/{id}` | analyst | CSRF. Optional `status`/`verdict_note`/`notes`/`scope`. Terminal `confirmed`/`refuted` requires a `verdict_note` (422) and captures the as-of snapshot. |
| `POST` | `/api/hunts/{id}/comment` | analyst | CSRF. `{text}`. |
| `DELETE` | `/api/hunts/{id}` | analyst (owner) / admin | CSRF. Owner-or-admin only (403 otherwise); deletes events then the hunt. |
| `GET` | `/api/hunts/{id}/report` | viewer | `?format=md` (default) or `json`: hypothesis, scope, **live evidence**, verdict, notes, honesty note. |

Read-only/additive: evidence is deterministic reuse of `_windowed_cached`; the engine scoring path is
untouched. The store runs on the shared per-thread sqlite connection (concurrency-safe).

### FP Tuning / Allowlist — `/api/tuning`

A deterministic post-engine policy layer for false-positive control (suppress / downgrade known-good
detections). The engine and scoring path are never touched; with no active entries every route below is a
no-op and `GET /api/detections` returns its exact unchanged shape. An allowlist **entry** is an AND of
optional predicates (`scenario_id`, `technique`, `host`, `zone`, `process_regex`, `command_regex`,
`image_regex`, `ts_from`/`ts_to`) plus `action` (`SUPPRESS` | `DOWNGRADE` with `downgrade_to` ∈
`{WATCH,HIGH}`) and a required non-empty `reason`. At least one predicate is required (422 otherwise).

| Method | Route | Role | Notes |
|---|---|---|---|
| `GET` | `/api/tuning` | viewer | List entries (`?enabled=true|false`); each carries a live `hit_count` over the current detection set. |
| `GET` | `/api/tuning/ledger` | viewer | The live "tuned out" ledger: counts + the suppressed/downgraded detections, each attributed to its entry + reason (the always-visible honesty surface). |
| `GET` | `/api/tuning/{id}` | viewer | One entry + its audit `events`. |
| `POST` | `/api/tuning` | analyst | CSRF. Create an entry. Validates ≥1 predicate, non-empty reason, valid regex/zone/technique/scenario, and DOWNGRADE band. |
| `PATCH` | `/api/tuning/{id}` | analyst | CSRF. Edit predicates/action/reason/expiry. |
| `POST` | `/api/tuning/{id}/enable` · `/disable` | analyst | CSRF. Soft toggle (no delete). |
| `DELETE` | `/api/tuning/{id}` | analyst (author) / admin | CSRF. Author-or-admin only (403 otherwise). |
| `POST` | `/api/tuning/propose_from_alert/{alert_id}` | analyst | CSRF. Returns an **unsaved** pre-filled draft (conservative DOWNGRADE→WATCH) + an advisory `baseline_hint` (rarity of the detection's process). Nothing is saved until the analyst POSTs `/api/tuning`. |

**Effect on `GET /api/detections` (array-shape, additive):** when active entries exist, suppressed rows
drop out and downgraded rows gain an additive `band_override` field; the response stays a bare
`Detection[]`. The "tuned out" detail is read separately from `/api/tuning/ledger`. Deterministic: the match
path has no wall-clock (entry expiry is resolved at the store boundary); proximity is never mutated.

---

## Environment Variables

Key environment variables that affect API behaviour:

| Variable | Description |
|---|---|
| `AUGUR_LOGS` | Path to the JSONL log feed loaded at startup (default: `sample_data/corpus/enterprise_day.jsonl`) |
| `AUGUR_SECRET_KEY` | Session signing key; must be set in production (fail-closed if absent) |
| `AUGUR_ADMIN_USER` / `AUGUR_ADMIN_PASSWORD` | Bootstrap the initial admin account |
| `AUGUR_COOKIE_SECURE` | Set to `true` to enable `Secure` flag on the session cookie (production) |
| `AUGUR_BACKEND` | Set to `neo4j` to use the Neo4j graph backend instead of NetworkX |
| `AUGUR_MONITOR_ENABLED` | Set to `true` to enable the autonomous background alerting monitor |
| `AUGUR_SCAN_WINDOW_SECONDS` | Sliding window for alert scan (seconds; `0` or unset = full feed) |
| `AUGUR_ANTHROPIC_API_KEY` | Required for the generative module (`[ai]` extra) |
| `AUGUR_AI_MAX_N` | Maximum candidates per generation request |

---

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) — full system overview including the auth and alerting modules
- [DATA_MODEL.md](DATA_MODEL.md) — detection object fields and graph data model
- [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md) — scenario YAML authoring reference
- [THREAT_MODEL.md](THREAT_MODEL.md) — security properties and trust boundaries
