**English** | [Tiếng Việt](../vi/EXPLAINER.md)

# Augur — Explained Simply

A plain-language tour of what Augur does, why it works the way it does, and how to read its output. For the technical deep-dives see [ARCHITECTURE.md](ARCHITECTURE.md), [ENGINE.md](ENGINE.md), [DATA_MODEL.md](DATA_MODEL.md), [API.md](API.md), and [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md).

---

## The one-sentence idea

Augur is a **smoke detector for cyber attacks** — except instead of just beeping when smoke appears, it tells you *which fire*, *which room*, and *how far along it has spread*.

---

## Why not just use an alert system?

Think of a burglar who knows where the motion sensors are. They move slowly, wait between steps, and make sure each individual action looks innocent. One person carries a box — that's normal. That same person first jiggled the back door, then checked the alarm panel, then pulled on latex gloves — suddenly the pattern tells a story the individual events never could.

Conventional security tools are event-by-event scorers. They see "PowerShell launched" and decide: suspicious or not? They generate thousands of these individual verdicts, and analysts drown trying to triage them.

Augur works differently. It says: *"I know what certain attacks look like as an ordered sequence of steps. Let me check whether that sequence is currently playing out on your machines."*

---

## The playbook idea

Augur comes with a library of **40 attack scenarios** — playbooks written by humans who studied real attack techniques documented in MITRE ATT&CK. Each playbook describes one specific attack pattern as an ordered list of steps:

> **Step 1:** A process runs from the user's Temp folder (suspicious dropper)
> **Step 2:** Within 5 minutes on the same machine, an unsigned DLL gets loaded into that process
> **Step 3:** Within 2 minutes, the process accesses LSASS memory (password theft attempt)
> **Step 4:** Within 10 minutes, a credential-staging file appears in a temp directory
> **Step 5:** Within 30 minutes, data is sent to an external IP

Each step has three kinds of constraints:
- **What** — what kind of activity are we looking for? (a process, a file load, a behavior tag from your EDR)
- **Where** — which network zone must the machine be in? (e.g. `User_Endpoint`, `Active_Directory`)
- **When** — how quickly after the previous step must this one occur?

The library spans **14 ATT&CK tactics** and covers Windows (`SCEN-WIN-*`), Linux (`SCEN-LNX-*`), and macOS (`SCEN-MAC-*`) environments, plus cloud-stub scenarios (`SCEN-CLD-*`) that approximate cloud-targeting activity via endpoint telemetry.

---

## The proximity idea: "how far along is the attacker?"

Here is where Augur does something different from a yes/no detector.

Instead of answering "is this attack happening?", it answers: **"how much of this attack pattern have we already seen?"**

```
proximity = steps matched ÷ total steps
```

A scenario with 5 steps where 3 steps have already been observed on the same machine within the time windows gives:

```
proximity = 3 / 5 = 0.60  →  60%
```

That 60% is an early warning. The attacker has started. They have not finished. You still have time to respond.

A scenario at 100% means all steps matched — the full kill-chain has executed. Still useful (you want to know it happened), but earlier is better.

A scenario at 0% (or below the 30% reporting threshold) is simply not reported. No alert, no noise — the pattern isn't there.

This is why proximity is more useful than a binary yes/no: **40% proximity on a critical scenario is a hunting priority before any alert has fired.**

---

## A concrete walkthrough

Let's say Augur is watching a machine called `HR_User_PC` on your corporate network (zone: `User_Endpoint`).

Your logs for the past hour contain:

```
10:00  dropper.exe  ran from  C:\Users\alice\AppData\Local\Temp\dropper.exe
10:02  unsigned DLL  bad.dll  was loaded by  dropper.exe
10:03  dropper.exe  accessed  LSASS memory  (behavior: lsass_access)
10:07  credential-dump file  creds.dmp  created in Temp folder
10:31  powershell.exe  connected to  185.220.x.x  (external IP)
```

Augur has a scenario `SCEN-WIN-001` (Credential Theft via LSASS comsvcs MiniDump) with exactly 5 steps matching this pattern, with these time windows:

| Step | Constraint | This log | Pass? |
|------|-----------|----------|-------|
| 1 | Process from Temp | dropper.exe at 10:00 | ✓ |
| 2 | Unsigned DLL loaded, same host, within 10 min | bad.dll at 10:02 (2 min) | ✓ |
| 3 | LSASS access, same host, within 5 min | 10:03 (1 min) | ✓ |
| 4 | Staging file, same host, within 15 min | 10:07 (4 min) | ✓ |
| 5 | External connection, same host, within 60 min | 10:31 (28 min) | ✓ |

Result: `5/5 steps matched → proximity = 1.0 → CRITICAL`.

Now suppose the 10:31 connection never happened (maybe the attacker got interrupted). Then:

```
4/5 steps matched → proximity = 0.8 → still CRITICAL
Missing: Exfiltration_Connection
```

That missing step is not a failure — it is your hunting lead. The attacker is at step 4. Go look for step 5 before it happens.

---

## Why the engine is deterministic (no AI guessing)

The phrase "AI-free scoring path" might sound like a limitation. It is a deliberate design choice.

When an LLM scores events, it can give different answers to the same question on different runs. It can hallucinate patterns. It cannot fully explain why it fired. In a SOC setting, that unpredictability is a serious problem: you need to be able to audit why an alert fired, reproduce it in a test environment, and trust that the same logs will give the same answer tomorrow.

Augur's engine uses no LLM and no randomness in its scoring. The matching algorithm is a deterministic depth-first search over the knowledge graph. Candidates at each step are sorted by `(timestamp, element_id)` before the search begins. There are no wall-clock reads, no random seeds. Given the same log file and the same scenario library, Augur always produces the same ranked list of detections.

This makes Augur:
- **Auditable** — you can trace exactly which graph nodes matched which step criteria
- **Testable** — the test suite has 1164 assertions that run the full engine with fixed inputs and assert exact outputs
- **Trustworthy** — an analyst can explain every detection to a manager without "the model thought so"

The AI layer (opt-in, separate from scoring) is only for *inventing new scenarios* offline — it does not touch the scoring path.

---

## Proving the engine knows when *not* to fire

It is easy to show a detector lights up when an attack is present. The harder — and more honest — question is whether it stays *silent* when it should: does it actually reject a sequence that almost-but-not-quite matches?

Augur validates this boundary directly. A robustness harness takes a scenario's perfect synthetic trace and *mutates* it along each gate the engine enforces:

- **Drop a step** — remove one step's events; the engine should degrade to the exact proximity the remaining prefix mandates.
- **Push past the temporal gate** — shift a step one second beyond its time window; the matched prefix should truncate right there.
- **Relocate off-zone** — move the anchor into the wrong network zone; the spatial gate should reject the whole match.
- **Break the same-host link** — split a `same_host` step onto a different machine; the chain should stop at the break.

For each mutation the harness asserts the engine produces the *mathematically required* proximity — not "lower", but the exact value the spec dictates (e.g. dropping step k of n must yield `(k-1)/n`). If any gate fails to reject as required, the run fails:

```bash
uv run python -m augur.metrics --fail-on-robustness
```

This turns "the engine doesn't false-fire" from a hope into a checked, deterministic regression gate. It is a construction-integrity proof on the scenario library — not a claim about a live adversary — but it proves the temporal, spatial, and link gates genuinely *reject*, not merely that the happy path fires.

---

## Multi-OS support

Augur normalizes logs from three OS families through separate normalizers:

- **Windows** — Sysmon events (event IDs 1, 7, and EDR behavior tags)
- **Linux** — auditd (EXECVE, SYSCALL, and EDR behavior tags)
- **macOS** — Endpoint Security Framework (ES_EVENT_NOTIFY_EXEC, MMAP, and EDR behavior tags)

All three paths produce the same `NormalizedEvent` structure, so the engine and all 40 scenarios work identically regardless of the source OS. A single log feed can contain events from all three OS families simultaneously — the normalizer registry dispatches on the `source_type` field in each event.

Cloud-stub scenarios (`SCEN-CLD-*`) work via endpoint telemetry: they detect behaviors on machines that correlate with cloud-targeting activity (credential theft followed by cloud API tool usage, for example). Full CloudTrail or M365 normalizers are a future project.

---

## What the output looks like

Running `make engine` against the multi-OS demo log prints:

```
========================================================================
Augur — 2 scenario(s) matched (min_proximity=0.3)
========================================================================
[CRITICAL ] Credential Theft via LSASS comsvcs MiniDump
           SCEN-WIN-001 — 5/5 steps — 100% — hosts: HR_User_PC
[CRITICAL ] Ransomware Staging via Shadow Copy Deletion
           SCEN-WIN-009 — 3/4 steps — 75% — hosts: File_Server_01
           missing: Ransom_Note_Drop
========================================================================
```

The dashboard at `http://127.0.0.1:8000` turns each detection into a card with:

- A **proximity bar** (e.g. 75%) showing kill-chain progression at a glance
- A **per-step breakdown** — green for matched steps, grey for missing steps, each showing host, timestamp, and evidence
- **KQL and Sigma queries** you can paste directly into your SIEM to hunt for the missing step or confirm the match
- A **min-proximity slider** to lower the threshold and surface earlier-stage signals

`Finance_User_PC` was also in the logs — it ran Chrome and Notepad, loaded signed DLLs. Zero detections for that host. The engine does not fire on noise.

---

## From detection to closed incident — the analyst loop

A ranked list of detections is the *start* of an analyst's day, not the end. A real attack rarely shows up as one tidy detection — it scatters across several scenarios, hosts, and techniques. So the platform closes the loop *around* the engine, each step additive and read-only:

1. **Cluster.** Related detections are correlated into a single **incident** — grouped because they share a host or share a MITRE technique. One campaign, one work item, instead of five disconnected cards. (Honestly: this is a correlation over *this* corpus, not a confirmed adversary campaign or a lateral-movement claim — singletons stay as one-member incidents, not discarded.)
2. **Respond.** Each incident folds into a single **consolidated response runbook** — the union of the standard, tactic-derived playbooks (contain / eradicate / recover / validate) for its scenarios, merged and de-duplicated.
3. **Report.** The incident plus its response assemble into a deterministic **post-incident report** (JSON and Markdown) you can hand off — an honest assembly of an engine correlation and a standard template, never a bespoke causal narrative.

None of this re-runs or re-weights the engine. The detections are computed once; everything downstream is a pure fold over them.

### Threat-intel overlay

An analyst can paste a real CTI watchlist — file hashes, domains, IPv4 and IPv6 addresses, CIDR blocks, ATT&CK techniques — and Augur shows what lights up across the Windows, Linux, and macOS telemetry in a single read pass, rolled up by host and criticality.

The honesty here is structural, not a disclaimer bolted on afterward. The synthetic telemetry uses **IANA documentation ranges** — RFC 5737 for IPv4, RFC 3849's `2001:db8::/32` for IPv6 — that are reserved and can *never* collide with a real-world address. So a match validates that the hunting pipeline works end-to-end; it never claims real-world prevalence. And where a real OS source genuinely can't carry a signal — auditd doesn't resolve DNS, and stable macOS ESF emits no DNS or socket events — that telemetry is modeled as an explicit agent/EDR overlay and *labeled as such*, never faked as native. Indicator types the corpus genuinely can't back are honestly rejected rather than silently matched against nothing.

---

## Scenarios vs. sample data — the two ingredients

People mix these up. They are different things:

| | Scenario | Sample data |
|---|----------|-------------|
| What it is | A rule — "wanted poster" for an attack | A recording — "security camera footage" of what happened |
| Format | YAML file in `scenarios/<tactic>/` | JSON Lines file in `sample_data/` |
| Contains | Steps, time windows, zone constraints, matching criteria | Raw log events: process ran, file loaded, connection made |
| In production | You keep and extend the library | You replace with your real SIEM/EDR logs |
| The engine | Matches *for* these | Searches *through* this |

The sample data that ships with Augur is a PoC stand-in for real logs, not a substitute for connecting Augur to your actual EDR or SIEM output.

---

## Adding a scenario

A scenario is one YAML file. The loader picks up every `*.yaml` under `scenarios/` recursively — no code changes needed.

```bash
cp scenarios/credential_access/win_lsass_comsvcs.yaml scenarios/credential_access/my_new_attack.yaml
```

Edit four sections:

1. **Metadata** — unique `scenario_id` (OS-prefixed: `SCEN-WIN-NNN`, `SCEN-LNX-NNN`, `SCEN-MAC-NNN`), name, severity, MITRE mappings, optional `os_family`.
2. **Spatial constraints** — which zones apply, whether critical assets only.
3. **Steps** — ordered, each with `matching_criteria` (must include `Node_Type`). Step 1 has no `temporal_link`. Each subsequent step has a `temporal_link` pointing at `previous_step: <id - 1>` with a `link_scope` (`same_host`, `cross_host`, or `any`) and a time window.
4. **Hunting outputs** — at least one KQL or Sigma query.

Validate with:

```bash
uv run pytest tests/test_scenario_library.py
```

The full reference for every matching operator (`regex`, `in`, `equals`, `exists`), every criterion key, and the `temporal_link` semantics is in [SCENARIO_FORMAT.md](SCENARIO_FORMAT.md).

---

## Honest limits

Augur is a PoC platform with real detection logic, not a production-ready commercial product. A few things to keep in mind:

- **Detectability = 100% is partly by construction.** Scenarios are authored to be synth-friendly. The PoC simulator generates logs that exercise them perfectly. Real adversary logs are messier.
- **FP rate = 0.0 is measured on a synthetic benign corpus.** That corpus is clean by construction. Real production telemetry will have more variety; validation on actual EDR data has not been performed.
- **Cloud-stub scenarios** approximate cloud activity via endpoint-level events. They are not full cloud-native detections.
- **The simulator is a PoC stand-in** for real machine logs, useful for testing and demonstration.

These caveats are not bugs — they are the honest scope of a Phase 1 deterministic engine. The platform is designed to be extended: real normalizers for additional log sources, real telemetry integration, and the opt-in generative layer for expanding the scenario library.

The through-line behind every feature in this document is one rule: **the platform grows *around* a deterministic engine that is never changed.** Incident clustering, the consolidated runbook, the post-incident report, the threat-intel overlay, the robustness harness — each is additive, read-only, and structurally blind to the engine's scoring path. The engine that fires today fires byte-for-byte identically tomorrow, no matter how much platform accretes around it.

---

## Quick reference

```bash
make install    # uv sync (one-time setup)
make test       # 1164 tests
make engine     # print detections, exit
make demo       # print detections + open dashboard at http://127.0.0.1:8000
make up         # full Docker stack (app + Neo4j)
make down       # stop Docker stack
```

Direct commands:

```bash
uv run python -m augur.demo --no-serve
uv run python -m augur.demo --logs sample_data/acceptance/demo_multi_os.jsonl --min-proximity 0.20
uv run python -m augur.demo --logs sample_data/corpus/enterprise_day.jsonl
```

Back to the [project README](README.md).
