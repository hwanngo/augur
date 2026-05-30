# Acceptance fixtures

Small, hand-verifiable feeds that pin the **engine's ground-truth behavior** (asserted by
`tests/test_acceptance.py`). All are **regenerated deterministically** by
`python -m scripts.regen_sample_data` from the live scenario library — do not hand-edit.

The events are in each host's **native OS format** (`windows_sysmon` / `linux_auditd` / `macos_esf`) and
carry **realistic** process paths and command lines (e.g. a real `comsvcs.dll MiniDump` invocation), not
synthetic tokens.

| File | What it demonstrates |
|------|----------------------|
| `full_detection.jsonl` | The full **SCEN-WIN-001** LSASS-dump chain on `HR_User_PC` → detection at **proximity 1.0**. |
| `partial_detection.jsonl` | Only the first part of that chain present → a **partial** prefix score (< 1.0): the engine reports how far the attack got. |
| `no_detection_temporal_gap.jsonl` | The same chain, but one step happens far outside its allowed time window → that step is **suppressed**, so the chain doesn't complete. |
| `no_detection_wrong_zone.jsonl` | The same chain on a host in a **zone the scenario doesn't apply to** → the spatial gate rejects it → **no detection**. |
| `no_detection_benign.jsonl` | A multi-OS slice of ordinary benign activity → fires **nothing** at or above the 0.30 reporting threshold. |
| `demo_multi_os.jsonl` | Two attacks (`SCEN-WIN-001` Windows + `SCEN-LNX-001` Linux) firing at 1.0 — the populated demo feed. |

See `../corpus/` for the larger seeded "enterprise day" (≈9.6k events, 6 hosts, 5 planted attacks listed
in `manifest.json`).
