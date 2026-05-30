# Post-Incident Report — INC-0001

## Header

| Field | Value |
| --- | --- |
| Top severity | CRITICAL |
| Max proximity | 1.0 |
| Score | 5.0 |
| Members | 2 |
| Hosts | 2 |
| Techniques | 2 |
| First seen (corpus) | 2026-01-01T01:00:00+00:00 |
| Last seen (corpus) | 2026-01-01T02:00:00+00:00 |
| Correlation relations | shared_host, shared_technique |

## Affected Assets

| Host | Zone | Criticality |
| --- | --- | --- |
| HOST-A | User_Endpoint | CRITICAL |
| HOST-B | Server | HIGH |

## MITRE Technique Coverage

T1059, T1078

## Detection Summary

| Scenario | Name | Severity | Proximity | Latest (corpus) |
| --- | --- | --- | --- | --- |
| SCEN-LNX-001 | Linux thing | HIGH | 1.0 | 2026-01-01T01:00:00+00:00 |
| SCEN-WIN-001 | Win thing | CRITICAL | 0.75 | 2026-01-01T02:00:00+00:00 |

## Consolidated Response

**Driving tactics:** TA0002 (Execution)

### Contain

| Action | From scenarios |
| --- | --- |
| Escalate: page on-call IR | SCEN-LNX-001, SCEN-WIN-001 |

### Eradicate

| Action | From scenarios |
| --- | --- |
| Remove persistence | SCEN-WIN-001 |

### Recover

| Action | From scenarios |
| --- | --- |
| Restore from backup | SCEN-LNX-001 |

### Validate

| Engine | Query | Query path | From scenarios |
| --- | --- | --- | --- |
| augur | rerun scenario | scenarios/x.yaml | SCEN-WIN-001 |

## Honesty

This report is a deterministic ASSEMBLY of an engine correlation and standard tactic-derived templates over THIS corpus. It is NOT a confirmed adversary campaign, NOT a causal attribution, NOT a bespoke incident-response plan, and NOT a containment guarantee. Every line is traceable to a detection, a topology fact, or a standard playbook — no narrative is invented.

- _Correlation (incident) note:_ INCIDENT NOTE about correlation not campaign.
- _Standard-template (response) note:_ RESPONSE NOTE about standard template not bespoke.
