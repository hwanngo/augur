# Security Policy

Augur is a self-hosted security product; we take vulnerabilities in the platform itself seriously.
The platform threat model — assets, trust boundaries, known residual risks, and recommendations —
is documented in [docs/en/THREAT_MODEL.md](docs/en/THREAT_MODEL.md). Please read it before reporting,
as some items (e.g. alert-sink SSRF, secrets-at-rest, ingest DoS budgets) are already known and tracked.

## Supported versions

Security fixes are provided for the latest `0.1.x` release line only. Augur is pre-1.0; the API and
configuration surface may change between minor versions.

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately to **security@\<your-domain\>**.
<!-- TODO: replace security@<your-domain> with the project's real security contact (or enable GitHub
private vulnerability reporting and point here). -->

Please include:

- A description of the vulnerability and its impact.
- Affected version / commit.
- Steps to reproduce or a proof-of-concept.
- Any relevant configuration (e.g. backend, AI extra enabled, deployment posture).

If you can, encrypt sensitive details or share them via a secure channel arranged in the first reply.

## Response-time SLA

| Stage | Target |
|-------|--------|
| Acknowledge receipt | within 3 business days |
| Initial assessment / severity triage | within 7 business days |
| Status updates | at least every 14 days until resolution |
| Fix or mitigation for confirmed High/Critical issues | within 90 days of confirmation |

## Coordinated disclosure

We follow coordinated (responsible) disclosure:

- Please give us a reasonable window (target: 90 days) to ship a fix before any public disclosure.
- We will keep you informed of progress and coordinate a disclosure date with you.
- We are happy to credit reporters in the release notes / changelog unless you prefer to remain anonymous.
- We do not currently operate a paid bug-bounty program.

## Scope

In scope: the Augur platform code in this repository — the engine, ingestion, web API/UI, auth, the
opt-in generative layer, the alerting subsystem, and the simulator. Out of scope (per the threat model):
multi-tenant isolation, host/OS hardening, the reverse proxy / TLS configuration, dependency supply chain,
physical access, a malicious `admin` (admins are trusted by assumption), and network-layer DoS.
