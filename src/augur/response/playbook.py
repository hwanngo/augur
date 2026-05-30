"""Tactic-derived standard response playbooks (contain / eradicate / recover / validate).

Pure, additive, read-only helper. Each detection's driving tactic (the lowest TA-id among
the scenario's MITRE mappings) selects a *standard template* runbook; HIGH/CRITICAL severity
prepends an escalate line. The playbook is honestly labelled a standard template derived from
the scenario's tactic & severity — never invented per-scenario IR.

NO engine import (guarded by a test) — this is a pure derivation over the Scenario schema.
"""
from __future__ import annotations

from augur.metrics.coverage import TACTIC_NAMES

_ESCALATE = "Escalate: page on-call IR and open a major-incident bridge."

_GENERIC = {
    "contain": ["Isolate affected systems."],
    "eradicate": ["Remove attacker artifacts."],
    "recover": ["Restore from known-good; validate."],
}

# 14-tactic standard runbook table (contain / eradicate / recover), one row per
# metrics.coverage.TACTIC_NAMES key. Verbatim from the locked design spec.
TACTIC_PLAYBOOKS: dict[str, dict[str, list[str]]] = {
    "TA0043": {"contain": ["Rate-limit/block recon sources."],
               "eradicate": ["External — harden the exposed surface."],
               "recover": ["Review external attack surface."]},
    "TA0042": {"contain": ["Block known adversary infrastructure."],
               "eradicate": ["Remove staged tooling/accounts."],
               "recover": ["Tighten provisioning controls."]},
    "TA0001": {"contain": ["Isolate entry host; block source IP/sender."],
               "eradicate": ["Remove dropped payload; close exposed service."],
               "recover": ["Restore host; patch the access vector."]},
    "TA0002": {"contain": ["Kill the offending process tree; isolate host."],
               "eradicate": ["Delete malicious binaries/scripts."],
               "recover": ["Re-image; verify application integrity."]},
    "TA0003": {"contain": ["Disable the affected account/service."],
               "eradicate": ["Remove autoruns/scheduled tasks/services."],
               "recover": ["Rebuild from known-good; rotate credentials."]},
    "TA0004": {"contain": ["Freeze the elevated account; isolate host."],
               "eradicate": ["Remove SUID/exploit artifacts; revoke tokens."],
               "recover": ["Reset privileges; patch the escalation path."]},
    "TA0005": {"contain": ["Snapshot the host before evidence loss."],
               "eradicate": ["Restore disabled logging/AV; remove evasion tooling."],
               "recover": ["Re-enable controls; validate telemetry."]},
    "TA0006": {"contain": ["Lock exposed accounts; revoke sessions."],
               "eradicate": ["Remove cred-dumping tools; clear cached secrets."],
               "recover": ["Force org-wide password/key rotation."]},
    "TA0007": {"contain": ["Monitor/contain the scanning host."],
               "eradicate": ["Remove recon tooling."],
               "recover": ["Review exposed-asset hardening."]},
    "TA0008": {"contain": ["Segment the network; disable affected accounts."],
               "eradicate": ["Remove remote-exec artifacts; close SMB/RDP paths."],
               "recover": ["Rotate credentials on all touched hosts."]},
    "TA0009": {"contain": ["Isolate the staging host."],
               "eradicate": ["Delete staged archives; revoke access."],
               "recover": ["Audit data-access controls."]},
    "TA0011": {"contain": ["Blackhole C2 domains/IPs; isolate host."],
               "eradicate": ["Remove the implant/beacon; close the channel."],
               "recover": ["Re-image; restore clean connectivity."]},
    "TA0010": {"contain": ["Block egress to the destination; isolate host."],
               "eradicate": ["Remove exfil tooling/channels."],
               "recover": ["DLP review; assess data-loss scope."]},
    "TA0040": {"contain": ["Isolate affected systems immediately."],
               "eradicate": ["Stop the ransomware/wiper; remove payload."],
               "recover": ["Restore from backups; verify integrity."]},
}


def build_playbook(scenario) -> dict:
    """Derive a standard playbook for a Scenario.

    Driving tactic = the lowest TA-id among the scenario's mitre_mappings (deterministic).
    HIGH/CRITICAL severity prepends one escalate contain line. The validate section is the
    scenario's actionable_hunting_outputs.validation_queries.
    """
    tactics = sorted(m.tactic for m in scenario.scenario_metadata.mitre_mappings)
    tactic = tactics[0]                                  # lowest TA-id = deterministic driving tactic
    tactic_name = TACTIC_NAMES.get(tactic, "Unknown")
    base = TACTIC_PLAYBOOKS.get(tactic, _GENERIC)
    contain = list(base["contain"])
    if scenario.severity.value in ("HIGH", "CRITICAL"):
        contain = [_ESCALATE, *contain]
    validate = [{"engine": q.engine, "query": q.query, "query_path": q.query_path}
                for q in scenario.actionable_hunting_outputs.validation_queries]
    return {
        "scenario_id": scenario.scenario_id,
        "derived_from": {"tactic": tactic, "tactic_name": tactic_name,
                         "severity": scenario.severity.value},
        "label": f"Standard playbook — {tactic_name}",
        "sections": {"contain": contain, "eradicate": list(base["eradicate"]),
                     "recover": list(base["recover"]), "validate": validate},
    }
