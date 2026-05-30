import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from augur.engine.runner import run_engine
from augur.generative.synth import synthesize_trace
from augur.graph.builder import build_graph
from augur.graph.networkx_backend import NetworkXBackend
from augur.normalize.ecs import normalize_events
from augur.pipeline import default_topology
from augur.ingest.jsonl import read_jsonl
from augur.scenarios.schema import Scenario

# Resolve benign data relative to the repo root (src/augur/generative/gauntlet.py
# -> repo root is parents[3]) so the gauntlet works as library code, not just under a
# repo-root cwd. The benign corpus must contain NO attack chains (it is the FP oracle).
_ROOT = Path(__file__).resolve().parents[3]
_FP_THRESHOLD = 0.30

# I2 — why only no_detection_benign.jsonl?
#
# We deliberately keep _BENIGN_PATHS to just acceptance/no_detection_benign.jsonl.
# The obvious candidate for a broader oracle — sample_data/corpus/enterprise_day.jsonl —
# contains 11 planted attack chains that are expected to fire at >= 0.30. Including that
# file would cause the FP guard to reject *legitimate* library scenario candidates (a
# candidate is FP-rejected whenever it fires on the "benign" oracle at >= _FP_THRESHOLD).
# The _partial_detection.jsonl and _tp.jsonl fixtures in sample_data/<category>/ are attack chains
# too, so they cannot be used either.
#
# Result: the only safe, attack-free data available in the repo is the 3-event
# acceptance/no_detection_benign.jsonl, which is specifically crafted to contain no attack chains.
# The existing fp_on_benign_rate == 0.0 eval test (test_generative_eval.py) confirms
# that no legitimate generated candidate is incorrectly FP-rejected.
#
# If a broader benign corpus becomes available (e.g., a dedicated benign_corpus.jsonl
# without planted attacks), add it here — but only after verifying it fires on 0 library
# scenarios at the _FP_THRESHOLD.
_BENIGN_PATHS = [_ROOT / "sample_data" / "acceptance" / "no_detection_benign.jsonl"]


@dataclass
class GauntletResult:
    passed: bool
    scenario_id: str = ""
    reject_stage: str = ""          # "" | schema | dedup | fp_guard | detectability
    reason: str = ""
    plausibility: float = 0.0
    yaml: str = ""
    notes: list[str] = field(default_factory=list)


def _criteria_values(criteria: dict) -> tuple:
    """Return a canonical tuple of (key, value) pairs for fingerprinting.

    Captures the literal/in/equals VALUES of each criterion (not just keys),
    so that LOLBin/tool-swap mutations (e.g. powershell.exe → evil.exe) produce
    distinct fingerprints rather than being falsely flagged as duplicates.
    """
    items = []
    for k in sorted(criteria):
        v = criteria[k]
        if isinstance(v, dict):
            # Canonicalize operator dicts: (key, op, value)
            if "in" in v:
                items.append((k, "in", tuple(sorted(v["in"]))))
            elif "equals" in v:
                items.append((k, "equals", v["equals"]))
            elif "regex" in v:
                items.append((k, "regex", v["regex"]))
            elif "exists" in v:
                items.append((k, "exists", bool(v["exists"])))
            else:
                items.append((k, repr(v)))
        elif isinstance(v, list):
            items.append((k, "list", tuple(sorted(v))))
        else:
            items.append((k, v))
    return tuple(items)


def _fingerprint(s: Scenario) -> tuple:
    """Structural + value fingerprint for scenario deduplication.

    Incorporates Node_Type, criterion KEYS, criterion VALUES (literal/in/equals),
    link_scope, and MITRE techniques — so tool-swap mutations are treated as novel
    while exact duplicates are still caught.
    """
    steps = tuple(
        (st.matching_criteria.get("Node_Type"),
         _criteria_values(st.matching_criteria),
         (st.temporal_link.link_scope.value if st.temporal_link else None))
        for st in s.attack_sequence_flow.steps)
    mitre = tuple(sorted(m.technique for m in s.scenario_metadata.mitre_mappings))
    return (steps, mitre)


def _next_gen_id(existing, extra_used: set[str] | None = None) -> str:
    """Return the next available SCEN-GEN-NNNN id.

    :param existing: list of Scenario objects already in the library.
    :param extra_used: ids already assigned in the current batch (prevents
                       inter-candidate collisions when generating N > 1).
    """
    used = {s.scenario_id for s in existing}
    if extra_used:
        used |= extra_used
    i = 1
    while f"SCEN-GEN-{i:04d}" in used:
        i += 1
    return f"SCEN-GEN-{i:04d}"


def _plausibility(s: Scenario) -> tuple[float, list[str]]:
    notes, score = [], 1.0
    n = s.step_count
    if not (2 <= n <= 8):
        score -= 0.3; notes.append(f"unusual step count {n}")
    for st in s.attack_sequence_flow.steps:
        for k, v in st.matching_criteria.items():
            if isinstance(v, dict) and "regex" in v:
                if v["regex"] in (".*", ".+", "(?s).*"):
                    score -= 0.3; notes.append(f"over-broad regex on {k}")
                try:
                    re.compile(v["regex"])
                except re.error:
                    score -= 0.5; notes.append(f"bad regex on {k}")
    return max(0.0, score), notes


def run_gauntlet(
    candidate_yaml: str,
    existing: list[Scenario],
    extra_used: set[str] | None = None,
    extra_fingerprints: set[tuple] | None = None,
) -> GauntletResult:
    """Run the gauntlet for a single candidate YAML.

    :param existing: Scenario objects already in the library.
    :param extra_used: scenario_ids already assigned in the current batch so
                       ``_next_gen_id`` doesn't hand out the same id twice.
    :param extra_fingerprints: fingerprints of scenarios that already passed
                               earlier in the current batch, used to dedup
                               intra-batch siblings.
    """
    # (a) schema
    try:
        data = yaml.safe_load(candidate_yaml)
        scenario = Scenario(**data)
    except Exception as exc:
        return GauntletResult(False, reject_stage="schema", reason=str(exc), yaml=candidate_yaml)

    # assign a fresh generated id (avoid collisions within this batch too)
    sid = _next_gen_id(existing, extra_used)
    data["scenario_metadata"]["scenario_id"] = sid
    scenario = Scenario(**data)
    canonical_yaml = yaml.safe_dump(data, sort_keys=False)

    # (b) dedup — check against library AND earlier passers in this batch
    fp = _fingerprint(scenario)
    existing_fps = {_fingerprint(e) for e in existing}
    all_fps = existing_fps | (extra_fingerprints or set())
    if fp in all_fps:
        return GauntletResult(False, sid, "dedup", "structural duplicate of an existing scenario",
                              yaml=canonical_yaml)

    topo = default_topology()

    # (c) FP guard — must not fire on benign
    raws = []
    for p in _BENIGN_PATHS:
        raws.extend(read_jsonl(p))
    backend = NetworkXBackend()
    build_graph(sorted(normalize_events(raws), key=lambda e: e.timestamp), topo, backend)
    for d in run_engine(backend, [scenario], min_proximity=0.0):
        if d.proximity >= _FP_THRESHOLD:
            return GauntletResult(False, sid, "fp_guard",
                                  f"fires on benign at {d.proximity}", yaml=canonical_yaml)

    notes: list[str] = []
    # (d) detectability — synthesize a positive trace; must fully fire. Un-synthesizable -> soft flag.
    trace = synthesize_trace(scenario, topo)
    if trace is not None:
        b2 = NetworkXBackend()
        build_graph(sorted(normalize_events(trace), key=lambda e: e.timestamp), topo, b2)
        dets = {d.scenario_id: d for d in run_engine(b2, [scenario], min_proximity=0.0)}
        det = dets.get(scenario.scenario_id)
        if det is None or det.proximity < 1.0:
            return GauntletResult(False, sid, "detectability",
                                  "synthesized trace did not fully match", yaml=canonical_yaml)
    else:
        notes.append("not auto-synthesizable; reviewer should confirm detectability")

    # (e) plausibility (soft)
    score, pnotes = _plausibility(scenario)
    return GauntletResult(True, sid, plausibility=score, yaml=canonical_yaml, notes=notes + pnotes)
