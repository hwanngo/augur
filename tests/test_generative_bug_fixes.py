"""Regression tests for the confirmed bugs in src/augur/generative/.

One test per bug, written BEFORE the fix (TDD RED phase).

C1 — synth.py File branch ignores Path/FileName criteria
C2 — _next_gen_id collides across a batch
I1 — batch-sibling dedup missing
N1 — fingerprint is value-blind
N2 — _parse_yaml_candidates glues leading prose onto first doc
N3 — claude.py messages.create never passes temperature
N4 — dead by_cat/cat="unknown" code in eval.main
"""

import yaml
import pytest

from augur.generative.fake import SAMPLE_VALID_YAML
from augur.generative.synth import synthesize_trace
from augur.generative.gauntlet import run_gauntlet, _fingerprint
from augur.generative.engine import generate_candidates
from augur.generative.fake import FakeScenarioGenerator
from augur.scenarios.loader import load_scenarios
from augur.scenarios.schema import Scenario
from augur.pipeline import default_topology
from augur.graph.networkx_backend import NetworkXBackend
from augur.graph.builder import build_graph
from augur.normalize.ecs import normalize_events
from augur.engine.runner import run_engine

# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

EXISTING = load_scenarios("scenarios")
_BY_ID = {s.scenario_id: s for s in EXISTING}
_TOPO = default_topology()


def _run_synth(sid: str):
    """Return (scenario, trace_or_None) for a library scenario."""
    s = _BY_ID[sid]
    trace = synthesize_trace(s, _TOPO)
    return s, trace


def _proximity(scenario, events):
    b = NetworkXBackend()
    build_graph(sorted(normalize_events(events), key=lambda e: e.timestamp), _TOPO, b)
    dets = {d.scenario_id: d for d in run_engine(b, [scenario], min_proximity=0.0)}
    det = dets.get(scenario.scenario_id)
    return det.proximity if det else 0.0


# ─────────────────────────────────────────────────────────────────────────────
# C1 — File-step Path / FileName criteria ignored by synthesizer
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sid", ["SCEN-WIN-003", "SCEN-WIN-011", "SCEN-WIN-012", "SCEN-WIN-015"])
def test_c1_file_path_filename_no_partial_trace(sid):
    """synthesize_trace must return None OR a fully-matching trace (proximity == 1.0).
    NEVER a partial-firing trace for a scenario that has a File step.
    """
    s, trace = _run_synth(sid)
    if trace is None:
        return  # soft-flagged — acceptable
    prox = _proximity(s, trace)
    assert prox == 1.0, (
        f"Partial trace for {sid}: proximity={prox}. "
        "synthesize_trace emitted a trace that doesn't fully match the scenario."
    )


def test_c1_sample_valid_still_full():
    """The existing SAMPLE_VALID_YAML scenario must still synthesize at 1.0."""
    s = Scenario(**yaml.safe_load(SAMPLE_VALID_YAML))
    events = synthesize_trace(s, _TOPO)
    assert events is not None
    assert _proximity(s, events) == 1.0


# ─────────────────────────────────────────────────────────────────────────────
# C2 — _next_gen_id assigns the same id to every candidate in a batch
# ─────────────────────────────────────────────────────────────────────────────

def test_c2_batch_of_3_has_distinct_ids():
    """generate_candidates over 3 candidates must produce 3 *distinct* SCEN-GEN-NNNN ids."""
    # Use a fake generator that returns 3 structurally-different YAMLs
    # (different technique ids so they pass dedup)
    from augur.generative.base import GenerationRequest

    # Build 3 variants of SAMPLE_VALID_YAML with different MITRE techniques so each
    # can pass the dedup gate (different fingerprint).
    techniques = ["T1059.001", "T1059.002", "T1059.003"]
    yamls = []
    for i, tech in enumerate(techniques):
        y = (
            SAMPLE_VALID_YAML
            .replace("SCEN-GEN-0001", f"SCEN-GEN-BATCH-{i}")
            .replace("T1059.001", tech)
            # also vary the process name so the fingerprint changes
            .replace('{ in: ["powershell.exe"] }', f'{{ in: ["proc{i}.exe"] }}')
        )
        yamls.append(y)

    class BatchFakeGen:
        def generate(self, request, n):
            return yamls[:n]

    req = GenerationRequest(seed_id="SCEN-WIN-001", n=3)
    results = generate_candidates(req, BatchFakeGen(), EXISTING)
    passers = [r for r in results if r.passed]
    ids = [r.scenario_id for r in passers]
    assert len(ids) == len(set(ids)), (
        f"Duplicate ids in a batch of 3 candidates: {ids}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# I1 — batch-sibling dedup missing (duplicate siblings all pass)
# ─────────────────────────────────────────────────────────────────────────────

def test_i1_identical_siblings_deduplicated():
    """Four structurally-identical candidates in one batch: only the first should pass dedup,
    the rest must be rejected at stage 'dedup'.
    """
    from augur.generative.base import GenerationRequest

    class AllSameGen:
        def generate(self, request, n):
            # All 4 are byte-for-byte identical (same fingerprint, same values)
            return [SAMPLE_VALID_YAML] * n

    req = GenerationRequest(seed_id="SCEN-WIN-001", n=4)
    results = generate_candidates(req, AllSameGen(), EXISTING)
    passers = [r for r in results if r.passed]
    dedup_rejections = [r for r in results if r.reject_stage == "dedup"]
    # At most 1 should pass (the first); the other 3 must be dedup-rejected
    assert len(passers) <= 1, f"Expected ≤1 passer from 4 identical siblings, got {len(passers)}"
    assert len(dedup_rejections) >= 3, (
        f"Expected ≥3 dedup rejections from 4 identical siblings, got {len(dedup_rejections)}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# N1 — fingerprint is value-blind (tool-swap mutation treated as duplicate)
# ─────────────────────────────────────────────────────────────────────────────

def _make_scenario(process_name: str) -> Scenario:
    """Return a scenario identical to SAMPLE_VALID_YAML except for ProcessName value."""
    y = SAMPLE_VALID_YAML.replace('{ in: ["powershell.exe"] }', f'{{ in: ["{process_name}"] }}')
    return Scenario(**yaml.safe_load(y))


def test_n1_tool_swap_produces_different_fingerprint():
    """A powershell.exe → evil.exe swap must produce a DIFFERENT fingerprint (not deduped)."""
    s1 = _make_scenario("powershell.exe")
    s2 = _make_scenario("evil.exe")
    assert _fingerprint(s1) != _fingerprint(s2), (
        "Tool-swap mutation not reflected in fingerprint — "
        "powershell.exe and evil.exe scenarios share the same fingerprint."
    )


def test_n1_exact_duplicate_same_fingerprint():
    """An exact copy of a scenario must still produce the SAME fingerprint (dedup works)."""
    s1 = _make_scenario("powershell.exe")
    s2 = _make_scenario("powershell.exe")
    assert _fingerprint(s1) == _fingerprint(s2), (
        "Identical scenarios should have identical fingerprints."
    )


def test_n1_existing_dup_still_rejected():
    """A byte-for-byte re-dump of SCEN-WIN-001 must still be rejected at 'dedup' stage."""
    s = _BY_ID["SCEN-WIN-001"]
    dup_yaml = yaml.safe_dump(s.model_dump(mode="json"), sort_keys=False)
    r = run_gauntlet(dup_yaml, EXISTING)
    assert r.passed is False and r.reject_stage == "dedup", (
        f"Expected dedup rejection, got: passed={r.passed}, stage={r.reject_stage}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# N2 — _parse_yaml_candidates glues prose onto first doc
# ─────────────────────────────────────────────────────────────────────────────

def test_n2_prose_stripped_before_first_doc():
    """A fake LLM response with leading prose must parse cleanly — no prose contamination."""
    from augur.generative.claude import _parse_yaml_candidates

    # Case 1: prose + fenced yaml blocks
    prose = "Here are two scenario candidates:\n\n"
    fence1 = "```yaml\nscenario_metadata:\n  scenario_id: SCEN-GEN-0001\n  name: First\n```\n"
    sep = "---\n"
    fence2 = "```yaml\nscenario_metadata:\n  scenario_id: SCEN-GEN-0002\n  name: Second\n```\n"

    raw = prose + fence1 + sep + fence2
    results = _parse_yaml_candidates(raw)
    assert len(results) == 2, f"Expected 2 docs, got {len(results)}: {results}"
    for doc in results:
        parsed = yaml.safe_load(doc)
        assert "scenario_metadata" in parsed, f"Doc missing scenario_metadata: {doc!r}"
        assert isinstance(parsed["scenario_metadata"], dict), f"scenario_metadata is not a dict: {doc!r}"

    # Case 2: prose WITHOUT a code fence (the original bug): prose line must not appear as a YAML key
    raw_no_fence = (
        "Here are two candidates for your review:\n\n"
        "scenario_metadata:\n  scenario_id: SCEN-GEN-0001\n  name: First\n"
        "---\n"
        "scenario_metadata:\n  scenario_id: SCEN-GEN-0002\n  name: Second\n"
    )
    results2 = _parse_yaml_candidates(raw_no_fence)
    assert len(results2) == 2, f"Expected 2 docs, got {len(results2)}: {results2}"
    for doc in results2:
        parsed = yaml.safe_load(doc)
        assert "scenario_metadata" in parsed, f"Doc missing scenario_metadata: {doc!r}"
        assert isinstance(parsed["scenario_metadata"], dict), f"Prose leaked into YAML doc: {doc!r}"
        # Must NOT have arbitrary prose keys
        for key in parsed:
            assert key == "scenario_metadata", f"Unexpected top-level key (prose leak?): {key!r}"


def test_n2_no_fence_single_doc():
    """Response without a code fence returns the raw YAML doc."""
    from augur.generative.claude import _parse_yaml_candidates

    raw = "scenario_metadata:\n  scenario_id: X\n  name: Y\n"
    results = _parse_yaml_candidates(raw)
    assert len(results) >= 1
    assert "scenario_metadata" in yaml.safe_load(results[0])


# ─────────────────────────────────────────────────────────────────────────────
# N3 — claude.py messages.create never passes temperature
# This is a code-inspection test (no live API call required).
# ─────────────────────────────────────────────────────────────────────────────

def test_n3_messages_create_passes_temperature():
    """ClaudeScenarioGenerator.generate must call messages.create with temperature kwarg."""
    import ast, textwrap
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] /
           "src" / "augur" / "generative" / "claude.py").read_text()
    tree = ast.parse(src)

    # Find all calls to messages.create (or self._client.messages.create)
    found_temp = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Check if this is a .create(...) call
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "create":
                kw_names = {kw.arg for kw in node.keywords}
                if "temperature" in kw_names:
                    found_temp = True
                    break

    assert found_temp, (
        "messages.create() call in claude.py does not pass the 'temperature' keyword argument."
    )


# ─────────────────────────────────────────────────────────────────────────────
# N4 — dead by_cat / cat="unknown" code in eval.main
# ─────────────────────────────────────────────────────────────────────────────

def test_n4_dead_code_removed_from_eval_main():
    """eval.main must not contain the dead by_cat / cat='unknown' assignment."""
    import ast
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] /
           "src" / "augur" / "generative" / "eval.py").read_text()

    # The dead code pattern: cat = "unknown"
    assert 'cat = "unknown"' not in src, (
        "Dead code `cat = \"unknown\"` still present in eval.py. Remove it."
    )
    # by_cat dict should be gone too
    assert "by_cat" not in src, (
        "Dead `by_cat` variable still present in eval.py. Remove it."
    )
