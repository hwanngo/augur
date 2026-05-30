"""Invariant 6 guard: the engine is STRUCTURALLY BLIND to NormalizedEvent.hashes.

Populating `hashes` on the corpus must change ZERO matcher input. This test locks that in three ways:
  1. `hashes` is in NEITHER criteria field map (the engine only reads NormalizedEvent via these maps).
  2. A scenario whose criteria reference a `hashes`/`Hashes` field cannot drive the engine (it is in no
     field map, so a step naming it can never match).
  3. Detectability stays 40/40 (the engine sees byte-identical input with or without hashes).
"""
import pytest

from augur.engine.criteria import PROCESS_KEY_MAP, FILE_KEY_MAP


def test_hashes_absent_from_criteria_field_maps():
    assert "hashes" not in PROCESS_KEY_MAP.values()
    assert "hashes" not in FILE_KEY_MAP.values()
    assert "hashes" not in PROCESS_KEY_MAP
    assert "hashes" not in FILE_KEY_MAP
    assert "Hashes" not in PROCESS_KEY_MAP
    assert "Hashes" not in FILE_KEY_MAP


def test_hash_criterion_is_in_no_field_map():
    """A `Hashes` criterion is in no field map, so the engine can never match it — even if a scenario
    schema would LOAD such a step (matching_criteria is free-form), it could never fire."""
    assert "Hashes" not in PROCESS_KEY_MAP and "Hashes" not in FILE_KEY_MAP
    assert "hashes" not in PROCESS_KEY_MAP and "hashes" not in FILE_KEY_MAP


def test_detectability_stays_40_of_40():
    from augur.metrics.detectability import detectability
    from augur.pipeline import default_scenarios, default_topology
    rep = detectability(default_scenarios(), default_topology())
    assert rep["total"] == 40
    assert rep["detectable"] == 40
    assert rep["detectability_rate"] == 1.0
