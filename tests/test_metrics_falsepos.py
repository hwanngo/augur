import pytest
from augur.pipeline import default_scenarios, default_topology
from augur.metrics.falsepos import generate_benign_corpus, false_positive_rate


def test_generate_benign_corpus_is_deterministic():
    a = generate_benign_corpus(seed=1234, duration_seconds=600, rate_per_minute=10)
    b = generate_benign_corpus(seed=1234, duration_seconds=600, rate_per_minute=10)
    assert a == b
    assert len(a) > 0


def test_generate_benign_corpus_different_seed():
    a = generate_benign_corpus(seed=1, duration_seconds=600, rate_per_minute=10)
    b = generate_benign_corpus(seed=2, duration_seconds=600, rate_per_minute=10)
    assert a != b


def test_false_positive_rate_no_fps():
    scenarios = default_scenarios()
    topology = default_topology()
    # 1-hour window, 60 events/min = 3600 events — enough to be meaningful, fast enough for CI
    corpus = generate_benign_corpus(seed=1234, duration_seconds=3600, rate_per_minute=60)
    result = false_positive_rate(scenarios, corpus, topology)

    assert result["false_positives"] == 0
    assert result["benign_events"] > 0
    assert result["fp_rate"] == 0.0
    assert result["fired_scenarios"] == []


def test_false_positive_rate_empty_corpus():
    result = false_positive_rate(default_scenarios(), [], default_topology())
    assert result["benign_events"] == 0
    assert result["false_positives"] == 0
    assert result["fp_rate"] == 0.0
    assert result["fired_scenarios"] == []


def test_false_positive_rate_structure():
    corpus = generate_benign_corpus(seed=42, duration_seconds=60, rate_per_minute=5)
    result = false_positive_rate(default_scenarios(), corpus, default_topology())
    assert set(result.keys()) == {"benign_events", "false_positives", "fp_rate", "fired_scenarios"}
    assert isinstance(result["fired_scenarios"], list)
    assert result["fired_scenarios"] == sorted(result["fired_scenarios"])
