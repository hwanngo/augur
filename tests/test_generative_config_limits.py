from augur.generative.config import load_ai_config


def test_config_has_throughput_limits(monkeypatch):
    monkeypatch.delenv("AUGUR_AI_MAX_CALLS", raising=False)
    monkeypatch.delenv("AUGUR_AI_WINDOW_SECONDS", raising=False)
    c = load_ai_config()
    assert c.max_calls == 30 and c.window_seconds == 900
