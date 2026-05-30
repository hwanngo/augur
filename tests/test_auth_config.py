import pytest
from augur.auth.config import load_config


def test_dev_generates_ephemeral_secret(monkeypatch):
    monkeypatch.delenv("AUGUR_SECRET_KEY", raising=False)
    monkeypatch.setenv("AUGUR_ENV", "dev")
    c = load_config()
    assert c.env == "dev" and c.secret_key and c.cookie_secure is False


def test_prod_without_secret_fails(monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "prod")
    monkeypatch.delenv("AUGUR_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        load_config()


def test_prod_with_secret_is_secure(monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "prod")
    monkeypatch.setenv("AUGUR_SECRET_KEY", "x" * 32)
    c = load_config()
    assert c.cookie_secure is True and c.secret_key == "x" * 32


def test_invalid_env_rejected(monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "weird")
    with pytest.raises(RuntimeError):
        load_config()


def test_cookie_secure_override(monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "prod")
    monkeypatch.setenv("AUGUR_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("AUGUR_COOKIE_SECURE", "false")
    assert load_config().cookie_secure is False           # prod can opt out (behind TLS proxy)
    monkeypatch.setenv("AUGUR_ENV", "dev")
    monkeypatch.delenv("AUGUR_SECRET_KEY", raising=False)
    monkeypatch.setenv("AUGUR_COOKIE_SECURE", "true")
    assert load_config().cookie_secure is True            # dev can opt in
