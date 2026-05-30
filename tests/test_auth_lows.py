"""TDD: password upper bound, narrowed verify_password exception handling,
and a loud warning when secure cookies are disabled in prod."""
import logging

import pytest
from fastapi import HTTPException

from augur.auth.hashing import hash_password, verify_password
from augur.auth.policy import check_password


def test_password_rejected_when_too_long():
    # Argon2 hashing is CPU-bound; an unbounded password is a mild DoS vector.
    with pytest.raises(HTTPException) as ei:
        check_password("a" * 5000, "someuser")
    assert ei.value.status_code == 422


def test_password_accepts_reasonable_length():
    check_password("a-perfectly-fine-password", "someuser")  # no raise


def test_verify_password_false_on_malformed_hash():
    # A corrupt/garbage stored hash must verify False, not raise.
    assert verify_password("not-an-argon2-hash", "whatever") is False


def test_verify_password_roundtrip():
    h = hash_password("correct horse battery staple")
    assert verify_password(h, "correct horse battery staple") is True
    assert verify_password(h, "wrong") is False


def test_prod_insecure_cookie_logs_warning(monkeypatch, caplog):
    monkeypatch.setenv("AUGUR_ENV", "prod")
    monkeypatch.setenv("AUGUR_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("AUGUR_COOKIE_SECURE", "false")
    import augur.auth.config as cfg
    with caplog.at_level(logging.WARNING, logger="augur.auth"):
        c = cfg.load_config()
    assert c.cookie_secure is False
    assert any("cookie" in r.message.lower() and "secure" in r.message.lower()
               for r in caplog.records), "expected a warning about insecure cookies in prod"
