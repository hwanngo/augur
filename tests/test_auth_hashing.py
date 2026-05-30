from augur.auth.hashing import hash_password, verify_password, needs_rehash


def test_hash_is_not_plaintext_and_verifies():
    h = hash_password("correct horse battery staple")
    assert h != "correct horse battery staple" and h.startswith("$argon2")
    assert verify_password(h, "correct horse battery staple") is True
    assert verify_password(h, "wrong") is False


def test_needs_rehash_returns_bool():
    assert isinstance(needs_rehash(hash_password("abcdefghijkl")), bool)


def test_verify_handles_garbage_hash():
    assert verify_password("not-a-hash", "x") is False
