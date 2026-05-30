from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    # Catch only the expected argon2 failure modes (wrong password / malformed
    # stored hash). VerificationError is the parent of VerifyMismatchError. Other
    # exceptions (e.g. argon2 backend/memory failures) propagate so operational
    # problems are observable instead of silently denying everyone.
    try:
        _ph.verify(password_hash, password)
        return True
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _ph.check_needs_rehash(password_hash)
    except Exception:
        return True
