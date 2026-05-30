"""Shared auth policy helpers (password strength, etc.)."""
from fastapi import HTTPException, status

from augur.auth.config import load_config

_MINLEN = load_config().min_password_len   # 12
# argon2 hashing is CPU-bound; cap input to avoid a DoS vector. Public so the
# login path can reject oversized passwords before spending a hash.
MAX_PASSWORD_LEN = 1024


def check_password(password: str, username: str) -> None:
    """Raise HTTP 422 if the password violates the strength policy."""
    if len(password) < _MINLEN or username.lower() in password.lower():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"password must be >= {_MINLEN} chars and not contain the username",
        )
    if len(password) > MAX_PASSWORD_LEN:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"password must be <= {MAX_PASSWORD_LEN} chars",
        )
