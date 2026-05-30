import logging
import os
import secrets
from dataclasses import dataclass

_VALID_ENVS = {"dev", "prod", "test"}
_log = logging.getLogger("augur.auth")


@dataclass(frozen=True)
class AuthConfig:
    env: str
    secret_key: str
    db_path: str
    cookie_secure: bool
    session_idle_seconds: int = 12 * 3600
    session_max_seconds: int = 7 * 24 * 3600
    rl_max_failures: int = 5
    rl_window_seconds: int = 15 * 60
    rl_lockout_seconds: int = 15 * 60
    # Per-IP failure cap (across all usernames) defends against password-spray and
    # avoids a single username lockout being the only control. Higher than the
    # per-username cap so NAT'd legitimate users aren't locked out prematurely.
    rl_ip_max_failures: int = 50
    # Only honor X-Forwarded-For when running behind a trusted reverse proxy.
    trust_proxy: bool = False
    min_password_len: int = 12


def load_config() -> AuthConfig:
    env = os.environ.get("AUGUR_ENV", "dev")
    if env not in _VALID_ENVS:
        raise RuntimeError(f"AUGUR_ENV must be one of {sorted(_VALID_ENVS)}, got {env!r}")
    secret = os.environ.get("AUGUR_SECRET_KEY")
    if not secret:
        if env == "prod":
            raise RuntimeError("AUGUR_SECRET_KEY is required when AUGUR_ENV=prod")
        secret = secrets.token_urlsafe(32)  # ephemeral; dev/test sessions don't survive restart
    # Secure cookies default to on in prod, but can be overridden (e.g. a prod stack
    # served over plain HTTP behind a TLS-terminating reverse proxy, or the bundled
    # docker compose demo on http://localhost).
    cookie_secure = env == "prod"
    override = os.environ.get("AUGUR_COOKIE_SECURE")
    if override is not None:
        cookie_secure = override.strip().lower() in ("1", "true", "yes", "on")
    if env == "prod" and not cookie_secure:
        _log.warning(
            "AUGUR_COOKIE_SECURE is disabled in prod: session cookies will be sent "
            "over plaintext HTTP. Only do this behind a TLS-terminating proxy."
        )
    trust_proxy = os.environ.get("AUGUR_TRUST_PROXY", "").strip().lower() in ("1", "true", "yes", "on")
    ip_max = int(os.environ.get("AUGUR_RL_IP_MAX", AuthConfig.rl_ip_max_failures))
    return AuthConfig(
        env=env, secret_key=secret,
        db_path=os.environ.get("AUGUR_DB", "data/augur.db"),
        cookie_secure=cookie_secure,
        rl_ip_max_failures=ip_max,
        trust_proxy=trust_proxy,
    )
