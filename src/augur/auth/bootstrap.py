import logging
import os

from augur.auth.hashing import hash_password

_log = logging.getLogger("augur.auth")


def bootstrap_admin(state) -> None:
    """First-run: create the env-specified admin iff there are no users yet. No default password."""
    if not state.users.is_empty():
        return
    user = os.environ.get("AUGUR_ADMIN_USER")
    pw = os.environ.get("AUGUR_ADMIN_PASSWORD")
    if user and pw:
        state.users.create_user(user, hash_password(pw), "admin")
        state.events.log("bootstrap_admin", username=user)
        _log.info("bootstrapped initial admin %r", user)
    else:
        _log.warning("no users and AUGUR_ADMIN_USER/PASSWORD unset — system is LOCKED until "
                     "an admin is created (use `python -m augur.useradmin add`).")
