import hmac

from fastapi import Depends, HTTPException, Request, status

from augur.auth.config import AuthConfig
from augur.auth.store import AuthEvents, SessionStore, User, UserStore, role_rank

COOKIE_NAME = "fs_session"
CSRF_HEADER = "X-CSRF-Token"


class AuthState:
    """Per-app auth wiring (holds the sqlite connection + stores + config + rate limiter)."""
    def __init__(self, conn, config: AuthConfig, rate_limiter) -> None:
        self.conn = conn
        self.config = config
        self.users = UserStore(conn)
        self.sessions = SessionStore(conn, config.session_idle_seconds, config.session_max_seconds)
        self.events = AuthEvents(conn)
        self.rl = rate_limiter
        # Per-IP limiter (set by attach_auth); guards against username-rotating spray.
        self.rl_ip = None


def get_state(request: Request) -> AuthState:
    return request.app.state.auth


def get_current_user(request: Request, state: AuthState = Depends(get_state)) -> User:
    sid = request.cookies.get(COOKIE_NAME)
    if not sid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    sess = state.sessions.get(sid)
    if sess is None or not state.sessions.is_valid(sess):
        if sess is not None:
            state.sessions.delete(sess.id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired")
    user = state.users.get_by_id(sess.user_id)
    if user is None or user.disabled:
        state.sessions.delete(sess.id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account unavailable")
    state.sessions.touch(sess.id)
    request.state.session = sess
    return user


def require_role(min_role: str):
    def _dep(user: User = Depends(get_current_user)) -> User:
        if role_rank(user.role) < role_rank(min_role):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return user
    return _dep


def verify_csrf(request: Request, state: AuthState = Depends(get_state)) -> None:
    sid = request.cookies.get(COOKIE_NAME)
    sess = state.sessions.get(sid) if sid else None
    header = request.headers.get(CSRF_HEADER, "")
    if sess is None or not header or not hmac.compare_digest(header, sess.csrf_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid CSRF token")
