from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Request, Response, status
from pydantic import BaseModel

from augur.auth.config import load_config
from augur.auth.deps import (COOKIE_NAME, AuthState, get_current_user, get_state, verify_csrf)
from augur.auth.hashing import hash_password, needs_rehash, verify_password
from augur.auth.policy import check_password, MAX_PASSWORD_LEN
from augur.auth.ratelimit import RateLimiter, SqliteRateLimiter
from augur.auth.store import connect

auth_router = APIRouter(prefix="/api/auth", tags=["auth"])


class _ChangePassword(BaseModel):
    current_password: str
    new_password: str

# Precomputed once: used to run an argon2 verify for unknown/disabled users so an
# attacker cannot distinguish "no such user" (fast) from "wrong password" (slow argon2).
_DUMMY_HASH = hash_password("timing-equalizer-not-a-real-account")


def _client_ip(request: Request, state: "AuthState | None" = None) -> str:
    # Only trust X-Forwarded-For when explicitly configured to run behind a proxy;
    # otherwise XFF is attacker-controlled and would let a client spoof its IP to
    # evade per-IP throttling. Falls back to the socket peer. Prefer the already
    # resolved AuthState.config; only load_config() as a fallback (e.g. unit tests
    # that call this helper without a state) — never per-request in the app path.
    if state is not None:
        trust = state.config.trust_proxy
    else:
        try:
            trust = load_config().trust_proxy
        except Exception:
            trust = False
    if trust:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "?"


@auth_router.post("/login")
def login(request: Request, response: Response, username: str = Form(...),
          password: str = Form(...), state: AuthState = Depends(get_state)):
    ip = _client_ip(request, state)
    if state.rl.is_locked(username) or (state.rl_ip and state.rl_ip.is_locked(ip)):
        state.events.log("login_lockout", username=username, ip=ip)
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts; try later")
    # Reject absurdly long passwords BEFORE the (CPU-bound) argon2 verify — this
    # is the pre-auth surface, so the cap must apply here, not just on signup.
    if len(password) > MAX_PASSWORD_LEN:
        state.rl.record_failure(username)
        if state.rl_ip:
            state.rl_ip.record_failure(ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    user = state.users.get_by_username(username)
    if user is None or user.disabled:
        verify_password(_DUMMY_HASH, password)   # equalize timing with a real argon2 verify
        ok = False
    else:
        ok = verify_password(user.password_hash, password)
    if not ok:
        state.rl.record_failure(username)
        if state.rl_ip:
            state.rl_ip.record_failure(ip)
        state.events.log("login_failed", username=username, ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if needs_rehash(user.password_hash):
        state.users.set_password(user.id, hash_password(password))
    state.rl.reset(username)
    if state.rl_ip:
        state.rl_ip.reset(ip)
    sess = state.sessions.create_session(user.id)
    state.events.log("login_ok", username=username, ip=ip)
    response.set_cookie(COOKIE_NAME, sess.id, httponly=True, samesite="strict",
                        secure=state.config.cookie_secure, path="/")
    return {"user": user.username, "role": user.role, "csrf_token": sess.csrf_token}


@auth_router.post("/logout")
def logout(request: Request, response: Response, _csrf: None = Depends(verify_csrf),
           user=Depends(get_current_user), state: AuthState = Depends(get_state)):
    sid = request.cookies.get(COOKIE_NAME)
    if sid:
        state.sessions.delete(sid)
    response.delete_cookie(COOKIE_NAME, path="/")
    state.events.log("logout", username=user.username, ip=_client_ip(request, state))
    return {"ok": True}


@auth_router.get("/me")
def me(request: Request, user=Depends(get_current_user),
       state: AuthState = Depends(get_state)):
    # Return the current session's CSRF token so a reloaded SPA can restore it
    # (login hands it back the same way). Without this, mutations 403 after a refresh.
    sid = request.cookies.get(COOKIE_NAME)
    sess = state.sessions.get(sid) if sid else None
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "csrf_token": sess.csrf_token if sess else None,
    }


@auth_router.post("/change-password")
def change_password(request: Request, body: _ChangePassword,
                    _csrf: None = Depends(verify_csrf),
                    user=Depends(get_current_user),
                    state: AuthState = Depends(get_state)):
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "current password is incorrect")
    check_password(body.new_password, user.username)
    state.users.set_password(user.id, hash_password(body.new_password))
    # Revoke all OTHER sessions (keep the current one)
    current_sid = request.cookies.get(COOKIE_NAME)
    for sess in state.sessions.list_for_user(user.id):
        if sess.id != current_sid:
            state.sessions.delete(sess.id)
    state.events.log("password_changed", username=user.username, ip=_client_ip(request, state))
    return {"ok": True}


@auth_router.get("/sessions")
def list_sessions(request: Request, user=Depends(get_current_user),
                  state: AuthState = Depends(get_state)):
    current_sid = request.cookies.get(COOKIE_NAME)
    sessions = state.sessions.list_for_user(user.id)
    return [
        {
            "id": s.id,
            "created_at": s.created_at,
            "last_seen": s.last_seen,
            "expires_at": s.expires_at,
            "current": s.id == current_sid,
        }
        for s in sessions
    ]


@auth_router.delete("/sessions/{sid}")
def revoke_session(sid: str, request: Request,
                   _csrf: None = Depends(verify_csrf),
                   user=Depends(get_current_user),
                   state: AuthState = Depends(get_state)):
    sess = state.sessions.get(sid)
    if sess is None or sess.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    state.sessions.delete(sid)
    state.events.log("session_revoked", username=user.username, ip=_client_ip(request, state))
    return {"ok": True}


def attach_auth(app: FastAPI, *, rate_limiter: RateLimiter | None = None) -> AuthState:
    """Create the auth store, mount routers, bootstrap admin, return the AuthState."""
    from augur.auth.users_router import audit_router, users_router  # Task 7
    from augur.auth.bootstrap import bootstrap_admin   # Task 7

    config = load_config()
    conn = connect(config.db_path)
    # DB-backed limiters by default so lockout state is shared across worker
    # processes and survives a restart. A caller may still inject an in-memory
    # RateLimiter (e.g. unit tests) via `rate_limiter`.
    rl = rate_limiter or SqliteRateLimiter(conn, config.rl_max_failures,
                                           config.rl_window_seconds, config.rl_lockout_seconds,
                                           namespace="user")
    state = AuthState(conn, config, rl)
    state.rl_ip = SqliteRateLimiter(conn, config.rl_ip_max_failures,
                                    config.rl_window_seconds, config.rl_lockout_seconds,
                                    namespace="ip")
    app.state.auth = state
    app.include_router(auth_router)
    app.include_router(users_router)
    app.include_router(audit_router)
    bootstrap_admin(state)
    return state
