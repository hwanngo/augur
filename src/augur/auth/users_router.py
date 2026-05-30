from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from augur.auth.deps import AuthState, get_state, require_role, verify_csrf
from augur.auth.hashing import hash_password
from augur.auth.policy import check_password as _check_password
from augur.auth.store import ROLES

users_router = APIRouter(prefix="/api/users", tags=["users"])


class NewUser(BaseModel):
    username: str = Field(min_length=1)
    password: str
    role: str


class PatchUser(BaseModel):
    role: str | None = None
    disabled: bool | None = None


class NewPassword(BaseModel):
    password: str


def _public(u) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role, "disabled": u.disabled,
            "created_at": u.created_at, "updated_at": u.updated_at}


@users_router.get("")
def list_users(_: object = Depends(require_role("admin")), state: AuthState = Depends(get_state)):
    return [_public(u) for u in state.users.list_users()]


@users_router.post("", status_code=201)
def create_user(body: NewUser, _csrf: None = Depends(verify_csrf),
                _: object = Depends(require_role("admin")), state: AuthState = Depends(get_state)):
    if body.role not in ROLES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid role")
    _check_password(body.password, body.username)
    if state.users.get_by_username(body.username):
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
    uid = state.users.create_user(body.username, hash_password(body.password), body.role)
    state.events.log("user_created", detail=f"{body.username}/{body.role}")
    return _public(state.users.get_by_id(uid))


@users_router.patch("/{uid}")
def patch_user(uid: int, body: PatchUser, _csrf: None = Depends(verify_csrf),
               _: object = Depends(require_role("admin")), state: AuthState = Depends(get_state)):
    target = state.users.get_by_id(uid)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    # guard the last admin against demotion/disable
    demote = (body.role is not None and body.role != "admin") or (body.disabled is True)
    if target.role == "admin" and demote and state.users.count_admins() <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "cannot remove the last admin")
    state.users.update_user(uid, role=body.role, disabled=body.disabled)
    if body.disabled:
        state.sessions.delete_user_sessions(uid)
    state.events.log("user_updated", detail=str(uid))
    return _public(state.users.get_by_id(uid))


@users_router.post("/{uid}/reset-password")
def reset_password(uid: int, body: NewPassword, _csrf: None = Depends(verify_csrf),
                   _: object = Depends(require_role("admin")), state: AuthState = Depends(get_state)):
    target = state.users.get_by_id(uid)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    _check_password(body.password, target.username)
    state.users.set_password(uid, hash_password(body.password))
    state.sessions.delete_user_sessions(uid)
    state.events.log("password_reset", detail=str(uid))
    return {"ok": True}


@users_router.delete("/{uid}")
def delete_user(uid: int, _csrf: None = Depends(verify_csrf),
                _: object = Depends(require_role("admin")), state: AuthState = Depends(get_state)):
    target = state.users.get_by_id(uid)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    if target.role == "admin" and state.users.count_admins() <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "cannot delete the last admin")
    state.users.delete_user(uid)
    state.events.log("user_deleted", detail=str(uid))
    return {"ok": True}


@users_router.post("/{uid}/revoke-sessions")
def admin_revoke_sessions(uid: int, _csrf: None = Depends(verify_csrf),
                          _: object = Depends(require_role("admin")),
                          state: AuthState = Depends(get_state)):
    state.sessions.delete_user_sessions(uid)
    state.events.log("sessions_revoked", detail=str(uid))
    return {"ok": True}


# Audit log is mounted under /api/audit (not /api/users), handled via the auth_router extension.
# We add it here as a standalone APIRouter so it can be included from attach_auth.
from fastapi import APIRouter as _AR, Query

audit_router = _AR(prefix="/api/audit", tags=["audit"])


@audit_router.get("")
def get_audit(limit: int = Query(100, ge=1, le=1000),
              _: object = Depends(require_role("admin")),
              state: AuthState = Depends(get_state)):
    return state.events.recent(limit)
