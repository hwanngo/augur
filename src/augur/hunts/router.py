import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from augur.auth.deps import AuthState, require_role, verify_csrf
from augur.enums import Zone
from augur.hunts.store import HuntStore, Hunt, _HUNT_STATUSES
from augur.hunts.evidence import compute_hunt_evidence

_TERMINAL = {"confirmed", "refuted"}
hunts_router = APIRouter(prefix="/api/hunts", tags=["hunts"])


class _HuntsState:
    def __init__(self, store, *, windowed_at, scenarios, topology):
        self.hunts = store; self.windowed_at = windowed_at
        self.scenarios = scenarios; self.topology = topology


def _hstate(request: Request) -> _HuntsState:
    return request.app.state.hunts


class _Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_ids: list[str] = []
    tactic: str | None = None
    zone: str | None = None
    host: str | None = None
    from_: str | None = Field(default=None, alias="from")
    to: str | None = None


class _CreateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hypothesis: str = Field(min_length=1)
    scope: _Scope = _Scope()


class _PatchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str | None = None
    verdict_note: str = ""
    notes: str | None = None
    scope: _Scope | None = None


class _CommentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1)


def _scope_to_dict(scope: _Scope) -> dict:
    return {"scenario_ids": scope.scenario_ids, "tactic": scope.tactic, "zone": scope.zone,
            "host": scope.host, "from": scope.from_, "to": scope.to}


def _validate_scope(scope: dict, st: _HuntsState) -> None:
    if scope.get("zone") and scope["zone"] not in {z.value for z in Zone}:
        raise HTTPException(422, f"unknown zone: {scope['zone']!r}")
    if scope.get("host") and st.topology.lookup(scope["host"]) is None:
        raise HTTPException(422, f"unknown host: {scope['host']!r}")
    parsed = {}
    for fld in ("from", "to"):
        if scope.get(fld):
            try:
                parsed[fld] = datetime.fromisoformat(scope[fld])
            except (ValueError, TypeError):
                raise HTTPException(422, f"invalid {fld}: {scope[fld]!r}")
    if "from" in parsed and "to" in parsed and parsed["from"] > parsed["to"]:
        raise HTTPException(422, "'from' must be <= 'to'")
    known = {s.scenario_id for s in st.scenarios}
    for sid in scope.get("scenario_ids") or []:
        if sid not in known:
            raise HTTPException(422, f"unknown scenario_id: {sid!r}")


def _hunt_view(h: Hunt) -> dict:
    return {"id": h.id, "owner": h.owner, "hypothesis": h.hypothesis,
            "scope": json.loads(h.scope_json) if h.scope_json else {}, "status": h.status,
            "verdict_note": h.verdict_note, "notes": h.notes,
            "verdict_evidence_at": h.verdict_evidence_at, "created_at": h.created_at,
            "updated_at": h.updated_at}


def _evidence_for(h: Hunt, st: _HuntsState) -> dict:
    return compute_hunt_evidence(json.loads(h.scope_json) if h.scope_json else {},
                                 windowed_at=st.windowed_at, scenarios=st.scenarios,
                                 topology=st.topology, computed_at=datetime.now(timezone.utc).isoformat())


@hunts_router.post("", status_code=status.HTTP_201_CREATED)
def create_hunt(body: _CreateBody, request: Request, user=Depends(require_role("analyst")),
                _csrf: None = Depends(verify_csrf)):
    st = _hstate(request)
    scope = _scope_to_dict(body.scope)
    _validate_scope(scope, st)
    hid = st.hunts.create(Hunt(owner=user.username, hypothesis=body.hypothesis,
                               scope_json=json.dumps(scope)))
    return _hunt_view(st.hunts.get(hid))


@hunts_router.get("")
def list_hunts(request: Request, status_f: str | None = Query(None, alias="status"),
               owner: str | None = Query(None), user=Depends(require_role("viewer"))):
    if owner == "me":
        owner = user.username
    return [_hunt_view(h) for h in _hstate(request).hunts.list(status=status_f, owner=owner)]


@hunts_router.get("/{hid}")
def get_hunt(hid: str, request: Request, user=Depends(require_role("viewer"))):
    st = _hstate(request)
    h = st.hunts.get(hid)
    if h is None:
        raise HTTPException(404, "hunt not found")
    view = _hunt_view(h)
    ev = _evidence_for(h, st)
    view["evidence"] = ev["evidence"]
    view["scope_resolved"] = ev["scope_resolved"]
    view["honesty_note"] = ev["honesty_note"]
    view["verdict_evidence"] = json.loads(h.verdict_evidence_json) if h.verdict_evidence_json else None
    view["events"] = [{"ts": e.ts, "actor": e.actor, "event": e.event, "detail": e.detail}
                      for e in st.hunts.list_events(hid)]
    return view


@hunts_router.patch("/{hid}")
def patch_hunt(hid: str, body: _PatchBody, request: Request, user=Depends(require_role("analyst")),
               _csrf: None = Depends(verify_csrf)):
    st = _hstate(request)
    h = st.hunts.get(hid)
    if h is None:
        raise HTTPException(404, "hunt not found")
    if body.scope is not None:
        scope = _scope_to_dict(body.scope)
        _validate_scope(scope, st)
        h.scope_json = json.dumps(scope)
    if body.notes is not None:
        h.notes = body.notes
    if body.scope is not None or body.notes is not None:
        st.hunts.update(h)
    if body.status is not None:
        if body.status not in _HUNT_STATUSES:
            raise HTTPException(422, f"invalid status: {body.status!r}")
        note = body.verdict_note.strip()
        ev_json, ev_at = "", ""
        if body.status in _TERMINAL:
            if not note:
                raise HTTPException(422, "a verdict note is required to confirm or refute")
            ev = _evidence_for(st.hunts.get(hid), st)
            ev_json = json.dumps(ev["evidence"]); ev_at = ev["computed_at"]
        st.hunts.set_status(hid, body.status, actor=user.username, note=note,
                            evidence_json=ev_json, evidence_at=ev_at)
    return _hunt_view(st.hunts.get(hid))


@hunts_router.post("/{hid}/comment", status_code=status.HTTP_201_CREATED)
def comment_hunt(hid: str, body: _CommentBody, request: Request,
                 user=Depends(require_role("analyst")), _csrf: None = Depends(verify_csrf)):
    st = _hstate(request)
    if st.hunts.get(hid) is None:
        raise HTTPException(404, "hunt not found")
    st.hunts.add_comment(hid, actor=user.username, text=body.text)
    return {"ok": True}


@hunts_router.delete("/{hid}")
def delete_hunt(hid: str, request: Request, user=Depends(require_role("analyst")),
                _csrf: None = Depends(verify_csrf)):
    st = _hstate(request)
    h = st.hunts.get(hid)
    if h is None:
        raise HTTPException(404, "hunt not found")
    if user.role != "admin" and h.owner != user.username:
        raise HTTPException(403, "only the owner or an admin may delete a hunt")
    st.hunts.delete(hid)
    return {"ok": True}


@hunts_router.get("/{hid}/report")
def hunt_report(hid: str, request: Request, format: str = Query("md"),
                user=Depends(require_role("viewer"))):
    st = _hstate(request)
    h = st.hunts.get(hid)
    if h is None:
        raise HTTPException(404, "hunt not found")
    ev = _evidence_for(h, st)
    payload = {"id": h.id, "owner": h.owner, "hypothesis": h.hypothesis,
               "scope": json.loads(h.scope_json) if h.scope_json else {}, "status": h.status,
               "verdict_note": h.verdict_note, "notes": h.notes, "evidence": ev["evidence"],
               "honesty_note": ev["honesty_note"], "created_at": h.created_at}
    if format == "json":
        return payload
    lines = [f"# Hunt report — {h.hypothesis}", "", f"- Owner: {h.owner}", f"- Status: {h.status}",
             f"- Created: {h.created_at}", "", "## Live evidence", ""]
    for e in ev["evidence"]:
        lines.append(f"- {e['scenario_id']} ({e['name']}) — proximity {e['proximity']} "
                     f"({e['matched_count']}/{e['total_steps']} steps)")
    if not ev["evidence"]:
        lines.append("- (no matching detections in scope)")
    lines += ["", f"_{ev['honesty_note']}_"]
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines))


def attach_hunts(app: FastAPI, state: AuthState, *, windowed_at, scenarios, topology) -> _HuntsState:
    store = HuntStore(state.conn)
    app.state.hunts = _HuntsState(store, windowed_at=windowed_at, scenarios=scenarios, topology=topology)
    app.include_router(hunts_router)
    return app.state.hunts
