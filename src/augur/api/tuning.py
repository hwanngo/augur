"""FP-tuning allowlist API — CRUD + propose-from-alert + live suppression ledger.

Mirrors `attach_hunts`: a sqlite store on the shared conn, viewer-read / analyst-write, CSRF on
mutations, routes registered before the SPA catch-all. The live ledger/hit-counts run the pure
`apply_allowlist` over the precomputed detection set (no engine re-run).
"""
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from augur.auth.deps import AuthState, require_role, verify_csrf
from augur.enums import Zone
from augur.graph.models import ProcessNode
from augur.tuning.store import AllowlistStore, AllowlistEntry, ACTIONS, DOWNGRADE_BANDS
from augur.tuning.apply import apply_allowlist

tuning_router = APIRouter(prefix="/api/tuning", tags=["tuning"])

BASELINE_HINT_NOTE = (
    "Advisory only — frequency in THIS corpus, not a verdict. Common ≠ benign and rare ≠ malicious; "
    "this just helps you judge whether the thing you are muting looks like routine baseline. You decide."
)


class _TuningState:
    def __init__(self, store, *, detections_provider, backend, technique_index, scenarios, topology,
                 baseline_provider=None):
        self.tuning = store
        self.detections_provider = detections_provider   # () -> list[public detection dict]
        self.backend = backend
        self.technique_index = technique_index            # {scenario_id: set[technique]}
        self.scenarios = scenarios
        self.topology = topology
        self.baseline_provider = baseline_provider        # (process_name) -> freq row | None


def _tstate(request: Request) -> _TuningState:
    return request.app.state.tuning


def _alert_store(request: Request):
    alerting = getattr(request.app.state, "alerting", None)
    return alerting.alerts if alerting is not None else None


def _now() -> datetime:
    return datetime.now(timezone.utc)


class _EntryBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str
    reason: str = Field(min_length=1)
    downgrade_to: str | None = None
    scenario_id: str | None = None
    technique: str | None = None
    host: str | None = None
    zone: str | None = None
    process_regex: str | None = None
    command_regex: str | None = None
    image_regex: str | None = None
    ts_from: str | None = None
    ts_to: str | None = None
    expires_at: str | None = None


def _all_techniques(st: _TuningState) -> set[str]:
    out: set[str] = set()
    for techs in st.technique_index.values():
        out |= techs
    return out


def _validate(body: _EntryBody, st: _TuningState) -> None:
    if body.action not in ACTIONS:
        raise HTTPException(422, f"unknown action: {body.action!r}")
    if body.action == "DOWNGRADE":
        if body.downgrade_to not in DOWNGRADE_BANDS:
            raise HTTPException(422, f"DOWNGRADE requires downgrade_to in {DOWNGRADE_BANDS}")
    elif body.downgrade_to:
        raise HTTPException(422, "downgrade_to is only valid for action=DOWNGRADE")

    entry = _body_to_entry(body, author="", source="manual")
    if not entry.predicates():
        raise HTTPException(422, "at least one predicate is required (a no-predicate entry would mute everything)")
    if body.scenario_id and body.scenario_id not in st.technique_index:
        raise HTTPException(422, f"unknown scenario_id: {body.scenario_id!r}")
    if body.technique and body.technique not in _all_techniques(st):
        raise HTTPException(422, f"unknown technique: {body.technique!r}")
    if body.zone and body.zone not in {z.value for z in Zone}:
        raise HTTPException(422, f"unknown zone: {body.zone!r}")
    for fld in ("process_regex", "command_regex", "image_regex"):
        pat = getattr(body, fld)
        if pat:
            try:
                re.compile(pat)
            except re.error as exc:
                raise HTTPException(422, f"invalid {fld}: {exc}")
    parsed = {}
    for fld in ("ts_from", "ts_to", "expires_at"):
        val = getattr(body, fld)
        if val:
            try:
                parsed[fld] = datetime.fromisoformat(val)
            except (ValueError, TypeError):
                raise HTTPException(422, f"invalid {fld}: {val!r}")
    if "ts_from" in parsed and "ts_to" in parsed and parsed["ts_from"] > parsed["ts_to"]:
        raise HTTPException(422, "ts_from must be <= ts_to")


def _body_to_entry(body: _EntryBody, *, author: str, source: str, source_alert_id: str | None = None) -> AllowlistEntry:
    return AllowlistEntry(
        action=body.action, reason=body.reason, author=author,
        downgrade_to=body.downgrade_to, scenario_id=body.scenario_id, technique=body.technique,
        host=body.host, zone=body.zone, process_regex=body.process_regex,
        command_regex=body.command_regex, image_regex=body.image_regex,
        ts_from=body.ts_from, ts_to=body.ts_to, expires_at=body.expires_at,
        source=source, source_alert_id=source_alert_id,
    )


def _entry_view(e: AllowlistEntry, *, hit_count: int | None = None) -> dict:
    view = {
        "id": e.id, "action": e.action, "downgrade_to": e.downgrade_to, "reason": e.reason,
        "author": e.author, "scenario_id": e.scenario_id, "technique": e.technique,
        "host": e.host, "zone": e.zone, "process_regex": e.process_regex,
        "command_regex": e.command_regex, "image_regex": e.image_regex,
        "ts_from": e.ts_from, "ts_to": e.ts_to, "enabled": e.enabled, "expires_at": e.expires_at,
        "source": e.source, "source_alert_id": e.source_alert_id,
        "created_at": e.created_at, "updated_at": e.updated_at,
    }
    if hit_count is not None:
        view["hit_count"] = hit_count
    return view


def _primary_process_name(det: dict, backend) -> str | None:
    """The process name of the detection's deepest resolvable matched step (most-advanced action).
    Resolved against the SAME backend the detections came from (so element ids always resolve, exactly
    as build_pivot_graph resolves seeds). None if no process node is reachable / no backend."""
    if backend is None:
        return None
    name = None
    for step in det.get("matched_steps", []):
        eid = step.get("element_id")
        if not eid:
            continue
        rid = eid.split("|EXH|")[0] if "|EXH|" in eid else eid
        node = backend.get_node(rid)
        if isinstance(node, ProcessNode) and node.name:
            name = node.name   # keep the deepest (last) one
    return name


def _baseline_hint(st: _TuningState, scenario_id: str) -> dict | None:
    """Advisory rarity hint for the process at the centre of this scenario's detection. None if it can't
    be substantiated (no provider / no detection / unresolved process / process absent from the index)."""
    if st.baseline_provider is None:
        return None
    det = next((d for d in st.detections_provider() if d["scenario_id"] == scenario_id), None)
    if det is None:
        return None
    pname = _primary_process_name(det, st.backend)
    if not pname:
        return None
    row = st.baseline_provider(pname)
    if row is None:
        return None
    return {"process": row["name"], "occurrences": row["occurrences"], "host_count": row["host_count"],
            "single_host": row["single_host"], "first_seen": row["first_seen"],
            "last_seen": row["last_seen"], "honesty_note": BASELINE_HINT_NOTE}


def _live_result(st: _TuningState):
    """Run apply_allowlist over the live detection set with the current active entries."""
    active = st.tuning.active_entries(now=_now())
    dets = list(st.detections_provider())
    return apply_allowlist(dets, active, backend=st.backend, technique_index=st.technique_index)


@tuning_router.get("")
def list_entries(request: Request, enabled: bool | None = Query(None), _=Depends(require_role("viewer"))):
    st = _tstate(request)
    hits = {pe["entry_id"]: pe["hit_count"] for pe in _live_result(st).ledger["per_entry"]}
    return [_entry_view(e, hit_count=hits.get(e.id, 0)) for e in st.tuning.list(enabled=enabled)]


@tuning_router.get("/ledger")
def ledger(request: Request, _=Depends(require_role("viewer"))):
    res = _live_result(_tstate(request))
    return {"ledger": res.ledger, "suppressed": res.suppressed, "downgraded": res.downgraded,
            "honesty_note": res.honesty_note}


@tuning_router.get("/{eid}")
def get_entry(eid: str, request: Request, _=Depends(require_role("viewer"))):
    st = _tstate(request)
    e = st.tuning.get(eid)
    if e is None:
        raise HTTPException(404, "allowlist entry not found")
    view = _entry_view(e)
    view["events"] = [{"ts": ev.ts, "actor": ev.actor, "event": ev.event, "detail": ev.detail}
                      for ev in st.tuning.list_events(eid)]
    return view


@tuning_router.post("", status_code=status.HTTP_201_CREATED)
def create_entry(body: _EntryBody, request: Request, user=Depends(require_role("analyst")),
                 _csrf: None = Depends(verify_csrf)):
    st = _tstate(request)
    _validate(body, st)
    eid = st.tuning.create(_body_to_entry(body, author=user.username, source="manual"))
    return _entry_view(st.tuning.get(eid))


@tuning_router.patch("/{eid}")
def patch_entry(eid: str, body: _EntryBody, request: Request, user=Depends(require_role("analyst")),
                _csrf: None = Depends(verify_csrf)):
    st = _tstate(request)
    existing = st.tuning.get(eid)
    if existing is None:
        raise HTTPException(404, "allowlist entry not found")
    _validate(body, st)
    updated = _body_to_entry(body, author=existing.author, source=existing.source,
                             source_alert_id=existing.source_alert_id)
    updated.id = eid
    st.tuning.update(updated, actor=user.username)
    return _entry_view(st.tuning.get(eid))


@tuning_router.post("/{eid}/enable")
def enable_entry(eid: str, request: Request, user=Depends(require_role("analyst")),
                 _csrf: None = Depends(verify_csrf)):
    return _set_enabled(eid, True, request, user)


@tuning_router.post("/{eid}/disable")
def disable_entry(eid: str, request: Request, user=Depends(require_role("analyst")),
                  _csrf: None = Depends(verify_csrf)):
    return _set_enabled(eid, False, request, user)


def _set_enabled(eid: str, enabled: bool, request: Request, user) -> dict:
    st = _tstate(request)
    if st.tuning.get(eid) is None:
        raise HTTPException(404, "allowlist entry not found")
    st.tuning.set_enabled(eid, enabled, actor=user.username)
    return _entry_view(st.tuning.get(eid))


@tuning_router.delete("/{eid}")
def delete_entry(eid: str, request: Request, user=Depends(require_role("analyst")),
                 _csrf: None = Depends(verify_csrf)):
    st = _tstate(request)
    e = st.tuning.get(eid)
    if e is None:
        raise HTTPException(404, "allowlist entry not found")
    if user.role != "admin" and e.author != user.username:
        raise HTTPException(403, "only the author or an admin may delete an allowlist entry")
    st.tuning.delete(eid, actor=user.username)
    return {"ok": True}


@tuning_router.post("/propose_from_alert/{alert_id}")
def propose_from_alert(alert_id: str, request: Request, user=Depends(require_role("analyst")),
                       _csrf: None = Depends(verify_csrf)):
    st = _tstate(request)
    store = _alert_store(request)
    if store is None:
        raise HTTPException(404, "alerting is not enabled")
    alert = store.get(alert_id)
    if alert is None:
        raise HTTPException(404, "alert not found")
    hosts = list(alert.affected_hosts)
    techs = sorted(st.technique_index.get(alert.scenario_id, set()))
    draft = {
        "action": "DOWNGRADE", "downgrade_to": "WATCH",
        "scenario_id": alert.scenario_id,
        "technique": techs[0] if techs else None,
        "host": hosts[0] if len(hosts) == 1 else None,
        "zone": None, "process_regex": None, "command_regex": None, "image_regex": None,
        "ts_from": None, "ts_to": None, "expires_at": None,
        "reason": f"FP triaged from alert {alert_id} by {user.username}",
        "source": "proposed", "source_alert_id": alert_id,
    }
    # baseline_hint = advisory rarity for this scenario's process ("runs on N hosts, M times in the
    # corpus"). Best-effort: null when it can't be substantiated. NEVER auto-fills the action or approves.
    return {"draft": draft, "baseline_hint": _baseline_hint(st, alert.scenario_id),
            "note": ("Pre-filled draft — NOT saved. Review and POST to /api/tuning to apply. "
                     "Proposes a conservative DOWNGRADE, not a hard suppress.")}


def attach_tuning(app: FastAPI, state: AuthState, *, detections_provider, backend, scenarios, topology,
                  baseline_provider=None) -> _TuningState:
    store = AllowlistStore(state.conn)
    technique_index = {s.scenario_id: {m.technique for m in s.scenario_metadata.mitre_mappings}
                       for s in scenarios}
    app.state.tuning = _TuningState(store, detections_provider=detections_provider, backend=backend,
                                    technique_index=technique_index, scenarios=scenarios, topology=topology,
                                    baseline_provider=baseline_provider)
    app.include_router(tuning_router)
    return app.state.tuning
