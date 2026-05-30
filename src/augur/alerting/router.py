import json
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from augur.auth.deps import AuthState, get_state, require_role, verify_csrf
from augur.alerting.acfg import AlertConfigStore, build_sink_factory
from augur.alerting.config import AlertConfig
from augur.alerting.notify import notify_assignment
from augur.alerting.scan import run_scan
from augur.alerting.store import AlertStore, _WORKFLOW_STATUSES
from augur.connectors import JsonlSource

_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_TERMINAL_STATUSES = {"resolved", "closed"}

alerting_router = APIRouter(prefix="/api/alerts", tags=["alerting"])


class _AlertingState:
    def __init__(self, store: AlertStore, config_store: AlertConfigStore, scan_source_path: str) -> None:
        self.alerts = store
        self.cfg = config_store
        self.scan_source_path = scan_source_path


def _astate(request: Request) -> _AlertingState:
    return request.app.state.alerting


def _ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _parse_window_seconds() -> float | None:
    """Read AUGUR_SCAN_WINDOW_SECONDS from env; return None if unset or <= 0."""
    raw = os.environ.get("AUGUR_SCAN_WINDOW_SECONDS", "0")
    try:
        value = float(raw)
    except (ValueError, TypeError):
        return None
    return value if value > 0 else None


def scan_state(astate, *, now, source=None) -> dict:
    """Run one scan cycle from the alerting state. Shared by POST /scan and the 3d monitor."""
    raw = astate.cfg.get()
    cfg = AlertConfig(min_proximity=raw["min_proximity"], auto_resolve_cycles=raw["auto_resolve_cycles"])
    src = source if source is not None else JsonlSource(astate.scan_source_path)
    window_seconds = _parse_window_seconds()
    return run_scan(astate.alerts, src, cfg, rules=raw.get("rules", []),
                    sink_factory=build_sink_factory(raw.get("sinks", {})), now=now,
                    window_seconds=window_seconds,
                    tuning_store=getattr(astate, "tuning_store", None),
                    technique_index=getattr(astate, "tuning_technique_index", None))


def _alert_view(a) -> dict:
    return {"id": a.id, "scenario_id": a.scenario_id, "scenario_name": a.scenario_name,
            "severity": a.severity, "affected_hosts": a.affected_hosts, "proximity": a.proximity,
            "band": a.band, "state": a.state, "first_seen": a.first_seen, "last_seen": a.last_seen,
            "count": a.count, "notified_band": a.notified_band, "created_at": a.created_at,
            "assignee": a.assignee, "status": a.status, "resolution_note": a.resolution_note,
            "assigned_at": a.assigned_at, "resolved_at": a.resolved_at,
            "detection": json.loads(a.detection_json) if a.detection_json else {}}


class AssignBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assignee: str = ""


class StatusBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    note: str = ""


class CommentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1)


class _ConfigBody(BaseModel):
    min_proximity: float = Field(ge=0.0, le=1.0)
    auto_resolve_cycles: int = Field(ge=0, default=0)
    rules: list = []
    sinks: dict = {}

    @field_validator("rules")
    @classmethod
    def _validate_rules(cls, rules: list) -> list:
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(f"rule[{i}] must be a dict")
            min_sev = rule.get("min_severity")
            if min_sev is not None and min_sev not in _VALID_SEVERITIES:
                raise ValueError(
                    f"rule[{i}].min_severity {min_sev!r} must be one of {sorted(_VALID_SEVERITIES)} or null"
                )
            min_prox = rule.get("min_proximity")
            if min_prox is not None and not (0.0 <= min_prox <= 1.0):
                raise ValueError(
                    f"rule[{i}].min_proximity {min_prox!r} must be in [0.0, 1.0] or null"
                )
            sinks = rule.get("sinks")
            if sinks is not None and not isinstance(sinks, list):
                raise ValueError(f"rule[{i}].sinks must be a list")
        return rules

    @field_validator("sinks")
    @classmethod
    def _validate_sinks(cls, sinks: dict) -> dict:
        from augur.connectors.sinks import validate_sink_url
        if not isinstance(sinks, dict):
            raise ValueError("sinks must be a mapping of name -> spec")
        for name, spec in sinks.items():
            if isinstance(spec, dict) and "url" in spec and spec["url"]:
                # SSRF guard: reject loopback / link-local / cloud-metadata targets.
                validate_sink_url(spec["url"])
        return sinks


def _parse_iso_bound(value: str | None, *, field: str) -> str | None:
    """Validate an ISO-8601 bound (422 on garbage); return it unchanged for the store filter."""
    if value is None:
        return None
    try:
        datetime.fromisoformat(value)
    except (ValueError, TypeError):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid {field}: {value!r}")
    return value


@alerting_router.get("")
def list_alerts(request: Request, state_f: str | None = Query(None, alias="state"),
                severity: str | None = Query(None), status_f: str | None = Query(None, alias="status"),
                assignee: str | None = Query(None), seen_from: str | None = Query(None),
                seen_to: str | None = Query(None), dedup_key: str | None = Query(None),
                user=Depends(require_role("analyst"))):
    if assignee == "me":
        assignee = user.username
    seen_from = _parse_iso_bound(seen_from, field="seen_from")
    seen_to = _parse_iso_bound(seen_to, field="seen_to")
    dedup_key = dedup_key.strip() if dedup_key and dedup_key.strip() else None
    rows = _astate(request).alerts.list(state=state_f, severity=severity, status=status_f,
                                        assignee=assignee, seen_from=seen_from, seen_to=seen_to,
                                        dedup_key=dedup_key)
    return [_alert_view(a) for a in rows]


@alerting_router.get("/summary")
def summary(request: Request, user=Depends(require_role("analyst"))):
    return _astate(request).alerts.summary()


@alerting_router.get("/config")
def get_config(request: Request, user=Depends(require_role("admin"))):
    return _astate(request).cfg.get()


@alerting_router.put("/config")
def put_config(body: _ConfigBody, request: Request, user=Depends(require_role("admin")),
               _csrf: None = Depends(verify_csrf), auth: AuthState = Depends(get_state)):
    _astate(request).cfg.put(body.model_dump())
    auth.events.log("alert_config_update", username=user.username, ip=_ip(request),
                    detail=f"min_proximity={body.min_proximity}")
    return {"status": "ok"}


@alerting_router.post("/scan")
def scan(request: Request, user=Depends(require_role("admin")),
         _csrf: None = Depends(verify_csrf), auth: AuthState = Depends(get_state)):
    st = _astate(request)
    counts = scan_state(st, now=datetime.now(timezone.utc))
    auth.events.log("alert_scan", username=user.username, ip=_ip(request),
                    detail=f"created={counts['created']} notified={counts['notified']}")
    return counts


@alerting_router.get("/{aid}")
def get_alert(aid: str, request: Request, user=Depends(require_role("analyst"))):
    st = _astate(request)
    a = st.alerts.get(aid)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    view = _alert_view(a)
    view["events"] = [{"ts": e.ts, "actor": e.actor, "event": e.event, "detail": e.detail}
                      for e in st.alerts.list_events(aid)]
    return view


@alerting_router.post("/{aid}/ack")
def ack(aid: str, request: Request, user=Depends(require_role("analyst")),
        _csrf: None = Depends(verify_csrf)):
    st = _astate(request)
    a = st.alerts.get(aid)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    st.alerts.set_state(aid, "acknowledged", actor=user.username)
    return {"status": "acknowledged", "id": aid}


@alerting_router.post("/{aid}/assign")
def assign(aid: str, body: AssignBody, request: Request, user=Depends(require_role("analyst")),
           _csrf: None = Depends(verify_csrf), auth: AuthState = Depends(get_state)):
    st = _astate(request)
    a = st.alerts.get(aid)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    assignee = body.assignee.strip()
    if assignee:
        target = auth.users.get_by_username(assignee)
        if target is None or target.disabled:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "unknown or disabled user")
    st.alerts.assign(aid, assignee, actor=user.username)
    # Best-effort notify-on-assign through the configured sinks/rules (no-op when unconfigured).
    updated = st.alerts.get(aid)
    raw = st.cfg.get()
    notify_assignment(updated, raw.get("rules", []), build_sink_factory(raw.get("sinks", {})))
    auth.events.log("alert_assigned", username=user.username, ip=_ip(request),
                    detail=f"{aid}->{assignee}")
    return _alert_view(updated)


@alerting_router.post("/{aid}/status")
def set_status(aid: str, body: StatusBody, request: Request, user=Depends(require_role("analyst")),
               _csrf: None = Depends(verify_csrf), auth: AuthState = Depends(get_state)):
    st = _astate(request)
    a = st.alerts.get(aid)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    if body.status not in _WORKFLOW_STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"invalid status: {body.status!r}")
    note = body.note.strip()
    if body.status in _TERMINAL_STATUSES and not note:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            "a resolution note is required to resolve or close")
    st.alerts.set_status(aid, body.status, actor=user.username, note=note)
    auth.events.log("alert_status", username=user.username, ip=_ip(request),
                    detail=f"{aid}->{body.status}")
    return _alert_view(st.alerts.get(aid))


@alerting_router.post("/{aid}/comment", status_code=status.HTTP_201_CREATED)
def comment(aid: str, body: CommentBody, request: Request, user=Depends(require_role("analyst")),
            _csrf: None = Depends(verify_csrf)):
    st = _astate(request)
    a = st.alerts.get(aid)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    st.alerts.add_comment(aid, actor=user.username, text=body.text)
    return {"ok": True}


def attach_alerting(app: FastAPI, state: AuthState, *, scan_source_path: str | None = None) -> _AlertingState:
    store = AlertStore(state.conn)
    config_store = AlertConfigStore(state.conn)
    src = scan_source_path or os.environ.get("AUGUR_LOGS", "sample_data/corpus/enterprise_day.jsonl")
    app.state.alerting = _AlertingState(store, config_store, src)
    app.include_router(alerting_router)
    return app.state.alerting
