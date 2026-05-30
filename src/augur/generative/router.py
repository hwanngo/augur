import re
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator

from augur.auth.deps import AuthState, get_state, require_role, verify_csrf
from augur.auth.ratelimit import RateLimiter
from augur.generative import get_generator
from augur.generative.base import GenerationRequest
from augur.generative.candidates import CandidateStore
from augur.generative.config import load_ai_config
from augur.generative.engine import generate_candidates
from augur.scenarios.loader import load_scenarios
from augur.scenarios.schema import Scenario

_CATEGORY_RE = re.compile(r"^[a-z0-9_]+$")

generative_router = APIRouter(prefix="/api", tags=["generative"])
_REPO_ROOT = Path(__file__).resolve().parents[3]


class _GenerativeState:
    def __init__(self, store: CandidateStore, scenarios_dir: Path, rl: RateLimiter) -> None:
        self.store = store
        self.scenarios_dir = scenarios_dir
        self.rl = rl


class _GenerateBody(BaseModel):
    seed: str | None = None
    category: str | None = None
    technique: str | None = None
    n: int = 5
    axes: list[str] = Field(default_factory=list)

    @field_validator("category")
    @classmethod
    def _validate_category(cls, v: str | None) -> str | None:
        if v is not None and not _CATEGORY_RE.match(v):
            raise ValueError(
                "category must match ^[a-z0-9_]+$ (no slashes, dots, spaces, or uppercase)"
            )
        return v


class _RejectBody(BaseModel):
    reason: str = ""


def _ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _gs(request: Request) -> _GenerativeState:
    return request.app.state.generative


def _candidate_view(c) -> dict:
    return {"id": c.id, "scenario_id": c.scenario_id, "category": c.category,
            "status": c.status, "plausibility": c.plausibility, "seed_id": c.seed_id,
            "mutation_axes": c.mutation_axes, "created_by": c.created_by,
            "created_at": c.created_at, "reviewed_by": c.reviewed_by,
            "reviewed_at": c.reviewed_at, "yaml": c.yaml,
            "gauntlet_report": c.gauntlet_report}


@generative_router.post("/generate")
def generate(body: _GenerateBody, request: Request,
             user=Depends(require_role("admin")),
             _csrf: None = Depends(verify_csrf),
             state: AuthState = Depends(get_state)):
    gs = _gs(request)
    cfg = load_ai_config()
    if gs.rl.is_locked(user.username):
        state.events.log("scenario_generate_ratelimited", username=user.username, ip=_ip(request))
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "generation rate limit; try later")
    gs.rl.record_failure(user.username)          # reuse the limiter as a per-admin call tally
    n = max(1, min(body.n, cfg.max_n))
    req = GenerationRequest(seed_id=body.seed, category=body.category,
                            technique=body.technique, n=n, axes=body.axes)
    existing = load_scenarios(str(gs.scenarios_dir))
    results = generate_candidates(req, get_generator(), existing,
                                  store=gs.store, created_by=user.username)
    passed = [r for r in results if r.passed]
    state.events.log("scenario_generate", username=user.username, ip=_ip(request),
                     detail=f"n={n} passed={len(passed)}")
    return {"requested": n, "passed": len(passed),
            "candidates": [{"scenario_id": r.scenario_id, "passed": r.passed,
                            "reject_stage": r.reject_stage, "reason": r.reason,
                            "plausibility": r.plausibility, "notes": r.notes}
                           for r in results]}


@generative_router.get("/candidates")
def list_candidates(request: Request,
                    status_filter: str | None = Query(None, alias="status"),
                    user=Depends(require_role("analyst"))):
    return [_candidate_view(c) for c in _gs(request).store.list(status=status_filter)]


@generative_router.post("/candidates/{cid}/approve")
def approve(cid: str, request: Request,
            user=Depends(require_role("admin")),
            _csrf: None = Depends(verify_csrf),
            state: AuthState = Depends(get_state)):
    gs = _gs(request)
    c = gs.store.get(cid)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "candidate not found")
    if c.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"candidate is {c.status}")
    try:
        Scenario(**yaml.safe_load(c.yaml))       # re-validate before entering the live library
    except Exception as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"candidate no longer valid: {exc}")
    # CRITICAL-1: resolve destination and confirm it stays inside scenarios_dir (belt-and-suspenders
    # path-traversal guard, covers candidates inserted via CLI that bypass _GenerateBody validation).
    base = gs.scenarios_dir.resolve()
    dest = (base / c.category / f"{c.scenario_id}.yaml").resolve()
    if not dest.is_relative_to(base):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid candidate category/id")
    # CRITICAL-2: fail-closed on cross-run id collision — never silently clobber an approved file.
    if dest.exists():
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{c.scenario_id} already exists on disk; regenerate this candidate",
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(c.yaml)
    gs.store.set_status(cid, "approved", reviewed_by=user.username)
    state.events.log("candidate_approve", username=user.username, ip=_ip(request),
                     detail=f"{c.scenario_id} -> {dest}")
    return {"status": "approved", "scenario_id": c.scenario_id, "path": str(dest)}


@generative_router.post("/candidates/{cid}/reject")
def reject(cid: str, body: _RejectBody, request: Request,
           user=Depends(require_role("admin")),
           _csrf: None = Depends(verify_csrf),
           state: AuthState = Depends(get_state)):
    gs = _gs(request)
    c = gs.store.get(cid)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "candidate not found")
    gs.store.set_status(cid, "rejected", reviewed_by=user.username)
    state.events.log("candidate_reject", username=user.username, ip=_ip(request),
                     detail=f"{c.scenario_id}: {body.reason}")
    return {"status": "rejected", "scenario_id": c.scenario_id}


def attach_generative(app: FastAPI, state: AuthState, *, scenarios_dir=None,
                      rate_limiter: RateLimiter | None = None) -> _GenerativeState:
    cfg = load_ai_config()
    store = CandidateStore(state.conn)           # shares the auth sqlite connection
    sdir = Path(scenarios_dir) if scenarios_dir else (_REPO_ROOT / "scenarios")
    rl = rate_limiter or RateLimiter(max_failures=cfg.max_calls,
                                     window_seconds=cfg.window_seconds,
                                     lockout_seconds=cfg.window_seconds)
    app.state.generative = _GenerativeState(store, sdir, rl)
    app.include_router(generative_router)
    return app.state.generative
