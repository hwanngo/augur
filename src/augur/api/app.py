import asyncio
import logging
import mimetypes
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

# Ensure the PWA manifest is served with a correct content type (not octet-stream).
mimetypes.add_type("application/manifest+json", ".webmanifest")
from augur.pipeline import default_topology, default_scenarios
from augur.api.observability import MetricsRegistry, setup_logging
from augur.api.detections import windowed_detections
from augur.tuning.apply import apply_allowlist
from augur.api.momentum import corpus_time_span, build_time_grid, momentum_series
from augur.api.host_risk import compute_host_risk
from augur.api.handover import build_handover
from augur.api.triage_handover import build_triage_handover
from augur.api.attack_path import build_attack_paths, HONESTY_NOTE as _ATTACK_PATH_NOTE
from augur.api.campaign import build_campaign_scorecard
from augur.api.timeline import build_case_timeline
from augur.api.pivot_graph import build_pivot_graph
from augur.pipeline import build_backend
from augur.topology.network import load_topology, Topology
from augur.scenarios.loader import load_scenarios
from augur.scenarios.schema import Scenario
from augur.enums import Zone
from augur.metrics.coverage import coverage_gap_matrix
from augur.api.navigator import build_navigator_layer
from augur.auth.router import attach_auth
from augur.auth.deps import require_role, verify_csrf
from augur.api.drill import run_drill, replay_detection
from augur.simulator.inject import is_synthesizable
from augur.api.ioc import match_iocs
from augur.api.ioc_extract import extract_iocs
from augur.api.rarity import compute_rarity, DIMENSIONS, MAX_COUNT_CAP, MAX_RESULTS
from augur.api.detection_health import compute_detection_health
from augur.api.incidents import cluster_incidents
from augur.api.incident_response import build_all_incident_responses
from augur.api.incident_report import build_incident_report, report_to_markdown
from augur.response.playbook import build_playbook
from augur.api.sigma import scenario_to_sigma, pack_to_yaml, HONESTY_NOTE as _SIGMA_NOTE
from augur.engine.scoring import Detection
from augur.connectors import get_sink
from augur.connectors.sinks import SinkDeliveryError
from augur.alerting.acfg import build_sink_factory
from pydantic import BaseModel, ConfigDict
import tempfile

# Absolute bounds used when only one of from/to is supplied (engine never sees "now").
_EPOCH_MIN = datetime(1970, 1, 1, tzinfo=timezone.utc)
_FAR_FUTURE = datetime(9999, 12, 31, tzinfo=timezone.utc)


def _rebuild_detection(stored: dict) -> Detection:
    """Rebuild a Detection from a stored public dict for Sink.emit.

    Mirrors alerting.notify._detection_from_alert. Drops keys that aren't Detection
    fields (e.g. the `stall` enrichment windowed_detections adds to partial dicts);
    the dataclass-default _-prefixed fields are simply re-derived by the sink's own
    _public() at emit time.
    """
    fields = set(Detection.__dataclass_fields__)
    return Detection(**{k: v for k, v in stored.items() if k in fields})


def _dispatch_jsonl_path() -> str:
    """Server-chosen jsonl output path; NEVER taken from the request body. [AUDIT #3]"""
    return tempfile.NamedTemporaryFile(
        prefix="augur-dispatch-", suffix=".jsonl", delete=False).name


def _parse_one(value: str | None, default: datetime) -> datetime:
    if value is None:
        return default
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Unparseable ISO timestamp: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_bounds(from_: str | None, to: str | None) -> tuple[datetime, datetime]:
    frm = _parse_one(from_, _EPOCH_MIN)
    t = _parse_one(to, _FAR_FUTURE)
    if frm > t:
        raise HTTPException(status_code=422, detail="'from' must be <= 'to'")
    return frm, t

# React SPA build output takes priority; fall back to the legacy vanilla web dir.
_FRONTEND_DIST = Path(__file__).resolve().parents[3] / "frontend" / "dist"
_WEB_LEGACY = Path(__file__).resolve().parent.parent / "web"


def _web_dir() -> Path | None:
    if _FRONTEND_DIST.exists():
        return _FRONTEND_DIST
    if _WEB_LEGACY.exists():
        return _WEB_LEGACY
    return None


@asynccontextmanager
async def _lifespan(app: FastAPI):
    from augur.alerting.monitor import monitor_enabled, monitor_interval, monitor_loop
    app.state.monitor_task = None
    stop = asyncio.Event()
    if monitor_enabled() and getattr(app.state, "alerting", None) is not None:
        app.state.monitor_task = asyncio.create_task(
            monitor_loop(app.state.alerting, interval=monitor_interval(), stop=stop))
    try:
        yield
    finally:
        stop.set()
        task = app.state.monitor_task
        if task is not None:
            try:
                await asyncio.wait_for(task, timeout=5)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                task.cancel()
            app.state.monitor_task = None


def create_app(log_paths: list[str] | None = None,
               topology: Topology | None = None,
               scenarios: list[Scenario] | None = None) -> FastAPI:
    log_paths = log_paths or [os.environ.get("AUGUR_LOGS", "sample_data/corpus/enterprise_day.jsonl")]
    if topology is None:
        env_topo = os.environ.get("AUGUR_TOPOLOGY")
        topology = load_topology(env_topo) if env_topo else default_topology()
    if scenarios is None:
        env_dir = os.environ.get("AUGUR_SCENARIOS_DIR")
        scenarios = load_scenarios(env_dir) if env_dir else default_scenarios()
        env_extra = os.environ.get("AUGUR_SCENARIOS_EXTRA_DIR")
        if env_extra:
            scenarios = scenarios + load_scenarios(env_extra)

    _real_data = any(s.scenario_id.startswith("SCEN-REAL-") for s in scenarios)

    # The loaded log feed is static, so the full ranked detection list never changes.
    # Compute it ONCE at startup and just filter per request — this keeps /api/detections
    # O(filter) instead of re-running the engine on every call (e.g. a dragged slider).
    # Reuse the windowed builder over the full span so the precompute and the windowed path are
    # byte-identical (including the F3 `stall` enrichment) — single source of truth. [AUDIT #3]
    all_detections = list(windowed_detections(
        log_paths, topology, scenarios, frm=_EPOCH_MIN, to=_FAR_FUTURE))

    # Per-window detections: the static feed makes a process-lifetime cache always valid.
    # Keyed on (frm_iso, to_iso) absolute ISO strings; topology/scenarios/log_paths via closure.
    @lru_cache(maxsize=32)   # 16 -> 32: momentum's <=12 bounds + detection windows w/o thrash
    def _windowed_cached(frm_iso: str, to_iso: str) -> tuple:
        dets = windowed_detections(
            log_paths, topology, scenarios,
            frm=datetime.fromisoformat(frm_iso), to=datetime.fromisoformat(to_iso),
        )
        return tuple(dets)

    @lru_cache(maxsize=32)
    def _timeline_cached(scenario_id: str, host: str | None, frm_iso: str | None, to_iso: str | None):
        det = next((d for d in all_detections if d["scenario_id"] == scenario_id), None)
        if det is None:
            return None
        frm = datetime.fromisoformat(frm_iso) if frm_iso else None
        to = datetime.fromisoformat(to_iso) if to_iso else None
        return build_case_timeline(det, log_paths, topology, host=host, frm=frm, to=to)

    @lru_cache(maxsize=32)
    def _campaign_cached(ids: tuple | None, tactic: str | None, os_family: str | None, min_proximity: float):
        return build_campaign_scorecard(scenarios, topology,
                                        scenario_ids=list(ids) if ids else None,
                                        tactic=tactic, os_family=os_family, min_proximity=min_proximity)

    # Pivot graph: the feed is static, so the knowledge graph is constant — build the backend ONCE
    # at startup (closure), then BFS per request. LRU on (scenario_id, hops). No engine re-run.
    _pivot_backend = build_backend(log_paths, topology)

    @lru_cache(maxsize=32)
    def _pivot_cached(scenario_id: str, hops: int):
        det = next((d for d in all_detections if d["scenario_id"] == scenario_id), None)
        if det is None:
            return None
        return build_pivot_graph(det, _pivot_backend, topology, hops=hops)

    # Momentum: event-time span computed ONCE at startup (never re-read per request) and closed over.
    _corpus_min_ts, _corpus_max_ts = corpus_time_span(log_paths)

    app = FastAPI(title="Augur", lifespan=_lifespan)

    _metrics = MetricsRegistry()

    @app.get("/api/health")
    def health():
        # Cheap liveness probe: the process is up and serving. real_data flags a real (non-synthetic)
        # feed so the console can show a "REAL DATASET" banner (default false ⇒ no banner).
        return {"status": "ok", "real_data": _real_data}

    @app.get("/metrics")
    def metrics_prometheus():
        # Prometheus scrape endpoint (unauthenticated like health/ready — restrict
        # at the network layer). HTTP request counts + latency, low-cardinality
        # (labelled by route template, not raw path).
        return Response(_metrics.render(), media_type="text/plain; version=0.0.4")

    @app.get("/api/ready")
    def ready(response: Response):
        # Readiness probe: verify the dependencies the app needs to serve traffic.
        checks = {"database": False, "graph_backend": False}
        try:
            app.state.auth.conn.execute("SELECT 1").fetchone()
            checks["database"] = True
        except Exception:
            pass
        try:
            _pivot_backend.get_node("__readiness_probe__")  # cheap reachability call
            checks["graph_backend"] = True
        except Exception:
            pass
        ok = all(checks.values())
        if not ok:
            response.status_code = 503
        return {"status": "ready" if ok else "not_ready", "checks": checks}

    @app.get("/api/detections")
    def detections(min_proximity: float = Query(0.30, ge=0.0, le=1.0),
                   from_: str | None = Query(None, alias="from"),
                   to: str | None = Query(None, alias="to"),
                   _=Depends(require_role("viewer"))):
        if from_ is None and to is None:
            dets = all_detections                      # fast path: unchanged precompute
        else:
            frm, t = _parse_bounds(from_, to)          # 422 on bad/inverted bounds
            dets = _windowed_cached(frm.isoformat(), t.isoformat())
        filtered = [d for d in dets if d["proximity"] >= min_proximity]
        # FP-tuning (array-shape, additive): when active allowlist entries exist, drop SUPPRESSED
        # detections and stamp a `band_override` on DOWNGRADED ones. Byte-identical bare list when
        # no entries are active (has_active short-circuits). The "tuned out" ledger lives at
        # GET /api/tuning/ledger — this endpoint never changes its top-level array shape.
        ts = getattr(app.state, "tuning", None)
        if ts is not None and ts.tuning.has_active(now=datetime.now(timezone.utc)):
            active = ts.tuning.active_entries(now=datetime.now(timezone.utc))
            return apply_allowlist(filtered, active, backend=_pivot_backend,
                                   technique_index=ts.technique_index).kept
        return filtered

    @app.get("/api/host_risk")
    def host_risk(min_proximity: float = Query(0.30, ge=0.0, le=1.0),
                  from_: str | None = Query(None, alias="from"),
                  to: str | None = Query(None, alias="to"),
                  _=Depends(require_role("viewer"))):
        # [AUDIT #3] replicate the /api/detections source-selection branch verbatim.
        if from_ is None and to is None:
            dets = all_detections                      # fast path: unchanged precompute
        else:
            frm, t = _parse_bounds(from_, to)          # 422 on bad/inverted bounds
            dets = _windowed_cached(frm.isoformat(), t.isoformat())
        filtered = [d for d in dets if d["proximity"] >= min_proximity]
        return {"hosts": compute_host_risk(filtered, topology)}

    @app.get("/api/momentum")
    def momentum(min_proximity: float = Query(0.30, ge=0.0, le=1.0),
                 steps: int = 6,
                 from_: str | None = Query(None, alias="from"),
                 to: str | None = Query(None, alias="to"),
                 _=Depends(require_role("viewer"))):
        frm, t = _parse_bounds(from_, to)                  # 422 on bad/inverted bounds
        steps = max(3, min(12, steps))                     # clamp 3..12
        # Empty feed -> no series (span is None).
        if _corpus_min_ts is None or _corpus_max_ts is None:
            return {"from": frm.isoformat(), "to": t.isoformat(), "bounds": [], "series": []}
        # [AUDIT #3] from/to clamp only the GRID SPAN; the window lower bound stays _EPOCH_MIN.
        span_lo = max(_corpus_min_ts, frm)
        span_hi = min(_corpus_max_ts, t)
        if span_lo > span_hi:                              # clamp wiped the span out
            return {"from": frm.isoformat(), "to": t.isoformat(), "bounds": [], "series": []}
        bounds = build_time_grid(span_lo, span_hi, steps=steps)
        # Scenario set = full-window result at the top bound with proximity >= min_proximity.
        top = _windowed_cached(_EPOCH_MIN.isoformat(), bounds[-1].isoformat())
        scenario_ids = [d["scenario_id"] for d in top if d["proximity"] >= min_proximity]
        # Cumulative windows: every lower bound is _EPOCH_MIN; N passes total (LRU-cached, shared w/ detections).
        windowed_at = lambda iso: _windowed_cached(_EPOCH_MIN.isoformat(), iso)
        series = momentum_series(windowed_at, bounds, scenario_ids, steps=steps)
        return {"from": frm.isoformat(), "to": t.isoformat(),
                "bounds": [b.isoformat() for b in bounds], "series": series}

    @app.get("/api/handover")
    def handover(min_proximity: float = Query(0.30, ge=0.0, le=1.0),
                 from_: str | None = Query(None, alias="from"),
                 to: str | None = Query(None, alias="to"),
                 _=Depends(require_role("viewer"))):
        # Default window (deterministic, no now()): 'to' = corpus max, 'from' = corpus midpoint.
        # Empty feed -> empty diff.
        if _corpus_min_ts is None or _corpus_max_ts is None:
            # Route the empty payload through build_handover with empty inputs so the shape is
            # structurally identical to the populated path (no hand-maintained drift risk).
            frm, t = _parse_bounds(from_, to)
            return build_handover([], [], [], [], from_iso=frm.isoformat(),
                                  to_iso=t.isoformat(), min_proximity=min_proximity)
        if from_ is None:
            from_ = (_corpus_min_ts + (_corpus_max_ts - _corpus_min_ts) / 2).isoformat()
        if to is None:
            to = _corpus_max_ts.isoformat()
        frm, t = _parse_bounds(from_, to)              # 422 on bad/inverted bounds
        # Cumulative engine windows from _EPOCH_MIN (prefix matching needs full pre-boundary history);
        # the two BOUNDARIES are the shift edges. Both passes are LRU-cached (shared w/ detections).
        prior_dets = list(_windowed_cached(_EPOCH_MIN.isoformat(), frm.isoformat()))
        current_dets = list(_windowed_cached(_EPOCH_MIN.isoformat(), t.isoformat()))
        prior_f = [d for d in prior_dets if d["proximity"] >= min_proximity]
        current_f = [d for d in current_dets if d["proximity"] >= min_proximity]
        prior_hosts = compute_host_risk(prior_f, topology)
        current_hosts = compute_host_risk(current_f, topology)
        return build_handover(prior_dets, current_dets, prior_hosts, current_hosts,
                              from_iso=frm.isoformat(), to_iso=t.isoformat(),
                              min_proximity=min_proximity)

    @app.get("/api/triage_handover")
    def triage_handover(from_: str | None = Query(None, alias="from"),
                        to: str | None = Query(None, alias="to"),
                        _=Depends(require_role("viewer"))):
        # Wall-clock triage diff over persisted alert lifecycle. Distinct clock from the corpus-time
        # board diff (/api/handover). Default window = the alert-store activity span (no now()).
        store = app.state.alerting.alerts
        if from_ is None or to is None:
            lo, hi = store.activity_span()
            from_ = from_ if from_ is not None else lo
            to = to if to is not None else hi
        if from_ is None or to is None:                # empty store -> structural empty payload
            return build_triage_handover([], {}, from_iso=None, to_iso=None)
        frm, t = _parse_bounds(from_, to)              # 422 on bad/inverted bounds
        alerts = store.list()
        events_by_alert = {a.id: store.list_events(a.id) for a in alerts}
        return build_triage_handover(alerts, events_by_alert,
                                     from_iso=frm.isoformat(), to_iso=t.isoformat())

    @app.get("/api/attack_paths")
    def attack_paths(min_proximity: float = Query(0.30, ge=0.0, le=1.0),
                     from_: str | None = Query(None, alias="from"),
                     to: str | None = Query(None, alias="to"),
                     entry_zone: str | None = Query(None),
                     target: str | None = Query(None),
                     _=Depends(require_role("viewer"))):
        if entry_zone is not None and entry_zone not in {z.value for z in Zone}:
            raise HTTPException(status_code=422, detail=f"unknown entry_zone: {entry_zone!r}")
        if target is not None and topology.lookup(target) is None:
            raise HTTPException(status_code=422, detail=f"unknown target host: {target!r}")
        if from_ is None and to is None:
            dets = all_detections                          # fast path
            frm, t = _EPOCH_MIN, _FAR_FUTURE
        else:
            frm, t = _parse_bounds(from_, to)              # 422 on bad/inverted bounds
            dets = _windowed_cached(frm.isoformat(), t.isoformat())
        paths = build_attack_paths(list(dets), topology, scenarios,
                                   min_proximity=min_proximity, entry_zone=entry_zone, target=target)
        return {"paths": paths, "honesty_note": _ATTACK_PATH_NOTE,
                "from": frm.isoformat(), "to": t.isoformat()}

    @app.get("/api/campaign")
    def campaign(tactic: str | None = Query(None),
                 scenario_ids: str | None = Query(None),
                 os_family: str | None = Query(None),
                 min_proximity: float = Query(1.0, ge=0.0, le=1.0),
                 _=Depends(require_role("viewer"))):
        ids = tuple(s.strip() for s in scenario_ids.split(",") if s.strip()) if scenario_ids else None
        try:
            return _campaign_cached(ids, tactic, os_family, round(min_proximity, 4))
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    @app.get("/api/timeline")
    def timeline(scenario_id: str,
                 host: str | None = Query(None),
                 from_: str | None = Query(None, alias="from"),
                 to: str | None = Query(None, alias="to"),
                 _=Depends(require_role("viewer"))):
        if not any(s.scenario_id == scenario_id for s in scenarios):
            raise HTTPException(status_code=404, detail=f"unknown scenario_id: {scenario_id!r}")
        frm, t = _parse_bounds(from_, to)
        frm_iso = frm.isoformat() if from_ is not None else None
        to_iso = t.isoformat() if to is not None else None
        try:
            result = _timeline_cached(scenario_id, host, frm_iso, to_iso)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        if result is None:
            raise HTTPException(status_code=404, detail=f"no detection for scenario_id: {scenario_id!r}")
        return result

    @app.get("/api/pivot_graph")
    def pivot_graph(detection: str,
                    hops: int = 2,
                    _=Depends(require_role("viewer"))):
        hops = max(1, min(3, hops))                 # clamp, never 422
        try:
            result = _pivot_cached(detection, hops)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        if result is None:
            raise HTTPException(status_code=404, detail=f"no detection for: {detection!r}")
        return result

    @lru_cache(maxsize=16)
    def _rarity_cached(dimension: str, max_count: int, limit: int) -> dict:
        return compute_rarity(dimension, log_paths, topology, max_count=max_count, limit=limit)

    @app.get("/api/rarity")
    def rarity(dimension: str = "process",
               max_count: int = 5,
               limit: int = 100,
               _=Depends(require_role("viewer"))):
        if dimension not in DIMENSIONS:
            raise HTTPException(status_code=422,
                                detail=f"unknown dimension: {dimension!r}; allowed: {', '.join(DIMENSIONS)}")
        max_count = max(1, min(MAX_COUNT_CAP, max_count))   # clamp, never 422
        limit = max(1, min(MAX_RESULTS, limit))             # clamp, never 422
        return _rarity_cached(dimension, max_count, limit)

    @lru_cache(maxsize=1)   # no params in v1 → singleton; invalidated on restart (static feed)
    def _detection_health_cached() -> dict:
        return compute_detection_health(log_paths, topology, scenarios)

    @app.get("/api/detection_health")
    def detection_health(_=Depends(require_role("viewer"))):
        try:
            return _detection_health_cached()
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    @lru_cache(maxsize=1)   # no params → singleton; static feed; invalidated on restart
    def _incidents_cached() -> dict:
        # Reuses the SAME full-corpus public detection list the dashboard/host_risk/ioc use.
        # Pure over the dicts — no new engine pass.
        return cluster_incidents(list(all_detections), scenarios, topology)

    @app.get("/api/incidents")
    def incidents(_=Depends(require_role("viewer"))):
        try:
            return _incidents_cached()
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    @lru_cache(maxsize=1)   # no params → singleton; static feed; invalidated on restart
    def _incident_response_cached() -> dict:
        incidents = _incidents_cached()["incidents"]      # reuse the SAME cached cluster output
        return build_all_incident_responses(incidents, scenarios, topology)

    @app.get("/api/incident_response")
    def incident_response(_=Depends(require_role("viewer"))):
        try:
            return _incident_response_cached()
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    @app.get("/api/incident_report/{incident_id}")
    def incident_report(incident_id: str, format: str = "json",
                        _=Depends(require_role("viewer"))):
        # Pure fold over the two SAME cached payloads /api/incidents and /api/incident_response
        # serve — no re-cluster, no re-fold, no engine. Registered before the SPA catch-all.
        try:
            incidents = _incidents_cached()["incidents"]
            responses = _incident_response_cached()["responses"]
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        inc = next((i for i in incidents if i["incident_id"] == incident_id), None)
        if inc is None:
            raise HTTPException(status_code=404, detail=f"unknown incident_id: {incident_id!r}")
        resp = next((r for r in responses if r["incident_id"] == incident_id), None)
        if resp is None:
            raise HTTPException(status_code=404, detail=f"unknown incident_id: {incident_id!r}")
        try:
            report = build_incident_report(inc, resp)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        md = report_to_markdown(report)
        if format == "markdown":
            return PlainTextResponse(
                md, media_type="text/markdown",
                headers={"Content-Disposition":
                         f"attachment; filename=augur-incident-{incident_id}.md"})
        return {**report, "markdown": md}

    class _IocItem(BaseModel):
        model_config = ConfigDict(extra="forbid")
        type: str
        value: str

    class _IocBody(BaseModel):
        model_config = ConfigDict(extra="forbid")
        iocs: list[_IocItem]

    @app.post("/api/ioc_match")
    def ioc_match(body: _IocBody,
                  _user=Depends(require_role("viewer")),
                  _csrf: None = Depends(verify_csrf)):
        try:
            return match_iocs([i.model_dump() for i in body.iocs],
                              log_paths, scenarios, topology, all_detections,
                              real_data=_real_data)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    class _IocExtractBody(BaseModel):
        model_config = ConfigDict(extra="forbid")
        text: str

    @app.post("/api/ioc_extract")
    def ioc_extract(body: _IocExtractBody,
                    _user=Depends(require_role("viewer")),
                    _csrf: None = Depends(verify_csrf)):
        try:
            return extract_iocs(body.text)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    @app.get("/api/scenarios")
    def list_scenarios(_=Depends(require_role("viewer"))):
        return [{"scenario_id": s.scenario_id, "name": s.name, "severity": s.severity.value,
                 "steps": s.step_count,
                 "os_family": s.os_family,
                 "applicable_zones": s.spatial_constraints.applicable_zones,
                 "synthesizable": is_synthesizable(s, topology),
                 "mitre": [m.model_dump() for m in s.scenario_metadata.mitre_mappings]}
                for s in scenarios]

    @app.get("/api/scenarios/{scenario_id}")
    def get_scenario(scenario_id: str, _=Depends(require_role("viewer"))):
        # Pure read of the closure-loaded scenarios: metadata + MITRE + full step
        # bodies. No engine, graph, scoring, persistence, now(), or randomness.
        scen = next((s for s in scenarios if s.scenario_id == scenario_id), None)
        if scen is None:
            raise HTTPException(status_code=404, detail=f"unknown scenario_id: {scenario_id!r}")
        return {
            "scenario_id": scen.scenario_id,
            "name": scen.name,
            "severity": scen.severity.value,
            "os_family": scen.os_family,
            "applicable_zones": scen.spatial_constraints.applicable_zones,
            "mitre": [m.model_dump() for m in scen.scenario_metadata.mitre_mappings],
            "step_count": scen.step_count,
            "steps": [
                {
                    "step_id": s.step_id,
                    "name": s.name,
                    "temporal_link": s.temporal_link.model_dump() if s.temporal_link else None,
                    "matching_criteria": s.matching_criteria,
                }
                for s in scen.attack_sequence_flow.steps
            ],
        }

    @app.get("/api/scenarios/{scenario_id}/sigma")
    def scenario_sigma(scenario_id: str, format: str = "json",
                       _=Depends(require_role("viewer"))):
        # Pure read-only Sigma export of one scenario's steps. No engine/scoring/persistence.
        scen = next((s for s in scenarios if s.scenario_id == scenario_id), None)
        if scen is None:
            raise HTTPException(status_code=404, detail=f"unknown scenario_id: {scenario_id!r}")
        rules = scenario_to_sigma(scen)
        yaml_text = pack_to_yaml([scen])
        if format == "yaml":
            return PlainTextResponse(yaml_text, media_type="text/yaml")
        return {"scenario_id": scen.scenario_id, "rules": rules,
                "yaml": yaml_text, "honesty_note": _SIGMA_NOTE}

    @app.get("/api/sigma_pack")
    def sigma_pack(format: str = "yaml", _=Depends(require_role("viewer"))):
        # Whole-library multi-doc Sigma export. Deterministic: scenario load order, then step order.
        yaml_text = pack_to_yaml(scenarios)
        rule_count = sum(s.step_count for s in scenarios)
        if format == "json":
            return {"rule_count": rule_count, "scenario_count": len(scenarios),
                    "yaml": yaml_text, "honesty_note": _SIGMA_NOTE}
        return PlainTextResponse(
            yaml_text, media_type="text/yaml",
            headers={"Content-Disposition": "attachment; filename=augur-sigma-pack.yml"})

    @app.get("/api/topology")
    def topology_endpoint(_=Depends(require_role("viewer"))):
        return {"zones": [z.value for z in topology.zones],
                "assets": [a.model_dump() for a in topology.assets]}

    @app.get("/api/coverage_gaps")
    def coverage_gaps(_=Depends(require_role("viewer"))):
        # Read-only: reuses the closure-loaded scenarios + topology; no engine run, no persistence.
        return coverage_gap_matrix(scenarios, topology)

    @app.get("/api/navigator_layer")
    def navigator_layer(type: str = "coverage", min_proximity: float = Query(0.30, ge=0.0, le=1.0),
                        from_: str | None = Query(None, alias="from"),
                        to: str | None = Query(None, alias="to"),
                        _=Depends(require_role("viewer"))):
        if type not in ("coverage", "detections"):
            raise HTTPException(status_code=422, detail=f"unknown type: {type!r}")
        if type == "coverage":
            return build_navigator_layer(scenarios, layer_type="coverage")
        # type == "detections": reuse the /api/detections source-selection branch verbatim.
        if from_ is None and to is None:
            dets = all_detections                      # fast path: unchanged precompute
        else:
            frm, t = _parse_bounds(from_, to)          # 422 on bad/inverted bounds
            dets = _windowed_cached(frm.isoformat(), t.isoformat())
        filtered = [d for d in dets if d["proximity"] >= min_proximity]
        return build_navigator_layer(scenarios, layer_type="detections", detections=filtered)

    class _DrillBody(BaseModel):
        model_config = ConfigDict(extra="forbid")
        scenario_id: str
        host: str

    @app.post("/api/drill")
    def drill(body: _DrillBody,
              _user=Depends(require_role("analyst")),
              _csrf: None = Depends(verify_csrf)):
        scen = next((s for s in scenarios if s.scenario_id == body.scenario_id), None)
        # Non-synthesizable real scenario → REPLAY against the loaded real telemetry (no engine re-run,
        # no synth). Reuse the precomputed dashboard detection list. host is ignored — the capture
        # decided where it fired. Unknown scenario (scen is None) falls through to run_drill, whose
        # validate_injection raises ValueError -> 422 (preserves the existing unknown-scenario test).
        if scen is not None and not is_synthesizable(scen, topology):
            return replay_detection(body.scenario_id, scen.name, all_detections)
        # Synthesizable (or unknown) → existing synth-inject path, BYTE-IDENTICAL run_drill result,
        # plus the additive mode/note the API surfaces for both modes (NORMAL clients ignore them).
        try:
            result = run_drill(body.scenario_id, body.host, scenarios, topology)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        return {**result, "mode": "inject",
                "note": ("Synth-injected onto the target host — a constructed proof on synthetic "
                         "data (not the loaded capture).")}

    @app.get("/api/playbook")
    def playbook(scenario_id: str, _=Depends(require_role("viewer"))):
        scen = next((s for s in scenarios if s.scenario_id == scenario_id), None)
        if scen is None:
            raise HTTPException(status_code=404, detail=f"unknown scenario_id: {scenario_id!r}")
        return build_playbook(scen)

    class _DispatchBody(BaseModel):
        model_config = ConfigDict(extra="forbid")
        scenario_id: str
        sink: str = "preview"

    @app.post("/api/dispatch")
    def dispatch(body: _DispatchBody,
                 _user=Depends(require_role("analyst")),
                 _csrf: None = Depends(verify_csrf)):
        stored = next((d for d in all_detections if d["scenario_id"] == body.scenario_id), None)
        if stored is None:
            raise HTTPException(status_code=404, detail=f"no detection for {body.scenario_id!r}")
        if body.sink == "preview":                       # [AUDIT #1] return stored dict verbatim
            return {"ok": True, "sink": "preview", "payload": stored}
        detection = _rebuild_detection(stored)           # stall-safe real Detection for emit
        if body.sink == "stdout":                        # [AUDIT #2] writes to process stdout
            get_sink("stdout").emit(detection)
            return {"ok": True, "sink": "stdout", "payload": stored}
        if body.sink == "jsonl":                          # [AUDIT #3] server path + close()
            sink = get_sink("jsonl", path=_dispatch_jsonl_path())
            try:
                sink.emit(detection)
            finally:
                sink.close()
            return {"ok": True, "sink": "jsonl", "payload": stored}
        # [AUDIT #4] real sink: resolve ONLY from persisted admin config (never request kwargs).
        cfg = app.state.alerting.cfg.get()
        factory = build_sink_factory(cfg.get("sinks", {}))
        sink = factory(body.sink)
        if sink is None:                                  # unknown name OR known-but-unconfigured → 422
            raise HTTPException(status_code=422, detail=f"sink not available: {body.sink!r}")
        try:
            sink.emit(detection)
        except SinkDeliveryError as exc:                  # remote sink failed → 502, not an unhandled 500
            raise HTTPException(status_code=502, detail=f"sink delivery failed: {exc}")
        finally:
            close = getattr(sink, "close", None)
            if callable(close):
                close()
        return {"ok": True, "sink": body.sink, "payload": stored}

    from augur.api.metrics_endpoint import platform_metrics

    @app.get("/api/metrics")
    def metrics_endpoint(_=Depends(require_role("admin"))):
        return platform_metrics(app.state.auth)

    state = attach_auth(app)  # mounts /api/auth + /api/users, sets app.state.auth

    # Security headers on every response (defense-in-depth behind React's escaping).
    # CSP allows inline styles (the SPA uses inline style attributes heavily) but no
    # inline scripts; HSTS only in prod (where TLS is expected).
    _csp = (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )
    _is_prod = state.config.env == "prod"

    # Configure structured/levelled logging outside tests (pytest owns log
    # capture; PYTEST_CURRENT_TEST also guards the prod-env unit tests from
    # clobbering global logging). Honors AUGUR_LOG_FORMAT=json + AUGUR_LOG_LEVEL.
    _access_log = state.config.env != "test" and "PYTEST_CURRENT_TEST" not in os.environ
    if _access_log:
        setup_logging()
    _access_logger = logging.getLogger("augur.access")

    @app.middleware("http")
    async def _record_metrics(request: Request, call_next):
        start = time.perf_counter()
        resp = await call_next(request)
        # Label by the matched route template (bounded cardinality); unmatched
        # paths collapse to a single bucket so 404 scans can't explode labels.
        route = request.scope.get("route")
        template = getattr(route, "path", None) or "unmatched"
        elapsed = time.perf_counter() - start
        _metrics.observe(request.method, template, resp.status_code, elapsed)
        if _access_log:
            _access_logger.info("request", extra={
                "method": request.method, "route": template,
                "status": resp.status_code, "duration_ms": round(elapsed * 1000, 1)})
        return resp

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy", _csp)
        if _is_prod:
            resp.headers.setdefault("Strict-Transport-Security",
                                    "max-age=63072000; includeSubDomains")
        return resp
    from augur.generative.router import attach_generative
    attach_generative(app, state)   # mounts /api/generate + /api/candidates over scenarios/
    from augur.alerting.router import attach_alerting
    attach_alerting(app, state, scan_source_path=log_paths[0])   # mounts /api/alerts; scans the configured feed
    from augur.hunts.router import attach_hunts
    attach_hunts(app, state, windowed_at=_windowed_cached, scenarios=scenarios, topology=topology)
    from augur.api.tuning import attach_tuning
    from augur.api.rarity import process_frequency_index

    @lru_cache(maxsize=1)   # static feed -> compute the process-frequency index once
    def _process_freq_index() -> dict:
        return process_frequency_index(log_paths)

    def _baseline_provider(process_name: str):
        return _process_freq_index().get(process_name.casefold())

    tuning_state = attach_tuning(app, state, detections_provider=lambda: all_detections,
                                 backend=_pivot_backend, scenarios=scenarios, topology=topology,
                                 baseline_provider=_baseline_provider)
    # Let the alerting scan path see the same allowlist (suppress before alerting/notify).
    if getattr(app.state, "alerting", None) is not None:
        app.state.alerting.tuning_store = tuning_state.tuning
        app.state.alerting.tuning_technique_index = tuning_state.technique_index

    web = _web_dir()
    if web is not None:
        spa_index = web / "index.html"

        # Mount /assets sub-directory so JS/CSS/etc. are served with correct MIME types.
        assets_dir = web / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        if spa_index.exists():
            # SPA fallback catch-all: any non-/api GET returns index.html so React Router
            # handles client-side deep-links (/users, /scenarios) on hard refresh.
            @app.get("/{full_path:path}", include_in_schema=False)
            async def spa_fallback(request: Request, full_path: str):
                # Serve real files that exist (favicon, etc.) — but only if they
                # resolve *inside* the dist root. Without this containment check a
                # path like %2e%2e/secret (decoded to ../secret) would escape the
                # web root and leak arbitrary files (DB, .env, source).
                web_root = web.resolve()
                candidate = (web / full_path).resolve()
                if (candidate == web_root or web_root in candidate.parents) and candidate.is_file():
                    return FileResponse(str(candidate))
                # Fall back to SPA shell
                return FileResponse(str(spa_index))
        else:
            # Legacy vanilla web: use StaticFiles with html=True
            app.mount("/", StaticFiles(directory=str(web), html=True), name="web")

    return app
