#!/usr/bin/env python3
"""End-to-end smoke test of the SOC triage workflow against a *running* Augur server.

Unlike the pytest suite (which is infra-free and runs the app in-process), this drives
the real HTTP API of a live server: login → scan → assign → status → resolve → comment
→ summary → detection time-filter, including the negative/validation cases.

Usage:
    # 1. start a server with a known admin (fresh DB recommended):
    AUGUR_DB=/tmp/e2e.db AUGUR_ADMIN_USER=admin AUGUR_ADMIN_PASSWORD=dev-password-123 \\
        uv run python -m augur.demo --logs sample_data/corpus/enterprise_day.jsonl --port 8000
    # 2. in another shell:
    python3 scripts/e2e_triage_smoke.py                 # defaults to http://127.0.0.1:8000
    python3 scripts/e2e_triage_smoke.py http://host:port

Config via env: AUGUR_E2E_BASE, AUGUR_ADMIN_USER, AUGUR_ADMIN_PASSWORD.
Stdlib only (urllib) — no third-party dependencies. Exit code 0 = all checks passed.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

BASE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("AUGUR_E2E_BASE", "http://127.0.0.1:8000")).rstrip("/")
USER = os.environ.get("AUGUR_ADMIN_USER", "admin")
PW = os.environ.get("AUGUR_ADMIN_PASSWORD", "dev-password-123")

_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
_csrf = None
_passed = _failed = 0


def check(name, cond, detail=""):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  ✓ {name}")
    else:
        _failed += 1
        print(f"  ✗ {name}  {detail}")


def req(method, path, *, form=None, body=None):
    """Issue a request; return (status, parsed_json_or_text). Never raises on HTTP error."""
    headers = {}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if _csrf and method != "GET":
        headers["X-CSRF-Token"] = _csrf
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        resp = _opener.open(r)
        raw, status = resp.read().decode(), resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read().decode(), e.code
    except urllib.error.URLError as e:
        print(f"\nCannot reach {BASE} — is the server running? ({e})")
        sys.exit(2)
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw


def main():
    global _csrf
    print(f"== SOC triage E2E against {BASE} ==")

    st, body = req("POST", "/api/auth/login", form={"username": USER, "password": PW})
    _csrf = body.get("csrf_token") if isinstance(body, dict) else None
    check("login 200 + csrf", st == 200 and bool(_csrf), f"status={st}")
    if not _csrf:
        print("Login failed — check AUGUR_ADMIN_USER/PASSWORD."); sys.exit(1)

    st, body = req("POST", "/api/alerts/scan", body={})
    check("scan 200", st == 200, f"status={st} body={body}")

    st, alerts = req("GET", "/api/alerts")
    ok = st == 200 and isinstance(alerts, list) and len(alerts) > 0
    check("list alerts 200 + non-empty", ok, f"status={st}")
    if not ok:
        print("No alerts produced by scan — cannot exercise workflow."); sys.exit(1)
    aid = alerts[0]["id"]
    check("new view fields present", all(k in alerts[0] for k in
          ("assignee", "status", "resolution_note", "assigned_at", "resolved_at")))

    st, body = req("POST", f"/api/alerts/{aid}/assign", body={"assignee": USER})
    check("assign 200 + assignee set", st == 200 and body.get("assignee") == USER, f"status={st} body={body}")
    st, _ = req("POST", f"/api/alerts/{aid}/assign", body={"assignee": "ghost_user"})
    check("assign unknown user -> 422", st == 422, f"status={st}")

    st, body = req("POST", f"/api/alerts/{aid}/status", body={"status": "in_progress"})
    check("status in_progress 200", st == 200 and body.get("status") == "in_progress", f"status={st}")
    st, _ = req("POST", f"/api/alerts/{aid}/status", body={"status": "resolved"})
    check("resolve without note -> 422", st == 422, f"status={st}")
    st, body = req("POST", f"/api/alerts/{aid}/status", body={"status": "resolved", "note": "handled in e2e"})
    check("resolve with note 200 + resolved_at + note",
          st == 200 and body.get("status") == "resolved" and bool(body.get("resolved_at"))
          and body.get("resolution_note") == "handled in e2e", f"status={st} body={body}")

    st, _ = req("POST", f"/api/alerts/{aid}/comment", body={"text": "e2e comment"})
    check("comment 201", st == 201, f"status={st}")
    st, _ = req("POST", f"/api/alerts/{aid}/comment", body={"text": ""})
    check("empty comment -> 422", st == 422, f"status={st}")

    st, detail = req("GET", f"/api/alerts/{aid}")
    events = {e.get("event") for e in detail.get("events", [])} if isinstance(detail, dict) else set()
    check("detail has assigned+status+comment events", {"assigned", "status", "comment"} <= events, f"events={events}")

    st, summ = req("GET", "/api/alerts/summary")
    check("summary resolved + by_status",
          st == 200 and summ.get("resolved_count", 0) >= 1 and summ.get("by_status", {}).get("resolved", 0) >= 1,
          f"summary={summ}")

    st, resolved = req("GET", "/api/alerts?status=resolved")
    check("?status=resolved filters", st == 200 and all(a["status"] == "resolved" for a in resolved))
    st, mine = req("GET", "/api/alerts?assignee=me")
    check("?assignee=me filters to caller", st == 200 and all(a["assignee"] == USER for a in mine))

    st, all_det = req("GET", "/api/detections?min_proximity=0.3")
    n_all = len(all_det) if isinstance(all_det, list) else -1
    check("detections no-bounds 200", st == 200 and n_all > 0, f"n={n_all}")
    st, past = req("GET", "/api/detections?min_proximity=0.3&from=2025-01-01T00:00:00%2B00:00&to=2025-02-01T00:00:00%2B00:00")
    check("window in 2025 -> empty", st == 200 and past == [])
    st, win = req("GET", "/api/detections?min_proximity=0.3&from=2026-01-01T00:00:00%2B00:00&to=2026-02-01T00:00:00%2B00:00")
    check("window covering corpus -> matches no-bounds", st == 200 and len(win) == n_all, f"n={len(win)} vs {n_all}")
    st, _ = req("GET", "/api/detections?from=2026-02-01T00:00:00%2B00:00&to=2026-01-01T00:00:00%2B00:00")
    check("inverted window -> 422", st == 422, f"status={st}")

    print(f"\n== {_passed} passed, {_failed} failed ==")
    sys.exit(1 if _failed else 0)


if __name__ == "__main__":
    main()
