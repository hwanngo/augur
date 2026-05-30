"""
Observability helper: platform_metrics(state) -> dict

Returns a DB-counts snapshot covering users, sessions, auth_events,
alerts, candidates, and loaded scenarios.

Guards all alerting/generative table queries with try/except
sqlite3.OperationalError so this function works even when those
subsystems are not attached to the app.
"""
import sqlite3


def platform_metrics(state) -> dict:
    """Build a platform health snapshot from the auth sqlite connection.

    Args:
        state: AuthState instance (has .conn, .users, .sessions)

    Returns:
        dict with keys: users, sessions_active, auth_events, alerts,
        candidates, scenarios.
    """
    conn = state.conn

    # ── users ───────────────────────────────────────────────────────────────
    total_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    role_rows = conn.execute(
        "SELECT role, COUNT(*) c FROM users GROUP BY role"
    ).fetchall()
    by_role = {r["role"]: r["c"] for r in role_rows}
    disabled_count = conn.execute(
        "SELECT COUNT(*) c FROM users WHERE disabled=1"
    ).fetchone()["c"]

    # ── sessions ────────────────────────────────────────────────────────────
    sessions_active = conn.execute("SELECT COUNT(*) c FROM sessions").fetchone()["c"]

    # ── auth_events ─────────────────────────────────────────────────────────
    auth_events_count = conn.execute(
        "SELECT COUNT(*) c FROM auth_events"
    ).fetchone()["c"]

    # ── alerts (may not exist if alerting subsystem not attached) ────────────
    alerts_by_state: dict = {}
    try:
        rows = conn.execute(
            "SELECT state, COUNT(*) c FROM alerts GROUP BY state"
        ).fetchall()
        alerts_by_state = {r["state"]: r["c"] for r in rows}
    except sqlite3.OperationalError:
        pass

    # ── candidates (may not exist if generative subsystem not attached) ──────
    candidates_by_status: dict = {}
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*) c FROM candidates GROUP BY status"
        ).fetchall()
        candidates_by_status = {r["status"]: r["c"] for r in rows}
    except sqlite3.OperationalError:
        pass

    # ── scenarios ───────────────────────────────────────────────────────────
    scenario_count = 0
    try:
        from augur.scenarios.loader import load_scenarios
        scenario_count = len(load_scenarios("scenarios"))
    except Exception:
        pass

    return {
        "users": {
            "total": total_users,
            "by_role": by_role,
            "disabled": disabled_count,
        },
        "sessions_active": sessions_active,
        "auth_events": auth_events_count,
        "alerts": alerts_by_state,
        "candidates": candidates_by_status,
        "scenarios": scenario_count,
    }
