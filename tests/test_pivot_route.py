"""TDD: GET /api/pivot_graph route (viewer, deterministic, LRU-cached, hop-clamped, 404 on unknown)."""
import pytest
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password

_LOGS = ["sample_data/corpus/enterprise_day.jsonl"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    app = create_app(log_paths=_LOGS)
    app.state.auth.users.create_user("viewer1", hash_password("password1234"), "viewer")
    return TestClient(app)


def _login(c):
    assert c.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"}).status_code == 200


def _get(c, params=None):
    return c.get("/api/pivot_graph", params=params or {})


def test_pivot_viewer_200_shape(client):
    _login(client)
    r = _get(client, {"detection": "SCEN-WIN-001"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) >= {"seed", "nodes", "edges", "summary"}
    assert set(body["summary"]) >= {"node_count", "edge_count", "nodes_total", "edges_total",
                                    "nodes_truncated", "edges_truncated", "hops", "honesty_note"}
    assert body["summary"]["hops"] == 2
    assert "NOT network reachability" in body["summary"]["honesty_note"]
    assert len(body["nodes"]) >= 1
    assert any(n["seed"] for n in body["nodes"])


def test_pivot_unauth_401_or_403(client):
    assert _get(client, {"detection": "SCEN-WIN-001"}).status_code in (401, 403)


def test_pivot_unknown_detection_404(client):
    _login(client)
    assert _get(client, {"detection": "SCEN-NOPE-999"}).status_code == 404


def test_pivot_hops_clamped_not_422(client):
    _login(client)
    hi = _get(client, {"detection": "SCEN-WIN-001", "hops": 9})
    assert hi.status_code == 200 and hi.json()["summary"]["hops"] == 3
    lo = _get(client, {"detection": "SCEN-WIN-001", "hops": 0})
    assert lo.status_code == 200 and lo.json()["summary"]["hops"] == 1


def test_pivot_deterministic(client):
    _login(client)
    p = {"detection": "SCEN-WIN-001"}
    assert _get(client, p).json() == _get(client, p).json()


def test_pivot_valueerror_becomes_422(tmp_path, monkeypatch):
    """Follow-up 1: a ValueError from build_pivot_graph must surface as 422, not 500.

    Patches build_pivot_graph *before* create_app so the LRU closure captures the stub.
    The detection exists (SCEN-WIN-001 is in the corpus), but the patched function raises
    ValueError — verifying the route wraps it in HTTPException(422), not a 500.
    """
    import augur.api.pivot_graph as _pg_mod
    import augur.api.app as _app_mod
    from augur.auth.hashing import hash_password

    def _raise(*a, **kw):
        raise ValueError("no resolvable seed node for detection 'SCEN-WIN-001'")

    # app.py uses `from augur.api.pivot_graph import build_pivot_graph`, so the name is
    # bound in augur.api.app's namespace — patch there for create_app to pick it up.
    monkeypatch.setattr(_app_mod, "build_pivot_graph", _raise)
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "b.db"))

    app2 = _app_mod.create_app(log_paths=_LOGS)
    app2.state.auth.users.create_user("v2", hash_password("pw1234"), "viewer")
    from fastapi.testclient import TestClient
    c2 = TestClient(app2)
    assert c2.post("/api/auth/login", data={"username": "v2", "password": "pw1234"}).status_code == 200
    r = c2.get("/api/pivot_graph", params={"detection": "SCEN-WIN-001"})
    assert r.status_code == 422, r.text
    assert "no resolvable seed" in r.json()["detail"]
