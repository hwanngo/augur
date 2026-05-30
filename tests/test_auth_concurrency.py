"""Concurrency regression: the shared sqlite connection must not be used across threads.

Reproduces the `sqlite3.InterfaceError: bad parameter or other API misuse` that occurred when
FastAPI's threadpool workers shared one connection. FAILS on the old shared-connection code,
passes with the per-thread connection proxy. Infra-free (file sqlite, NetworkX default).
"""
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from augur.auth.store import connect
from augur.alerting.store import AlertStore, Alert
from augur.auth.hashing import hash_password
from augur.api.app import create_app


def _alert(**kw):
    base = dict(dedup_key="SCEN-1|h", scenario_id="SCEN-1", scenario_name="Cred Theft",
                severity="CRITICAL", affected_hosts=["h"], proximity=0.6, band="WATCH",
                created_at="2026-06-01T08:00:00+00:00", updated_at="2026-06-01T08:00:00+00:00")
    base.update(kw)
    return Alert(**base)


def test_store_concurrent_read_write_no_interface_error(tmp_path):
    """16 threads x 25 iterations of read+write through ONE store, started behind a barrier,
    must not raise sqlite3 errors. Trips the shared-connection bug; green with per-thread conns."""
    store = AlertStore(connect(str(tmp_path / "a.db")))
    store.create(_alert(dedup_key="d1"))
    store.create(_alert(dedup_key="d2", scenario_id="SCEN-2"))

    N, M = 16, 25
    barrier = threading.Barrier(N)
    errors: list[Exception] = []

    def worker(tid: int):
        barrier.wait()
        try:
            for i in range(M):
                store.list()                                  # read
                store.create(_alert(dedup_key=f"t{tid}-{i}")) # write + commit
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    with ThreadPoolExecutor(max_workers=N) as ex:
        list(ex.map(worker, range(N)))
    assert not errors, f"sqlite errors under concurrency: {errors[:3]}"


def test_api_concurrent_requests_all_200(tmp_path, monkeypatch):
    """30 concurrent authenticated GET /api/detections must all be 200 (no 500s). This is the
    literal 5/30 reproduction from the bug report.

    `/api/detections` requires the `viewer` role (so the test user can access it) and, like every
    authenticated route, runs `get_current_user` -> `SessionStore.touch` (a write on the shared
    connection) -- which is the exact traceback path from the bug report.
    """
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "a.db"))
    app = create_app(log_paths=["sample_data/corpus/enterprise_day.jsonl"])
    app.state.auth.users.create_user("viewer1", hash_password("password1234"), "viewer")
    client = TestClient(app)
    r = client.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"})
    assert r.status_code == 200, r.text

    N = 30
    barrier = threading.Barrier(N)
    codes: list[int] = []

    def hit(_):
        barrier.wait()
        codes.append(client.get("/api/detections").status_code)

    with ThreadPoolExecutor(max_workers=N) as ex:
        list(ex.map(hit, range(N)))
    assert all(c == 200 for c in codes), f"non-200s under concurrency: {sorted(set(codes))}"


def test_connect_returns_per_thread_proxy(tmp_path):
    """Same-thread proxy executes; two threads get DISTINCT underlying connections."""
    proxy = connect(str(tmp_path / "p.db"))
    assert proxy.execute("SELECT 1").fetchone()[0] == 1

    ids: dict[int, int] = {}
    lock = threading.Lock()

    def grab():
        underlying = proxy._conn()
        with lock:
            ids[threading.get_ident()] = id(underlying)

    t1 = threading.Thread(target=grab)
    t2 = threading.Thread(target=grab)
    t1.start(); t2.start()
    t1.join(); t2.join()
    distinct = set(ids.values())
    assert len(distinct) == 2, f"expected 2 distinct per-thread connections, got {ids}"
