import pytest
import yaml
from fastapi.testclient import TestClient

from augur.api.app import create_app
from augur.auth.hashing import hash_password


@pytest.fixture
def client():
    app = create_app(log_paths=["sample_data/acceptance/demo_multi_os.jsonl"])
    app.state.auth.users.create_user("viewer1", hash_password("password1234"), "viewer")
    return TestClient(app)


def _auth(c):
    c.post("/api/auth/login", data={"username": "viewer1", "password": "password1234"})


def test_scenario_sigma_json_viewer_ok(client):
    _auth(client)
    r = client.get("/api/scenarios/SCEN-WIN-001/sigma")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"scenario_id", "rules", "yaml", "honesty_note"}
    assert body["scenario_id"] == "SCEN-WIN-001"
    assert len(body["rules"]) == 3
    assert body["honesty_note"]
    # yaml field is the multi-doc download blob
    docs = list(yaml.safe_load_all(body["yaml"]))
    assert len(docs) == 3


def test_scenario_sigma_yaml_format(client):
    _auth(client)
    r = client.get("/api/scenarios/SCEN-WIN-001/sigma?format=yaml")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/yaml")
    assert r.text.startswith("# Augur Sigma export")
    docs = list(yaml.safe_load_all(r.text))
    assert len(docs) == 3


def test_scenario_sigma_unknown_404(client):
    _auth(client)
    r = client.get("/api/scenarios/SCEN-NOPE-999/sigma")
    assert r.status_code == 404, r.text


def test_scenario_sigma_requires_auth(client):
    r = client.get("/api/scenarios/SCEN-WIN-001/sigma")
    assert r.status_code == 401, r.text


def test_scenario_sigma_route_not_shadowed_by_spa(client):
    _auth(client)
    r = client.get("/api/scenarios/SCEN-WIN-001/sigma")
    assert "text/html" not in r.headers.get("content-type", "")


def test_sigma_pack_yaml(client):
    _auth(client)
    r = client.get("/api/sigma_pack")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/yaml")
    assert "attachment" in r.headers.get("content-disposition", "")
    docs = list(yaml.safe_load_all(r.text))
    assert len(docs) >= 40  # >= one rule per step across the library
    # Honesty survives to the integration boundary: steps with no Sigma-expressible
    # field ship as NON-FIRING `unsupported` rules, never stripped or made match-all.
    unsupported = [d for d in docs if d.get("status") == "unsupported"]
    assert unsupported, "expected at least one non-firing unsupported rule in the pack"
    for d in unsupported:
        assert d["detection"]["condition"] == "selection and not selection"
    # and NO rule is an always-true match-everything selection
    assert not any(
        d["detection"].get("selection") == {} and d["detection"].get("condition") == "selection"
        for d in docs
    )


def test_sigma_pack_json(client):
    _auth(client)
    r = client.get("/api/sigma_pack?format=json")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"rule_count", "scenario_count", "yaml", "honesty_note"}
    assert body["scenario_count"] == 40
    assert body["rule_count"] == len(list(yaml.safe_load_all(body["yaml"])))


def test_sigma_pack_deterministic(client):
    _auth(client)
    a = client.get("/api/sigma_pack").text
    b = client.get("/api/sigma_pack").text
    assert a == b
