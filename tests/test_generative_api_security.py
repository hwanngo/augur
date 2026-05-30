"""Security regression tests for the generative approve endpoint.

CRITICAL-1: path-traversal / arbitrary file write via unsanitised category
CRITICAL-2: cross-run id collision → silent scenario clobber on approve
"""
import secrets

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from augur.auth.hashing import hash_password
from augur.auth.ratelimit import RateLimiter
from augur.auth.router import attach_auth
from augur.generative.candidates import Candidate
from augur.generative.router import attach_generative


# ---------------------------------------------------------------------------
# Shared fixture (mirrors test_generative_api.py exactly)
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", str(tmp_path / "g.db"))
    monkeypatch.setenv("AUGUR_AI_GENERATOR", "fake")
    app = FastAPI()
    state = attach_auth(app)
    state.users.create_user("admin1", hash_password("password1234"), "admin")
    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir()
    gs = attach_generative(app, state, scenarios_dir=scenarios_dir)
    tc = TestClient(app)
    return tc, scenarios_dir, gs


def _auth(c, user):
    csrf = c.post(
        "/api/auth/login", data={"username": user, "password": "password1234"}
    ).json()["csrf_token"]
    return {"X-CSRF-Token": csrf}


def _gen(c, h, **body):
    body.setdefault("seed", "SCEN-WIN-001")
    body.setdefault("category", "credential_access")
    body.setdefault("n", 3)
    return c.post("/api/generate", json=body, headers=h)


# ---------------------------------------------------------------------------
# CRITICAL-1a: category validator rejects traversal at the API boundary
# ---------------------------------------------------------------------------

def test_generate_rejects_traversal_category(client):
    """POST /api/generate with a path-traversal category must return 422.
    No candidate should be created."""
    c, _, gs = client
    h = _auth(c, "admin1")

    bad_categories = [
        "../../tmp/x",
        "../escape",
        "/absolute/path",
        "has/slash",
        "has space",
        "UPPERCASE",
        "has.dot",
    ]
    for cat in bad_categories:
        r = c.post(
            "/api/generate",
            json={"seed": "SCEN-WIN-001", "category": cat, "n": 1},
            headers=h,
        )
        assert r.status_code == 422, f"expected 422 for category={cat!r}, got {r.status_code}: {r.text}"
        # No candidate must have been created
        pending = c.get("/api/candidates", params={"status": "pending"}).json()
        assert pending == [], f"candidate created despite invalid category={cat!r}"


# ---------------------------------------------------------------------------
# CRITICAL-1b: belt-and-suspenders in approve blocks out-of-tree destination
# ---------------------------------------------------------------------------

def test_approve_rejects_out_of_tree_dest(client, tmp_path):
    """A candidate inserted directly (bypassing the API validator) with an
    escaping category must be rejected with 400 on approve, and must NOT
    write any file outside scenarios_dir."""
    c, scenarios_dir, gs = client
    h = _auth(c, "admin1")

    # Craft a minimal but valid YAML for a 1-step scenario so schema re-validation passes.
    import yaml as _yaml
    valid_yaml = _yaml.dump({
        "scenario_metadata": {
            "scenario_id": "SCEN-GEN-EVIL1",
            "name": "Evil traversal",
            "description": "crafted",
            "severity": "HIGH",
            "mitre_mappings": [{"tactic": "TA0006", "technique": "T1003"}],
        },
        "spatial_constraints": {
            "applicable_zones": ["User_Endpoint"],
        },
        "attack_sequence_flow": {
            "steps": [
                {
                    "step_id": 1,
                    "name": "evil_step",
                    "matching_criteria": {"Node_Type": "Process", "process_name": "evil.exe"},
                    "temporal_link": None,
                }
            ],
        },
        "actionable_hunting_outputs": {
            "validation_queries": [{"engine": "splunk", "query": "index=* evil"}],
        },
    })

    # Insert directly into the store — bypasses the _GenerateBody validator.
    escape_category = "../escape"
    cand = Candidate(
        scenario_id="SCEN-GEN-EVIL1",
        category=escape_category,
        yaml=valid_yaml,
        seed_id="",
        mutation_axes="",
        plausibility=0.9,
        gauntlet_report="{}",
        created_by="test",
    )
    cid = gs.store.create(cand)

    r = c.post(f"/api/candidates/{cid}/approve", headers=h)
    assert r.status_code == 400, f"expected 400 for out-of-tree approve, got {r.status_code}: {r.text}"

    # Confirm nothing was written outside scenarios_dir
    escaped_parent = tmp_path / "escape"
    assert not escaped_parent.exists(), "approve wrote files outside scenarios_dir!"


# ---------------------------------------------------------------------------
# CRITICAL-2: cross-run id collision must not silently clobber the first file
# ---------------------------------------------------------------------------

def test_two_runs_same_id_no_clobber(client):
    """Two pending candidates that share the same scenario_id + category should
    not silently overwrite each other.  Approving the first must succeed (200).
    Approving the second must fail with 409, and the first file must be intact."""
    c, scenarios_dir, gs = client
    h = _auth(c, "admin1")

    import yaml as _yaml

    def make_yaml(scenario_id: str, content_marker: str) -> str:
        return _yaml.dump({
            "scenario_metadata": {
                "scenario_id": scenario_id,
                "name": f"Scenario {content_marker}",
                "description": content_marker,
                "severity": "MEDIUM",
                "mitre_mappings": [{"tactic": "TA0002", "technique": "T1059"}],
            },
            "spatial_constraints": {
                "applicable_zones": ["User_Endpoint"],
            },
            "attack_sequence_flow": {
                "steps": [
                    {
                        "step_id": 1,
                        "name": f"step_{content_marker}",
                        "matching_criteria": {
                            "Node_Type": "Process",
                            "process_name": f"{content_marker}.exe",
                        },
                        "temporal_link": None,
                    }
                ],
            },
            "actionable_hunting_outputs": {
                "validation_queries": [{"engine": "splunk", "query": f"index=* {content_marker}"}],
            },
        })

    shared_id = "SCEN-GEN-COLL1"
    shared_category = "generated"

    yaml_first = make_yaml(shared_id, "FIRST")
    yaml_second = make_yaml(shared_id, "SECOND")

    # Insert two pending candidates directly — same scenario_id + category.
    cid1 = gs.store.create(Candidate(
        scenario_id=shared_id, category=shared_category,
        yaml=yaml_first, seed_id="", mutation_axes="",
        plausibility=0.8, gauntlet_report="{}", created_by="test",
    ))
    cid2 = gs.store.create(Candidate(
        scenario_id=shared_id, category=shared_category,
        yaml=yaml_second, seed_id="", mutation_axes="",
        plausibility=0.8, gauntlet_report="{}", created_by="test",
    ))

    # Approve first — must succeed.
    r1 = c.post(f"/api/candidates/{cid1}/approve", headers=h)
    assert r1.status_code == 200, f"first approve failed: {r1.text}"
    dest_path = scenarios_dir / shared_category / f"{shared_id}.yaml"
    assert dest_path.is_file(), "first approve did not write the file"
    first_content = dest_path.read_text()
    assert "FIRST" in first_content, "first file does not contain expected content"

    # Approve second — must fail with 409 (not clobber).
    r2 = c.post(f"/api/candidates/{cid2}/approve", headers=h)
    assert r2.status_code == 409, f"expected 409 on collision, got {r2.status_code}: {r2.text}"

    # First file must still exist and be unmodified.
    assert dest_path.is_file(), "first scenario file was deleted"
    assert dest_path.read_text() == first_content, "first scenario file was clobbered!"
