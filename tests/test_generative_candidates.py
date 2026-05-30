from augur.auth.store import connect
from augur.generative.candidates import CandidateStore, Candidate


def test_candidate_lifecycle(tmp_path):
    cs = CandidateStore(connect(str(tmp_path / "c.db")))
    cid = cs.create(Candidate(scenario_id="SCEN-GEN-0001", category="credential_access",
                              yaml="yaml: here", seed_id="SCEN-WIN-001", mutation_axes="lolbin",
                              plausibility=0.9, gauntlet_report="{}", created_by="admin"))
    assert cs.get(cid).status == "pending"
    assert [c.scenario_id for c in cs.list(status="pending")] == ["SCEN-GEN-0001"]
    cs.set_status(cid, "approved", reviewed_by="admin")
    assert cs.get(cid).status == "approved"
    assert cs.list(status="pending") == []
