"""TDD: shift-handover diff pure helpers (infra-free, deterministic, read-only)."""
from augur.api.handover import diff_detections


def _det(sid, prox, sev="HIGH", hosts=None, name=None):
    return {"scenario_id": sid, "name": name or sid, "severity": sev,
            "proximity": prox, "affected_hosts": hosts or ["H1"]}


def test_diff_detections_classifies_each_bucket():
    prior = [_det("A", 0.40), _det("B", 0.80), _det("C", 0.60), _det("GONE", 0.50)]
    current = [_det("A", 0.40), _det("B", 1.00), _det("C", 0.20), _det("NEW", 0.90)]
    out = diff_detections(prior, current, min_proximity=0.30)

    assert [d["scenario_id"] for d in out["new"]] == ["NEW"]
    assert out["new"][0]["proximity_prior"] is None
    assert out["new"][0]["proximity_current"] == 0.90

    assert [d["scenario_id"] for d in out["gone"]] == ["GONE"]
    assert out["gone"][0]["proximity_current"] is None
    assert out["gone"][0]["proximity_prior"] == 0.50

    esc = {d["scenario_id"]: d for d in out["escalated"]}
    assert esc["B"]["proximity_delta"] == 0.20
    assert esc["B"]["band_prior"] == "HIGH" and esc["B"]["band_current"] == "CONFIRMED"
    assert esc["B"]["band_changed"] is True

    dec = {d["scenario_id"]: d for d in out["decayed"]}
    assert dec["C"]["proximity_delta"] == -0.40

    assert out["unchanged_count"] == 1


def test_diff_detections_min_proximity_floor_applied_both_sides():
    prior = [_det("LOW", 0.10), _det("A", 0.50)]
    current = [_det("LOW", 0.20), _det("A", 0.50)]
    out = diff_detections(prior, current, min_proximity=0.30)
    all_ids = {d["scenario_id"] for k in ("new", "escalated", "decayed", "gone") for d in out[k]}
    assert "LOW" not in all_ids
    assert out["unchanged_count"] == 1


def test_diff_detections_band_only_escalation_counts_as_escalated():
    prior = [_det("X", 0.80)]
    current = [_det("X", 1.00)]
    out = diff_detections(prior, current, min_proximity=0.30)
    assert [d["scenario_id"] for d in out["escalated"]] == ["X"]
    assert out["escalated"][0]["band_changed"] is True


def test_diff_detections_ordering_biggest_mover_first():
    prior = [_det("S", 0.50, sev="LOW"), _det("B", 0.50, sev="HIGH")]
    current = [_det("S", 0.95, sev="LOW"), _det("B", 0.60, sev="HIGH")]
    out = diff_detections(prior, current, min_proximity=0.30)
    assert [d["scenario_id"] for d in out["escalated"]] == ["S", "B"]


def test_diff_detections_deterministic():
    prior = [_det("A", 0.40), _det("B", 0.80)]
    current = [_det("A", 0.90), _det("B", 0.80)]
    assert diff_detections(prior, current, min_proximity=0.30) == \
           diff_detections(prior, current, min_proximity=0.30)


from augur.api.handover import diff_hosts


def _hostrow(name, score, band, zone="DMZ", crit="HIGH"):
    return {"hostname": name, "zone": zone, "criticality": crit,
            "score": score, "band": band}


def test_diff_hosts_entered_left_escalated_deescalated():
    prior = [_hostrow("H1", 0.0, "CLEAR"), _hostrow("H2", 5.0, "HIGH"),
             _hostrow("H3", 2.0, "WATCH"), _hostrow("LEFT", 3.0, "WATCH")]
    current = [_hostrow("H1", 4.0, "HIGH"), _hostrow("H2", 9.0, "CRITICAL"),
               _hostrow("H3", 1.0, "LOW"), _hostrow("LEFT", 0.0, "CLEAR")]
    out = diff_hosts(prior, current)

    assert [h["hostname"] for h in out["entered"]] == ["H1"]
    assert [h["hostname"] for h in out["left"]] == ["LEFT"]
    assert out["entered"][0]["score_current"] == 4.0
    assert out["left"][0]["score_prior"] == 3.0

    esc = {h["hostname"]: h for h in out["escalated"]}
    assert esc["H2"]["score_delta"] == 4.0
    dec = {h["hostname"]: h for h in out["deescalated"]}
    assert dec["H3"]["score_delta"] == -1.0


def test_diff_hosts_ordering_biggest_move_first():
    prior = [_hostrow("A", 1.0, "LOW"), _hostrow("B", 1.0, "LOW")]
    current = [_hostrow("A", 9.0, "CRITICAL"), _hostrow("B", 2.0, "WATCH")]
    out = diff_hosts(prior, current)
    assert [h["hostname"] for h in out["escalated"]] == ["A", "B"]


def test_diff_hosts_deterministic():
    prior = [_hostrow("A", 1.0, "LOW")]
    current = [_hostrow("A", 5.0, "HIGH")]
    assert diff_hosts(prior, current) == diff_hosts(prior, current)


from augur.api.handover import build_handover


def test_build_handover_assembles_full_payload():
    prior_dets = [_det("A", 0.40), _det("B", 0.80)]
    current_dets = [_det("A", 0.90), _det("B", 0.80), _det("NEW", 0.95)]
    prior_hosts = [_hostrow("H1", 0.0, "CLEAR")]
    current_hosts = [_hostrow("H1", 4.0, "HIGH")]

    out = build_handover(
        prior_dets, current_dets, prior_hosts, current_hosts,
        from_iso="2026-01-01T09:00:00+00:00", to_iso="2026-01-01T18:00:00+00:00",
        min_proximity=0.30,
    )
    assert out["window"] == {"from": "2026-01-01T09:00:00+00:00",
                             "to": "2026-01-01T18:00:00+00:00"}
    assert out["meta"] == {"min_proximity": 0.30, "basis": "corpus-windowed", "deterministic": True}
    assert [d["scenario_id"] for d in out["detections"]["new"]] == ["NEW"]
    assert [d["scenario_id"] for d in out["detections"]["escalated"]] == ["A"]
    assert [h["hostname"] for h in out["host_risk"]["entered"]] == ["H1"]
    assert out["summary"]["counts"]["new"] == 1
    assert out["summary"]["counts"]["hosts_entered"] == 1
    assert "triage" not in out


def test_build_handover_host_escalated_deescalated_populate_and_count():
    # Hosts on the board in BOTH windows whose score moves -> escalated / deescalated buckets,
    # surfaced end-to-end through build_handover (not just diff_hosts in isolation).
    dets = [_det("A", 0.50)]
    prior_hosts = [_hostrow("UP", 2.0, "WATCH"), _hostrow("DOWN", 6.0, "HIGH")]
    current_hosts = [_hostrow("UP", 7.0, "HIGH"), _hostrow("DOWN", 2.0, "WATCH")]
    out = build_handover(dets, dets, prior_hosts, current_hosts,
                         from_iso="2026-01-01T09:00:00+00:00",
                         to_iso="2026-01-01T18:00:00+00:00", min_proximity=0.30)
    assert [h["hostname"] for h in out["host_risk"]["escalated"]] == ["UP"]
    assert [h["hostname"] for h in out["host_risk"]["deescalated"]] == ["DOWN"]
    assert out["summary"]["counts"]["hosts_escalated"] == 1
    assert out["summary"]["counts"]["hosts_deescalated"] == 1


def test_build_handover_identical_states_all_unchanged():
    dets = [_det("A", 0.50)]
    hosts = [_hostrow("H1", 2.0, "WATCH")]
    out = build_handover(dets, dets, hosts, hosts,
                         from_iso="2026-01-01T09:00:00+00:00",
                         to_iso="2026-01-01T09:00:00+00:00", min_proximity=0.30)
    assert out["detections"]["new"] == [] and out["detections"]["gone"] == []
    assert out["detections"]["escalated"] == [] and out["detections"]["decayed"] == []
    assert out["detections"]["unchanged_count"] == 1
    assert all(v == 0 for k, v in out["summary"]["counts"].items()
               if k not in ("unchanged",))
