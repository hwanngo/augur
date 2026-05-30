import json
import os
from datetime import datetime, timedelta, timezone

from augur.scenarios.loader import load_scenarios
from augur.pipeline import default_topology
from augur.simulator.inject import render_injection
from augur.simulator.config import Injection, SimConfig
from augur.simulator.baseline import generate_baseline
from augur.simulator.profiles import MachineProfile
from augur.simulator.run import generate_feed

# A representative host per os_family that exists in the standard topology and satisfies the
# common applicable_zones (User_Endpoint / Internal_Server). render_injection re-targets the
# synth trace onto this host and emits native format.
_HOST = {"windows": "HR_User_PC", "linux": "CORP-JENKINS01", "macos": "DESIGN-MBP-07"}
_BASE = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)

_ACC_BASE = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
# A windows host NOT in SCEN-WIN-001's applicable_zones (User_Endpoint/Internal_Server) -> spatial fail.
_OUT_OF_ZONE_HOST = "Domain_Controller"   # Active_Directory zone


def regen_tp_fixtures(scenarios_dir: str, out_dir: str) -> list[str]:
    """Render every scenario's positive trace into a native-OS <id>_tp.jsonl under out_dir/<tactic>/."""
    scns = load_scenarios(scenarios_dir)
    topo = default_topology()
    # map scenario_id -> its source category folder (loader doesn't return the path, so re-walk)
    cat_by_id = {}
    for root, _dirs, files in os.walk(scenarios_dir):
        for f in files:
            if f.endswith(".yaml"):
                import yaml
                data = yaml.safe_load(open(os.path.join(root, f)))
                cat_by_id[data["scenario_metadata"]["scenario_id"]] = os.path.basename(root)
    written = []
    for s in scns:
        host = _HOST[s.os_family]
        inj = Injection(scenario_id=s.scenario_id, host=host, start_offset_seconds=0)
        events = render_injection(inj, scns, topo, _BASE, os_family=s.os_family)
        cat = cat_by_id[s.scenario_id]
        dest_dir = os.path.join(out_dir, cat)
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, f"{s.scenario_id}_tp.jsonl")
        with open(dest, "w") as fh:
            for e in events:
                fh.write(json.dumps({**e, "_scenario_id": s.scenario_id}) + "\n")
        written.append(dest)
    return written


def _render_anchor(scns, topo, anchor_id, host, os_family):
    inj = Injection(scenario_id=anchor_id, host=host, start_offset_seconds=0)
    return render_injection(inj, scns, topo, _ACC_BASE, os_family=os_family)


def regen_acceptance(scenarios_dir: str, out_dir: str) -> None:
    scns = load_scenarios(scenarios_dir)
    topo = default_topology()
    by_id = {s.scenario_id: s for s in scns}
    win, lnx = "SCEN-WIN-001", "SCEN-LNX-001"
    os.makedirs(out_dir, exist_ok=True)

    def _write(name, events):
        with open(os.path.join(out_dir, name), "w") as fh:
            for e in events:
                fh.write(json.dumps(e) + "\n")

    tp = _render_anchor(scns, topo, win, "HR_User_PC", "windows")
    _write("full_detection.jsonl", tp)

    # partial: keep only the events belonging to the first ceil(n/2) steps of the anchor.
    n_steps = by_id[win].step_count
    keep = (n_steps + 1) // 2
    # The render preserves per-step ordering; events for step k carry process_guid groups in order.
    # Simplest robust truncation: keep events up to (but not including) the timestamp of the last step.
    times = sorted({e["timestamp"] for e in tp})
    cutoff = times[min(keep, len(times)) - 1]
    _write("partial_detection.jsonl", [e for e in tp if e["timestamp"] <= cutoff])

    # temporal_violation: push the LAST event's timestamp far past its window so its step is suppressed.
    last_ts = max(e["timestamp"] for e in tp)
    violated = []
    for e in tp:
        if e["timestamp"] == last_ts:
            shifted = (datetime.fromisoformat(e["timestamp"]) + timedelta(days=2)).isoformat()
            violated.append({**e, "timestamp": shifted})
        else:
            violated.append(e)
    _write("no_detection_temporal_gap.jsonl", violated)

    # spatial_violation: same chain, host rewritten to an out-of-zone host (bypasses injection validation).
    _write("no_detection_wrong_zone.jsonl", [{**e, "host": _OUT_OF_ZONE_HOST} for e in tp])

    # benign: a small benign multi-OS slice (fires nothing).
    profiles = [MachineProfile("HR_User_PC", "windows", ["alice"]),
                MachineProfile("CORP-JENKINS01", "linux", ["jenkins"]),
                MachineProfile("DESIGN-MBP-07", "macos", ["jsmith"])]
    benign = generate_baseline(profiles, SimConfig(seed=7, duration_seconds=600, rate_per_minute=12), _ACC_BASE)
    _write("no_detection_benign.jsonl", benign)

    # demo: two anchors firing (windows + linux), offset apart.
    demo = tp + _render_anchor(scns, topo, lnx, "CORP-JENKINS01", "linux")
    _write("demo_multi_os.jsonl", demo)


# Fixed planted-attack manifest (one per OS family + extras), each on a compatible host/zone.
_CORPUS_INJECTIONS = [
    {"scenario_id": "SCEN-WIN-001", "host": "HR_User_PC", "start_offset_seconds": 1800},
    {"scenario_id": "SCEN-LNX-001", "host": "CORP-JENKINS01", "start_offset_seconds": 3600},
    {"scenario_id": "SCEN-MAC-001", "host": "DESIGN-MBP-07", "start_offset_seconds": 5400},
    {"scenario_id": "SCEN-CLD-001", "host": "DMZ-WEB02", "start_offset_seconds": 7200},
    {"scenario_id": "SCEN-WIN-014", "host": "File_Server_01", "start_offset_seconds": 9000},
]
_CORPUS_PROFILES = [
    ("HR_User_PC", "windows", ["alice", "bob"]),
    ("Finance_User_PC", "windows", ["carol"]),
    ("File_Server_01", "windows", ["svc"]),
    ("CORP-JENKINS01", "linux", ["jenkins", "deploy"]),
    ("DMZ-WEB02", "linux", ["www"]),
    ("DESIGN-MBP-07", "macos", ["jsmith"]),
]


def regen_corpus(scenarios_dir: str, out_dir: str) -> dict:
    scns = load_scenarios(scenarios_dir)
    topo = default_topology()
    profiles = [MachineProfile(h, o, u) for h, o, u in _CORPUS_PROFILES]
    cfg = SimConfig(seed=2026, duration_seconds=14400, rate_per_minute=40,
                    injections=[Injection(**i) for i in _CORPUS_INJECTIONS])
    raws = generate_feed(cfg, profiles, scns, topo, _ACC_BASE)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "enterprise_day.jsonl"), "w") as fh:
        for e in raws:
            fh.write(json.dumps(e) + "\n")
    manifest = {"seed": 2026, "events": len(raws), "injections": _CORPUS_INJECTIONS}
    with open(os.path.join(out_dir, "manifest.json"), "w") as fh:
        fh.write(json.dumps(manifest, indent=2))
    return manifest


def main() -> None:
    out = "sample_data"
    n = len(regen_tp_fixtures("scenarios", out))
    regen_acceptance("scenarios", os.path.join(out, "acceptance"))
    manifest = regen_corpus("scenarios", os.path.join(out, "corpus"))
    print(f"regenerated sample_data: {n} TP fixtures, 6 acceptance fixtures, "
          f"corpus {manifest['events']} events / {len(manifest['injections'])} planted")


if __name__ == "__main__":
    main()
