from datetime import datetime, timezone
from augur.simulator.config import SimConfig, Injection
from augur.simulator.run import generate_feed
from augur.simulator.stream import stream_feed
from augur.simulator.profiles import default_profiles
from augur.pipeline import default_scenarios, default_topology
from augur.connectors import DirectorySource
from augur.alerting.scan import run_scan
from augur.alerting.store import AlertStore
from augur.alerting.config import AlertConfig
from augur.auth.store import connect

BASE = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def test_generated_dropfeed_fires_an_alert_through_the_monitor_scan(tmp_path):
    # 1) generate a feed with an injected attack
    cfg = SimConfig(seed=11, duration_seconds=3600, rate_per_minute=15,
                    injections=[Injection(scenario_id="SCEN-WIN-001", host="HR_User_PC",
                                          start_offset_seconds=300)])
    raws = generate_feed(cfg, default_profiles(), default_scenarios(), default_topology(), BASE)
    # 2) stream it to a directory drop-feed (no real sleep)
    feed_dir = tmp_path / "feed"
    stream_feed(str(feed_dir), raws, batch_size=40, interval=0, sleep_fn=lambda s: None)
    # 3) the 3d monitor's scan tick over a DirectorySource of that dir -> an alert fires
    store = AlertStore(connect(str(tmp_path / "alerts.db")))
    counts = run_scan(store, DirectorySource(str(feed_dir)),
                      AlertConfig(min_proximity=0.6, auto_resolve_cycles=0),
                      rules=[], sink_factory=dict().get, now=NOW)
    assert counts["created"] >= 1
    alerts = {a.scenario_id: a for a in store.list()}
    assert "SCEN-WIN-001" in alerts and alerts["SCEN-WIN-001"].band == "CONFIRMED"
