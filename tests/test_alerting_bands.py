from augur.alerting.bands import band_for, band_rank, BANDS
from augur.alerting.config import load_alert_config


def test_band_for_thresholds():
    assert band_for(1.0) == "CONFIRMED"
    assert band_for(0.95) == "HIGH"
    assert band_for(0.8) == "HIGH"
    assert band_for(0.6) == "WATCH"
    assert band_for(0.79) == "WATCH"


def test_band_rank_is_ascending():
    assert band_rank("WATCH") < band_rank("HIGH") < band_rank("CONFIRMED")
    assert band_rank("") == -1           # unknown/none ranks below WATCH
    assert BANDS == ["WATCH", "HIGH", "CONFIRMED"]


def test_config_defaults(monkeypatch):
    for k in ("AUGUR_ALERT_MIN_PROXIMITY", "AUGUR_ALERT_AUTO_RESOLVE_CYCLES"):
        monkeypatch.delenv(k, raising=False)
    c = load_alert_config()
    assert c.min_proximity == 0.6 and c.auto_resolve_cycles == 0


def test_config_clamps_min_proximity(monkeypatch):
    monkeypatch.setenv("AUGUR_ALERT_MIN_PROXIMITY", "1.5")
    assert load_alert_config().min_proximity == 1.0
    monkeypatch.setenv("AUGUR_ALERT_MIN_PROXIMITY", "-0.2")
    assert load_alert_config().min_proximity == 0.0
