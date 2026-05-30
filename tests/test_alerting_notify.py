from augur.alerting.notify import route_notifications, rule_matches
from augur.alerting.store import Alert
from augur.engine.scoring import Detection

SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class FakeSink:
    def __init__(self): self.emitted = []
    def emit(self, detection): self.emitted.append(detection)


class BoomSink:
    def emit(self, detection): raise RuntimeError("sink down")


def _alert(sev="CRITICAL", p=0.9, key="SCEN-1|hA"):
    return Alert(dedup_key=key, scenario_id="SCEN-1", scenario_name="n", severity=sev,
                 affected_hosts=["hA"], proximity=p, band="HIGH", id="id1")


def _det(p=0.9):
    return Detection("SCEN-1", "n", "CRITICAL", p, [], [], ["hA"], [], [])


def test_rule_matches_severity_and_proximity():
    assert rule_matches(_alert(sev="CRITICAL", p=0.9), {"min_severity": "HIGH", "min_proximity": 0.8})
    assert not rule_matches(_alert(sev="LOW", p=0.9), {"min_severity": "HIGH", "min_proximity": None})
    assert not rule_matches(_alert(sev="CRITICAL", p=0.5), {"min_severity": None, "min_proximity": 0.8})
    assert rule_matches(_alert(), {"min_severity": None, "min_proximity": None})   # wildcard


def test_route_emits_to_union_of_matching_rule_sinks():
    slack, jira = FakeSink(), FakeSink()
    factory = {"slack": slack, "jira": jira}.get
    rules = [{"min_severity": "CRITICAL", "min_proximity": None, "sinks": ["slack", "jira"]},
             {"min_severity": None, "min_proximity": None, "sinks": ["slack"]}]
    n = route_notifications([(_alert(), _det())], rules, factory)
    assert n == 1                       # one alert delivered to >=1 sink
    assert len(slack.emitted) == 1 and len(jira.emitted) == 1   # union, slack not double-emitted


def test_failing_sink_does_not_block_others():
    ok = FakeSink()
    factory = {"boom": BoomSink(), "ok": ok}.get
    rules = [{"min_severity": None, "min_proximity": None, "sinks": ["boom", "ok"]}]
    n = route_notifications([(_alert(), _det())], rules, factory)
    assert n == 1 and len(ok.emitted) == 1     # boom failed, ok still got it


def test_no_rules_or_no_alerts_notifies_zero():
    assert route_notifications([], [{"min_severity": None, "min_proximity": None, "sinks": ["x"]}], dict().get) == 0
    assert route_notifications([(_alert(), _det())], [], dict().get) == 0


# ── FIX 2: fail-safe on unknown severity ────────────────────────────────────

def test_rule_matches_unknown_severity_returns_false_not_raise():
    """Unknown severity in a rule must NOT raise; it must return False (fail-closed)."""
    assert rule_matches(_alert(sev="CRITICAL"), {"min_severity": "BOGUS", "min_proximity": None}) is False


def test_route_notifications_unknown_severity_rule_returns_zero_not_raise():
    """route_notifications with a bogus min_severity rule must return 0 without raising."""
    rules = [{"min_severity": "BOGUS", "min_proximity": None, "sinks": ["x"]}]
    fake = FakeSink()
    n = route_notifications([(_alert(sev="CRITICAL"), _det())], rules, {"x": fake}.get)
    assert n == 0


# ── FIX 3: close sinks after route_notifications ─────────────────────────────

def test_sink_close_called_after_route_notifications():
    """A sink with a close() method must be closed exactly once after route_notifications."""
    closed = []

    class CloseableSink:
        def emit(self, detection):
            pass
        def close(self):
            closed.append(True)

    sink = CloseableSink()
    rules = [{"min_severity": None, "min_proximity": None, "sinks": ["cs"]}]
    route_notifications([(_alert(), _det())], rules, {"cs": sink}.get)
    assert closed == [True], f"expected close() called once, got {closed}"


def test_sink_close_called_even_if_no_alerts_matched():
    """close() is called even when a sink was cached but delivered nothing (e.g. second alert missed)."""
    closed = []

    class CloseableSink:
        def emit(self, detection):
            pass
        def close(self):
            closed.append(True)

    sink = CloseableSink()
    # One alert triggers the sink (cached), a second with higher threshold rule won't — but close() still fires
    rules = [{"min_severity": "CRITICAL", "min_proximity": None, "sinks": ["cs"]}]
    route_notifications([(_alert(sev="CRITICAL"), _det()), (_alert(sev="LOW", key="SCEN-1|hB"), _det())],
                        rules, {"cs": sink}.get)
    assert closed == [True]


def test_sink_close_failure_does_not_propagate():
    """A close() that raises must not propagate out of route_notifications."""
    class ExplodingClose:
        def emit(self, detection): pass
        def close(self): raise RuntimeError("kaboom on close")

    sink = ExplodingClose()
    rules = [{"min_severity": None, "min_proximity": None, "sinks": ["ec"]}]
    # Must not raise:
    route_notifications([(_alert(), _det())], rules, {"ec": sink}.get)
