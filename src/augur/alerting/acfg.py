import json
import os
import sqlite3

from augur.alerting.config import load_alert_config
from augur.connectors import get_sink


def _init_config_db(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS alert_config(id INTEGER PRIMARY KEY CHECK(id=1), blob TEXT NOT NULL)")
    conn.commit()


def _seed() -> dict:
    base = load_alert_config()
    sinks_env = os.environ.get("AUGUR_ALERT_SINKS")
    rules_env = os.environ.get("AUGUR_ALERT_RULES")
    return {
        "min_proximity": base.min_proximity,
        "auto_resolve_cycles": base.auto_resolve_cycles,
        "rules": json.loads(rules_env) if rules_env else [],
        "sinks": json.loads(sinks_env) if sinks_env else {},
    }


class AlertConfigStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        _init_config_db(conn)
        if self.conn.execute("SELECT 1 FROM alert_config WHERE id=1").fetchone() is None:
            self.conn.execute("INSERT INTO alert_config(id, blob) VALUES(1, ?)",
                              (json.dumps(_seed()),))
            self.conn.commit()

    def get(self) -> dict:
        row = self.conn.execute("SELECT blob FROM alert_config WHERE id=1").fetchone()
        return json.loads(row["blob"])

    def put(self, cfg: dict) -> None:
        self.conn.execute("UPDATE alert_config SET blob=? WHERE id=1", (json.dumps(cfg),))
        self.conn.commit()


def build_sink_factory(sinks_cfg: dict):
    """sinks_cfg: {name: {type, **kwargs}} -> a factory(name)->Sink|None reusing connectors.get_sink."""
    def factory(name: str):
        spec = sinks_cfg.get(name)
        if not spec:
            return None
        kwargs = {k: v for k, v in spec.items() if k != "type"}
        try:
            return get_sink(spec["type"], **kwargs)
        except Exception:
            return None
    return factory
