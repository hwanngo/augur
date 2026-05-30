"""Observability helpers: a dependency-free HTTP metrics registry rendered in
Prometheus text format, plus structured (JSON) logging setup.

No new dependencies — the Prometheus exposition format is simple text, and the
JSON formatter is a thin stdlib ``logging.Formatter`` subclass. Metrics are
labelled by the matched *route template* (not the raw path) to keep cardinality
bounded; path params and SPA deep-links collapse onto their template.
"""
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone


class MetricsRegistry:
    """Thread-safe HTTP request counters + latency sums (Prometheus-friendly)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # (method, template, status) -> count
        self._requests: dict[tuple[str, str, int], int] = {}
        # (method, template) -> [sum_seconds, count]
        self._latency: dict[tuple[str, str], list[float]] = {}

    def observe(self, method: str, template: str, status: int, seconds: float) -> None:
        with self._lock:
            rk = (method, template, status)
            self._requests[rk] = self._requests.get(rk, 0) + 1
            lk = (method, template)
            agg = self._latency.get(lk)
            if agg is None:
                self._latency[lk] = [seconds, 1.0]
            else:
                agg[0] += seconds
                agg[1] += 1.0

    def render(self) -> str:
        """Render the current metrics in Prometheus text exposition format."""
        def esc(v: str) -> str:
            return v.replace("\\", "\\\\").replace('"', '\\"')

        lines: list[str] = []
        with self._lock:
            requests = sorted(self._requests.items())
            latency = sorted(self._latency.items())
        lines.append("# HELP augur_http_requests_total Total HTTP requests.")
        lines.append("# TYPE augur_http_requests_total counter")
        for (method, template, status), count in requests:
            lines.append(
                f'augur_http_requests_total{{method="{esc(method)}",'
                f'route="{esc(template)}",status="{status}"}} {count}'
            )
        lines.append("# HELP augur_http_request_duration_seconds Request latency.")
        lines.append("# TYPE augur_http_request_duration_seconds summary")
        for (method, template), (total, count) in latency:
            label = f'method="{esc(method)}",route="{esc(template)}"'
            lines.append(f"augur_http_request_duration_seconds_sum{{{label}}} {total}")
            lines.append(f"augur_http_request_duration_seconds_count{{{label}}} {count}")
        return "\n".join(lines) + "\n"


class JsonLogFormatter(logging.Formatter):
    """Emit one JSON object per log record (ts, level, logger, message + extras)."""

    _RESERVED = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime", "taskName"}

    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            out["exc_info"] = self.formatException(record.exc_info)
        # Include any structured extras passed via logger.info(..., extra={...}).
        for k, v in record.__dict__.items():
            if k not in self._RESERVED and not k.startswith("_"):
                out[k] = v
        return json.dumps(out, default=str)


def setup_logging() -> None:
    """Configure root logging from env: AUGUR_LOG_LEVEL (default INFO) and
    AUGUR_LOG_FORMAT (``json`` or ``text``, default ``text``). Replaces the root
    handlers — call once at process startup (the uvicorn entrypoint / prod)."""
    level = os.environ.get("AUGUR_LOG_LEVEL", "INFO").upper()
    fmt = os.environ.get("AUGUR_LOG_FORMAT", "text").lower()
    handler = logging.StreamHandler()
    if fmt == "json":
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
