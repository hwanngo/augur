import ipaddress
import json
import socket
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from augur.connectors.base import SinkBase
from augur.engine.scoring import Detection


class SinkDeliveryError(Exception):
    """A sink failed to deliver a detection to its remote endpoint (network/HTTP error).

    Distinct from configuration errors so callers (e.g. the API) can map delivery
    failures to a 502 Bad Gateway rather than leaking an unhandled 500/traceback.
    """


def validate_sink_url(url: str) -> str:
    """Reject SSRF-prone sink URLs at config-write time.

    Blocks non-http(s) schemes and hosts that resolve to loopback or
    link-local ranges (cloud metadata at 169.254.169.254, ::1, fe80::/10).
    Private RFC1918 ranges are intentionally ALLOWED — on-prem SOAR/Jira/Slack
    relays legitimately live there. Raises ValueError on a disallowed URL.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"sink url scheme must be http(s): {url!r}")
    host = parts.hostname
    if not host:
        raise ValueError(f"sink url has no host: {url!r}")
    # Resolve every address the host maps to and reject if ANY is loopback/link-local.
    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
        addrs = {info[4][0] for info in infos}
    except socket.gaierror:
        # Unresolvable host: let delivery fail later rather than block config; but a
        # bare IP literal that didn't resolve is still parseable below.
        addrs = {host}
    for addr in addrs:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        # An IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1) is not itself flagged
        # loopback/link-local by the stdlib — unwrap it so it can't smuggle a
        # blocked v4 target past the checks below.
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise ValueError(f"sink url resolves to a blocked address ({addr}): {url!r}")
    return url


def _public(detection: Detection) -> dict:
    """Detection as a JSON-safe dict, dropping internal _-prefixed fields."""
    return {k: v for k, v in asdict(detection).items() if not k.startswith("_")}


def _post_json(url: str, payload: dict, timeout: float) -> int:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        # Network/HTTP failure delivering to a remote sink — surface as a typed
        # error so the API layer returns 502 instead of an unhandled 500.
        raise SinkDeliveryError(f"failed to deliver to {url!r}: {exc}") from exc


class StdoutSink(SinkBase):
    """Human-readable detection lines on stdout (CLI default)."""
    def emit(self, detection: Detection) -> None:
        matched = len(detection.matched_steps)
        total = matched + len(detection.missing_steps)
        pct = round(detection.proximity * 100)
        print(f"[{detection.severity:8}] {detection.scenario_id}  {pct:3d}%  "
              f"{matched}/{total}  {detection.name}  hosts={detection.affected_hosts}")


class JsonlFileSink(SinkBase):
    """Append one detection JSON object per line to a file (durable, diffable)."""
    def __init__(self, path: str, mode: str = "a") -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, mode)

    def emit(self, detection: Detection) -> None:
        self._fh.write(json.dumps(_public(detection)) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class WebhookSink(SinkBase):
    """POST each detection as JSON to a URL (generic SOAR / webhook integration)."""
    def __init__(self, url: str, timeout: float = 5.0) -> None:
        self.url = url
        self.timeout = timeout

    def emit(self, detection: Detection) -> None:
        _post_json(self.url, _public(detection), self.timeout)


class SlackSink(WebhookSink):
    """POST a Slack-style {"text": ...} message per detection (ChatOps integration)."""
    def emit(self, detection: Detection) -> None:
        matched = len(detection.matched_steps)
        total = matched + len(detection.missing_steps)
        pct = round(detection.proximity * 100)
        hosts = ", ".join(detection.affected_hosts)
        text = (f":rotating_light: *{detection.severity}* {detection.name} "
                f"({detection.scenario_id}) — {pct}% ({matched}/{total}) on {hosts}")
        _post_json(self.url, {"text": text}, self.timeout)


_XSOAR_SEVERITY = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class CortexXsoarSink(WebhookSink):
    """POST each detection as a Cortex XSOAR incident to the XSOAR REST API."""

    def emit(self, detection: Detection) -> None:
        payload = {
            "name": f"{detection.name} ({detection.scenario_id})",
            "type": "Augur Detection",
            "severity": _XSOAR_SEVERITY.get(detection.severity.upper(), 1),
            "labels": [{"type": "scenario_id", "value": detection.scenario_id}],
            "rawJSON": json.dumps(_public(detection)),
        }
        _post_json(self.url, payload, self.timeout)


class JiraSink(WebhookSink):
    """POST each detection as a Jira create-issue request."""

    def emit(self, detection: Detection) -> None:
        matched = len(detection.matched_steps)
        total = matched + len(detection.missing_steps)
        pct = round(detection.proximity * 100)
        hosts = ", ".join(detection.affected_hosts)
        description = (
            f"Scenario: {detection.scenario_id}\n"
            f"Severity: {detection.severity}\n"
            f"Proximity: {pct}%\n"
            f"Matched/Total steps: {matched}/{total}\n"
            f"Affected hosts: {hosts}\n"
        )
        payload = {
            "fields": {
                "summary": f"[{detection.severity}] {detection.name} ({detection.scenario_id})",
                "description": description,
                "labels": ["augur", detection.severity.lower()],
            }
        }
        _post_json(self.url, payload, self.timeout)
