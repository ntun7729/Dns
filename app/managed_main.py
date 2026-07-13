#!/usr/bin/env python3
"""Managed dashboard features: auth, history, controls, and DNS filtering."""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import os
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime, timezone
from typing import Any

import enhanced_main as enhanced
import main as core

HAGEZI_LIGHT_URL = (
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt"
)
BLOCKLIST_PRESETS: dict[str, str | None] = {
    "off": None,
    "hagezi_light": HAGEZI_LIGHT_URL,
}
MAX_CONTROL_BODY_BYTES = 64 * 1024
MAX_BLOCKLIST_BYTES = 32 * 1024 * 1024


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


HISTORY_MINUTES = _env_int("HISTORY_MINUTES", 120, 15, 1440)
FILTER_UPDATE_HOURS = _env_int("FILTER_UPDATE_HOURS", 24, 1, 168)
DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "").strip()
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")
AUTH_ENABLED = bool(DASHBOARD_USERNAME and DASHBOARD_PASSWORD)

CONTROL_LOCK = threading.RLock()
FILTER_LOCK = threading.RLock()
HISTORY_LOCK = threading.RLock()

CONTROL_STATE: dict[str, Any] = {
    "upstreams": tuple(enhanced.UPSTREAMS),
    "strategy": enhanced.UPSTREAM_STRATEGY,
}


def _parse_domain_lines(value: str | None) -> set[str]:
    domains: set[str] = set()
    for raw in (value or "").replace(",", "\n").splitlines():
        domain = _normalize_domain(raw)
        if domain:
            domains.add(domain)
    return domains


FILTER_STATE: dict[str, Any] = {
    "enabled": _env_bool("FILTER_ENABLED", False),
    "preset": os.getenv("BLOCKLIST_PRESET", "off").strip().lower(),
    "domains": set(),
    "manual_block": _parse_domain_lines(os.getenv("MANUAL_BLOCK_DOMAINS")),
    "allow": _parse_domain_lines(os.getenv("ALLOW_DOMAINS")),
    "loading": False,
    "last_updated_at": None,
    "last_error": None,
    "blocked_queries": 0,
}
if FILTER_STATE["preset"] not in BLOCKLIST_PRESETS:
    FILTER_STATE["preset"] = "off"

HISTORY: deque[dict[str, Any]] = deque(maxlen=HISTORY_MINUTES)


def _normalize_domain(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = value.strip().lower().rstrip(".")
    if not candidate or candidate.startswith("#") or " " in candidate:
        return None
    if candidate.startswith("||"):
        candidate = candidate[2:]
    candidate = candidate.rstrip("^")
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(candidate) > 253:
        return None
    labels = candidate.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not label or len(label) > 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
        if not all(char.isalnum() or char == "-" for char in label):
            return None
    return candidate


def _minute_epoch(timestamp: float | None = None) -> int:
    return int((timestamp if timestamp is not None else time.time()) // 60) * 60


def _record_history(
    *,
    queries: int = 0,
    errors: int = 0,
    blocked: int = 0,
    failovers: int = 0,
    latency_ms: float | None = None,
) -> None:
    epoch = _minute_epoch()
    with HISTORY_LOCK:
        if not HISTORY or HISTORY[-1]["epoch"] != epoch:
            HISTORY.append(
                {
                    "epoch": epoch,
                    "queries": 0,
                    "errors": 0,
                    "blocked": 0,
                    "failovers": 0,
                    "latency_total_ms": 0.0,
                    "latency_samples": 0,
                }
            )
        bucket = HISTORY[-1]
        bucket["queries"] += queries
        bucket["errors"] += errors
        bucket["blocked"] += blocked
        bucket["failovers"] += failovers
        if latency_ms is not None:
            bucket["latency_total_ms"] += latency_ms
            bucket["latency_samples"] += 1


def history_snapshot() -> list[dict[str, Any]]:
    now_epoch = _minute_epoch()
    first_epoch = now_epoch - (HISTORY_MINUTES - 1) * 60
    with HISTORY_LOCK:
        existing = {item["epoch"]: dict(item) for item in HISTORY}
    points: list[dict[str, Any]] = []
    for epoch in range(first_epoch, now_epoch + 1, 60):
        bucket = existing.get(
            epoch,
            {
                "epoch": epoch,
                "queries": 0,
                "errors": 0,
                "blocked": 0,
                "failovers": 0,
                "latency_total_ms": 0.0,
                "latency_samples": 0,
            },
        )
        samples = int(bucket["latency_samples"])
        total = float(bucket["latency_total_ms"])
        points.append(
            {
                "time": datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace(
                    "+00:00", "Z"
                ),
                "queries": int(bucket["queries"]),
                "errors": int(bucket["errors"]),
                "blocked": int(bucket["blocked"]),
                "failovers": int(bucket["failovers"]),
                "latency_ms": round(total / samples, 2) if samples else None,
            }
        )
    return points


def _current_upstream_config() -> tuple[
    tuple[enhanced.UpstreamEndpoint, ...], str
]:
    with CONTROL_LOCK:
        return tuple(CONTROL_STATE["upstreams"]), str(CONTROL_STATE["strategy"])


def _ordered_upstreams(
    upstreams: tuple[enhanced.UpstreamEndpoint, ...], strategy: str
) -> tuple[enhanced.UpstreamEndpoint, ...]:
    if strategy == "primary_failover" or len(upstreams) <= 1:
        return upstreams
    with core.RUNTIME_LOCK:
        cursor = int(core.RUNTIME.get("upstream_cursor", 0)) % len(upstreams)
        core.RUNTIME["upstream_cursor"] = cursor + 1
    return upstreams[cursor:] + upstreams[:cursor]


def query_upstreams_sync(payload: bytes) -> bytes:
    upstreams, strategy = _current_upstream_config()
    errors: list[BaseException] = []
    for index, endpoint in enumerate(_ordered_upstreams(upstreams, strategy)):
        started = time.perf_counter()
        try:
            response = enhanced._send_udp_query(
                endpoint, payload, enhanced.UPSTREAM_TIMEOUT_SECONDS
            )
        except (OSError, TimeoutError) as exc:
            errors.append(exc)
            enhanced._record_upstream_failure(endpoint, exc)
            continue
        latency_ms = (time.perf_counter() - started) * 1000
        failover = index > 0
        enhanced._record_upstream_success(endpoint, latency_ms, failover=failover)
        _record_history(latency_ms=latency_ms, failovers=1 if failover else 0)
        return response

    if errors and all(
        isinstance(error, (socket.timeout, TimeoutError)) for error in errors
    ):
        raise socket.timeout("All upstream DNS resolvers timed out.")
    raise OSError("All upstream DNS resolvers failed.")


async def forward_dns_query(payload: bytes, _settings: core.Settings) -> bytes:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, query_upstreams_sync, payload)


def parse_dns_question(payload: bytes) -> tuple[str, int]:
    if len(payload) < 12:
        raise ValueError("DNS message is shorter than the header.")
    qdcount = int.from_bytes(payload[4:6], "big")
    if qdcount < 1:
        raise ValueError("DNS message contains no question.")
    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(payload):
            raise ValueError("DNS question name is truncated.")
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("Compressed DNS question names are not supported.")
        if length > 63 or offset + length > len(payload):
            raise ValueError("DNS question label is invalid.")
        try:
            labels.append(payload[offset : offset + length].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise ValueError("DNS question label is not ASCII.") from exc
        offset += length
    if offset + 4 > len(payload):
        raise ValueError("DNS question type or class is truncated.")
    domain = _normalize_domain(".".join(labels))
    if not domain:
        raise ValueError("DNS question name is invalid.")
    return domain, offset + 4


def _domain_suffixes(domain: str) -> tuple[str, ...]:
    labels = domain.split(".")
    return tuple(".".join(labels[index:]) for index in range(len(labels) - 1))


def domain_is_blocked(domain: str) -> bool:
    suffixes = _domain_suffixes(domain)
    with FILTER_LOCK:
        if not FILTER_STATE["enabled"]:
            return False
        allow = FILTER_STATE["allow"]
        if any(suffix in allow for suffix in suffixes):
            return False
        manual = FILTER_STATE["manual_block"]
        downloaded = FILTER_STATE["domains"]
        return any(suffix in manual or suffix in downloaded for suffix in suffixes)


def build_nxdomain_response(payload: bytes, question_end: int) -> bytes:
    query_flags = int.from_bytes(payload[2:4], "big")
    response_flags = 0x8000 | 0x0080 | (query_flags & 0x7900) | 0x0003
    header = (
        payload[:2]
        + response_flags.to_bytes(2, "big")
        + b"\x00\x01"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
    )
    return header + payload[12:question_end]


async def handle_dot(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    settings: core.Settings = core.SETTINGS,
) -> None:
    enhanced._record_connection_delta(1)
    try:
        while True:
            header = await reader.readexactly(2)
            length = int.from_bytes(header, "big")
            if length <= 0 or length > 4096:
                raise ValueError(f"Invalid DNS message length: {length}")
            payload = await reader.readexactly(length)
            domain, question_end = parse_dns_question(payload)
            blocked = domain_is_blocked(domain)
            if blocked:
                response = build_nxdomain_response(payload, question_end)
                with FILTER_LOCK:
                    FILTER_STATE["blocked_queries"] += 1
            else:
                response = await forward_dns_query(payload, settings)
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
            with core.RUNTIME_LOCK:
                core.RUNTIME["dns_queries"] += 1
                core.RUNTIME["last_query_at"] = core.now_iso()
            _record_history(queries=1, blocked=1 if blocked else 0)
    except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
        with core.RUNTIME_LOCK:
            core.RUNTIME["client_disconnects"] = int(
                core.RUNTIME.get("client_disconnects", 0)
            ) + 1
    except Exception as exc:  # noqa: BLE001 - aggregate telemetry only.
        safe_error = core.redact_text(str(exc), settings)
        enhanced._record_dns_error(enhanced.classify_dns_error(exc), safe_error)
        _record_history(errors=1)
    finally:
        enhanced._record_connection_delta(-1)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


def _parse_blocklist_text(text: str) -> set[str]:
    domains: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!", "[")):
            continue
        if " " in line or "\t" in line:
            parts = line.split()
            line = parts[-1] if parts else ""
        domain = _normalize_domain(line)
        if domain:
            domains.add(domain)
    return domains


def _download_blocklist(url: str) -> set[str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "DNS-Dashboard/2.3 blocklist updater"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(MAX_BLOCKLIST_BYTES + 1)
    if len(data) > MAX_BLOCKLIST_BYTES:
        raise ValueError("Blocklist exceeds the configured size limit.")
    return _parse_blocklist_text(data.decode("utf-8", errors="ignore"))


def refresh_blocklist_async() -> None:
    with FILTER_LOCK:
        preset = str(FILTER_STATE["preset"])
        url = BLOCKLIST_PRESETS.get(preset)
        if not FILTER_STATE["enabled"] or not url:
            FILTER_STATE["domains"] = set()
            FILTER_STATE["loading"] = False
            FILTER_STATE["last_error"] = None
            return
        if FILTER_STATE["loading"]:
            return
        FILTER_STATE["loading"] = True
        FILTER_STATE["last_error"] = None

    def worker() -> None:
        try:
            domains = _download_blocklist(url)
            if not domains:
                raise ValueError("Downloaded blocklist contained no valid domains.")
            with FILTER_LOCK:
                if FILTER_STATE["preset"] == preset:
                    FILTER_STATE["domains"] = domains
                    FILTER_STATE["last_updated_at"] = core.now_iso()
                    FILTER_STATE["last_error"] = None
        except Exception as exc:  # noqa: BLE001 - surfaced as safe status only.
            with FILTER_LOCK:
                FILTER_STATE["last_error"] = str(exc)[:300]
        finally:
            with FILTER_LOCK:
                FILTER_STATE["loading"] = False

    threading.Thread(target=worker, daemon=True).start()


def _blocklist_refresh_loop() -> None:
    while True:
        time.sleep(FILTER_UPDATE_HOURS * 3600)
        refresh_blocklist_async()


def filtering_status() -> dict[str, Any]:
    with FILTER_LOCK:
        return {
            "enabled": bool(FILTER_STATE["enabled"]),
            "preset": str(FILTER_STATE["preset"]),
            "source": BLOCKLIST_PRESETS.get(str(FILTER_STATE["preset"])),
            "downloaded_domains": len(FILTER_STATE["domains"]),
            "manual_block_domains": len(FILTER_STATE["manual_block"]),
            "allow_domains": len(FILTER_STATE["allow"]),
            "blocked_queries": int(FILTER_STATE["blocked_queries"]),
            "loading": bool(FILTER_STATE["loading"]),
            "last_updated_at": FILTER_STATE["last_updated_at"],
            "last_error": FILTER_STATE["last_error"],
        }


def control_payload() -> dict[str, Any]:
    upstreams, strategy = _current_upstream_config()
    with FILTER_LOCK:
        return {
            "runtime_only": True,
            "upstream_servers": ",".join(endpoint.key for endpoint in upstreams),
            "upstream_strategy": strategy,
            "filter_enabled": bool(FILTER_STATE["enabled"]),
            "filter_preset": str(FILTER_STATE["preset"]),
            "manual_block_domains": "\n".join(sorted(FILTER_STATE["manual_block"])),
            "allow_domains": "\n".join(sorted(FILTER_STATE["allow"])),
            "filter_presets": [
                {"id": "off", "name": "Off"},
                {"id": "hagezi_light", "name": "HaGeZi Light"},
            ],
        }


def apply_control_update(data: dict[str, Any]) -> dict[str, Any]:
    strategy = str(data.get("upstream_strategy", "")).strip().lower()
    if strategy not in enhanced.SUPPORTED_UPSTREAM_STRATEGIES:
        raise ValueError("Unsupported upstream strategy.")
    upstream_text = str(data.get("upstream_servers", "")).strip()
    upstreams = enhanced.parse_upstream_servers(
        upstream_text,
        fallback_host=core.SETTINGS.upstream_dns,
        fallback_port=core.SETTINGS.upstream_dns_port,
    )
    if len(upstreams) > 8:
        raise ValueError("A maximum of eight upstream resolvers is supported.")

    preset = str(data.get("filter_preset", "off")).strip().lower()
    if preset not in BLOCKLIST_PRESETS:
        raise ValueError("Unsupported filtering preset.")
    filter_enabled = bool(data.get("filter_enabled", False))
    manual_block = _parse_domain_lines(str(data.get("manual_block_domains", "")))
    allow = _parse_domain_lines(str(data.get("allow_domains", "")))
    if len(manual_block) > 5000 or len(allow) > 5000:
        raise ValueError("Manual domain lists are limited to 5,000 entries each.")

    with CONTROL_LOCK:
        CONTROL_STATE["upstreams"] = upstreams
        CONTROL_STATE["strategy"] = strategy
        enhanced.UPSTREAMS = upstreams
        enhanced.UPSTREAM_STRATEGY = strategy
    with core.RUNTIME_LOCK:
        stats = core.RUNTIME.setdefault("upstream_stats", {})
        blank = enhanced._blank_upstream_stats()
        for endpoint in upstreams:
            stats.setdefault(endpoint.key, blank[endpoint.key])

    with FILTER_LOCK:
        old_preset = FILTER_STATE["preset"]
        FILTER_STATE["enabled"] = filter_enabled
        FILTER_STATE["preset"] = preset
        FILTER_STATE["manual_block"] = manual_block
        FILTER_STATE["allow"] = allow
        if not filter_enabled or preset == "off":
            FILTER_STATE["domains"] = set()
            FILTER_STATE["last_error"] = None
        elif old_preset != preset:
            FILTER_STATE["domains"] = set()

    if filter_enabled and preset != "off":
        refresh_blocklist_async()
    return control_payload()


_base_status_payload = enhanced.status_payload


def status_payload(settings: core.Settings = core.SETTINGS) -> dict[str, Any]:
    payload = _base_status_payload(settings)
    filter_status = filtering_status()
    payload["history"] = history_snapshot()
    payload["metrics"]["dns_blocked"] = filter_status["blocked_queries"]
    payload["filtering"] = filter_status
    payload["access_control"] = {
        "enabled": AUTH_ENABLED,
        "controls_available": AUTH_ENABLED,
    }
    payload["configuration"]["history_minutes"] = HISTORY_MINUTES
    payload["configuration"]["runtime_controls"] = "memory-only"
    payload["configuration"]["upstream_servers"] = [
        endpoint.key for endpoint in _current_upstream_config()[0]
    ]
    payload["configuration"]["upstream_strategy"] = _current_upstream_config()[1]

    diagnostics = list(payload.get("diagnostics", []))
    if not AUTH_ENABLED:
        diagnostics.append(
            {
                "severity": "warning",
                "code": "dashboard_auth_disabled",
                "message": "Dashboard controls are disabled until DASHBOARD_USERNAME and DASHBOARD_PASSWORD are configured.",
            }
        )
    if filter_status["last_error"]:
        diagnostics.append(
            {
                "severity": "warning",
                "code": "blocklist_update_failed",
                "message": "The blocklist update failed; the previous in-memory list remains active.",
            }
        )
    payload["diagnostics"] = diagnostics
    return payload


def _authorized(handler: core.DashboardHandler) -> bool:
    if not AUTH_ENABLED:
        return True
    header = handler.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
        username, password = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError):
        return False
    return hmac.compare_digest(username, DASHBOARD_USERNAME) and hmac.compare_digest(
        password, DASHBOARD_PASSWORD
    )


def _send_unauthorized(handler: core.DashboardHandler) -> None:
    body = b"Authentication required."
    handler.send_response(401)
    handler.send_header("WWW-Authenticate", 'Basic realm="DNS Dashboard"')
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _same_origin(handler: core.DashboardHandler) -> bool:
    origin = handler.headers.get("Origin")
    if not origin:
        return True
    parsed = urllib.parse.urlparse(origin)
    return parsed.netloc == handler.headers.get("Host", "")


_original_do_get = core.DashboardHandler.do_GET


def managed_do_get(handler: core.DashboardHandler) -> None:
    path = handler.path.split("?", 1)[0]
    if path not in {"/healthz", "/readyz"} and not _authorized(handler):
        _send_unauthorized(handler)
        return
    if path == "/api/control":
        if not AUTH_ENABLED:
            handler._json(
                {
                    "ok": False,
                    "error": "Configure dashboard credentials to enable controls.",
                },
                core.HTTPStatus.FORBIDDEN,
            )
            return
        handler._json({"ok": True, "control": control_payload()})
        return
    _original_do_get(handler)


def managed_do_post(handler: core.DashboardHandler) -> None:
    path = handler.path.split("?", 1)[0]
    if path != "/api/control":
        handler.send_error(core.HTTPStatus.NOT_FOUND)
        return
    if not AUTH_ENABLED or not _authorized(handler):
        _send_unauthorized(handler)
        return
    if not _same_origin(handler):
        handler._json(
            {"ok": False, "error": "Cross-origin control requests are rejected."},
            core.HTTPStatus.FORBIDDEN,
        )
        return
    if not handler.headers.get("Content-Type", "").startswith("application/json"):
        handler._json(
            {"ok": False, "error": "Content-Type must be application/json."},
            core.HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
        )
        return
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        length = -1
    if length < 0 or length > MAX_CONTROL_BODY_BYTES:
        handler._json(
            {"ok": False, "error": "Control request is too large."},
            core.HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
        )
        return
    try:
        data = json.loads(handler.rfile.read(length).decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object.")
        action = str(data.get("action", "save"))
        if action == "refresh_blocklist":
            refresh_blocklist_async()
            control = control_payload()
        elif action == "save":
            control = apply_control_update(data)
        else:
            raise ValueError("Unsupported control action.")
    except (ValueError, json.JSONDecodeError) as exc:
        handler._json(
            {"ok": False, "error": str(exc)}, core.HTTPStatus.BAD_REQUEST
        )
        return
    handler._json({"ok": True, "control": control, "status": status_payload()})


def start_managed_services() -> None:
    if FILTER_STATE["enabled"] and FILTER_STATE["preset"] != "off":
        refresh_blocklist_async()
    threading.Thread(target=_blocklist_refresh_loop, daemon=True).start()


enhanced.forward_dns_query = forward_dns_query
enhanced.handle_dot = handle_dot
core.forward_dns_query = forward_dns_query
core.handle_dot = handle_dot
core.status_payload = status_payload
core.DashboardHandler.do_GET = managed_do_get
core.DashboardHandler.do_POST = managed_do_post
core.DashboardHandler.server_version = "DnsDashboard/2.3"


if __name__ == "__main__":
    start_managed_services()
    core.main()
