#!/usr/bin/env python3
"""Operational telemetry, quiet runtime, and multi-upstream DNS support."""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import main as core

ERROR_TYPES = (
    "upstream_timeout",
    "upstream_socket",
    "malformed_message",
    "internal_error",
)
SUPPORTED_UPSTREAM_STRATEGIES = {"round_robin", "primary_failover"}

_original_reset_runtime = core.reset_runtime
_original_status_payload = core.status_payload


@dataclass(frozen=True)
class UpstreamEndpoint:
    host: str
    port: int

    @property
    def key(self) -> str:
        host = f"[{self.host}]" if ":" in self.host and not self.host.startswith("[") else self.host
        return f"{host}:{self.port}"


def parse_upstream_servers(
    value: str | None,
    *,
    fallback_host: str,
    fallback_port: int,
) -> tuple[UpstreamEndpoint, ...]:
    """Parse comma-separated host[:port] values, including bracketed IPv6."""
    raw_items = [item.strip() for item in (value or "").split(",") if item.strip()]
    if not raw_items:
        raw_items = [f"{fallback_host}:{fallback_port}"]

    endpoints: list[UpstreamEndpoint] = []
    seen: set[str] = set()
    for item in raw_items:
        host = item
        port = fallback_port
        if item.startswith("["):
            closing = item.find("]")
            if closing < 2:
                raise ValueError(f"Invalid bracketed upstream address: {item}")
            host = item[1:closing]
            remainder = item[closing + 1 :]
            if remainder:
                if not remainder.startswith(":"):
                    raise ValueError(f"Invalid upstream address: {item}")
                port = int(remainder[1:])
        elif item.count(":") == 1:
            host, raw_port = item.rsplit(":", 1)
            port = int(raw_port)
        elif item.count(":") > 1:
            host = item

        host = host.strip()
        if not host or port < 1 or port > 65535:
            raise ValueError(f"Invalid upstream resolver: {item}")
        endpoint = UpstreamEndpoint(host, port)
        if endpoint.key not in seen:
            endpoints.append(endpoint)
            seen.add(endpoint.key)

    if not endpoints:
        raise ValueError("At least one upstream resolver is required.")
    return tuple(endpoints)


def _env_float(name: str, default: float, minimum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(minimum, value)


UPSTREAMS = parse_upstream_servers(
    os.getenv("UPSTREAM_DNS_SERVERS"),
    fallback_host=core.SETTINGS.upstream_dns,
    fallback_port=core.SETTINGS.upstream_dns_port,
)
UPSTREAM_STRATEGY = os.getenv("UPSTREAM_STRATEGY", "round_robin").strip().lower()
if UPSTREAM_STRATEGY not in SUPPORTED_UPSTREAM_STRATEGIES:
    UPSTREAM_STRATEGY = "round_robin"
UPSTREAM_TIMEOUT_SECONDS = _env_float("UPSTREAM_TIMEOUT_SECONDS", 2.0, 0.2)


def _blank_upstream_stats() -> dict[str, dict[str, Any]]:
    return {
        endpoint.key: {
            "endpoint": endpoint.key,
            "attempts": 0,
            "successes": 0,
            "failures": 0,
            "timeouts": 0,
            "last_latency_ms": None,
            "latency_total_ms": 0.0,
            "latency_samples": 0,
            "last_success_at": None,
            "last_failure_at": None,
            "last_error_type": None,
        }
        for endpoint in UPSTREAMS
    }


def _telemetry_defaults() -> dict[str, Any]:
    return {
        "dns_error_types": {name: 0 for name in ERROR_TYPES},
        "client_disconnects": 0,
        "active_connections": 0,
        "peak_connections": 0,
        "upstream_cursor": 0,
        "upstream_failovers": 0,
        "upstream_last_used": None,
        "upstream_last_latency_ms": None,
        "upstream_latency_total_ms": 0.0,
        "upstream_latency_samples": 0,
        "upstream_last_success_at": None,
        "upstream_last_failure_at": None,
        "upstream_stats": _blank_upstream_stats(),
    }


def _ensure_telemetry_state() -> None:
    with core.RUNTIME_LOCK:
        defaults = _telemetry_defaults()
        for key, value in defaults.items():
            if key not in core.RUNTIME:
                core.RUNTIME[key] = value
        if not isinstance(core.RUNTIME.get("dns_error_types"), dict):
            core.RUNTIME["dns_error_types"] = defaults["dns_error_types"]
        if not isinstance(core.RUNTIME.get("upstream_stats"), dict):
            core.RUNTIME["upstream_stats"] = defaults["upstream_stats"]


def reset_runtime() -> None:
    _original_reset_runtime()
    with core.RUNTIME_LOCK:
        core.RUNTIME.update(_telemetry_defaults())


def classify_dns_error(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError, asyncio.TimeoutError)):
        return "upstream_timeout"
    if isinstance(exc, OSError):
        return "upstream_socket"
    if isinstance(exc, ValueError):
        return "malformed_message"
    return "internal_error"


def _record_connection_delta(delta: int) -> None:
    with core.RUNTIME_LOCK:
        active = max(0, int(core.RUNTIME.get("active_connections", 0)) + delta)
        core.RUNTIME["active_connections"] = active
        core.RUNTIME["peak_connections"] = max(
            int(core.RUNTIME.get("peak_connections", 0)), active
        )


def _ordered_upstreams(
    upstreams: tuple[UpstreamEndpoint, ...] = UPSTREAMS,
    strategy: str = UPSTREAM_STRATEGY,
) -> tuple[UpstreamEndpoint, ...]:
    if strategy == "primary_failover" or len(upstreams) <= 1:
        return upstreams
    with core.RUNTIME_LOCK:
        cursor = int(core.RUNTIME.get("upstream_cursor", 0)) % len(upstreams)
        core.RUNTIME["upstream_cursor"] = cursor + 1
    return upstreams[cursor:] + upstreams[:cursor]


def _record_upstream_success(endpoint: UpstreamEndpoint, latency_ms: float, failover: bool) -> None:
    now = core.now_iso()
    with core.RUNTIME_LOCK:
        stats = core.RUNTIME.setdefault("upstream_stats", _blank_upstream_stats())
        current = stats.setdefault(endpoint.key, _blank_upstream_stats()[endpoint.key])
        current["attempts"] += 1
        current["successes"] += 1
        current["last_latency_ms"] = round(latency_ms, 2)
        current["latency_total_ms"] += latency_ms
        current["latency_samples"] += 1
        current["last_success_at"] = now
        current["last_error_type"] = None
        core.RUNTIME["upstream_last_used"] = endpoint.key
        core.RUNTIME["upstream_last_latency_ms"] = round(latency_ms, 2)
        core.RUNTIME["upstream_latency_total_ms"] += latency_ms
        core.RUNTIME["upstream_latency_samples"] += 1
        core.RUNTIME["upstream_last_success_at"] = now
        if failover:
            core.RUNTIME["upstream_failovers"] += 1


def _record_upstream_failure(endpoint: UpstreamEndpoint, exc: BaseException) -> None:
    now = core.now_iso()
    kind = classify_dns_error(exc)
    with core.RUNTIME_LOCK:
        stats = core.RUNTIME.setdefault("upstream_stats", _blank_upstream_stats())
        current = stats.setdefault(endpoint.key, _blank_upstream_stats()[endpoint.key])
        current["attempts"] += 1
        current["failures"] += 1
        current["last_failure_at"] = now
        current["last_error_type"] = kind
        if kind == "upstream_timeout":
            current["timeouts"] += 1
        core.RUNTIME["upstream_last_failure_at"] = now


def _record_dns_error(kind: str, message: str) -> None:
    with core.RUNTIME_LOCK:
        error_types = dict(core.RUNTIME.get("dns_error_types", {}))
        error_types[kind] = int(error_types.get(kind, 0)) + 1
        core.RUNTIME["dns_error_types"] = error_types
        core.RUNTIME["dns_errors"] = int(core.RUNTIME.get("dns_errors", 0)) + 1
        core.RUNTIME["dot_last_error"] = message


def _send_udp_query(
    endpoint: UpstreamEndpoint,
    payload: bytes,
    timeout: float,
) -> bytes:
    last_error: OSError | None = None
    addresses = socket.getaddrinfo(
        endpoint.host,
        endpoint.port,
        type=socket.SOCK_DGRAM,
    )
    for family, socktype, protocol, _canonical_name, address in addresses:
        try:
            with socket.socket(family, socktype, protocol) as sock:
                sock.settimeout(timeout)
                sock.connect(address)
                sock.send(payload)
                response = sock.recv(4096)
                if len(response) < 12:
                    raise OSError("Upstream returned a truncated DNS header.")
                if len(payload) >= 2 and response[:2] != payload[:2]:
                    raise OSError("Upstream returned a mismatched DNS transaction ID.")
                return response
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise OSError(f"No network address found for upstream {endpoint.key}.")


def query_upstreams_sync(
    payload: bytes,
    *,
    upstreams: tuple[UpstreamEndpoint, ...] = UPSTREAMS,
    strategy: str = UPSTREAM_STRATEGY,
    timeout: float = UPSTREAM_TIMEOUT_SECONDS,
) -> bytes:
    errors: list[BaseException] = []
    for index, endpoint in enumerate(_ordered_upstreams(upstreams, strategy)):
        started = time.perf_counter()
        try:
            response = _send_udp_query(endpoint, payload, timeout)
        except (OSError, TimeoutError) as exc:
            errors.append(exc)
            _record_upstream_failure(endpoint, exc)
            continue
        _record_upstream_success(
            endpoint,
            (time.perf_counter() - started) * 1000,
            failover=index > 0,
        )
        return response

    if errors and all(isinstance(error, (socket.timeout, TimeoutError)) for error in errors):
        raise socket.timeout("All upstream DNS resolvers timed out.")
    raise OSError("All upstream DNS resolvers failed.")


async def forward_dns_query(payload: bytes, settings: core.Settings) -> bytes:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, query_upstreams_sync, payload)


async def handle_dot(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    settings: core.Settings = core.SETTINGS,
) -> None:
    _record_connection_delta(1)
    try:
        while True:
            header = await reader.readexactly(2)
            length = int.from_bytes(header, "big")
            if length <= 0 or length > 4096:
                raise ValueError(f"Invalid DNS message length: {length}")
            payload = await reader.readexactly(length)
            response = await forward_dns_query(payload, settings)
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
            with core.RUNTIME_LOCK:
                core.RUNTIME["dns_queries"] += 1
                core.RUNTIME["last_query_at"] = core.now_iso()
    except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
        with core.RUNTIME_LOCK:
            core.RUNTIME["client_disconnects"] = int(
                core.RUNTIME.get("client_disconnects", 0)
            ) + 1
    except Exception as exc:  # noqa: BLE001 - operational telemetry only.
        safe_error = core.redact_text(str(exc), settings)
        _record_dns_error(classify_dns_error(exc), safe_error)
    finally:
        _record_connection_delta(-1)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


def quiet_start_frpc(settings: core.Settings) -> subprocess.Popen[bytes] | None:
    """Start FRPC without stdout/stderr pipes or log-reader threads."""
    if not settings.frpc_enabled:
        core.set_runtime(frpc_state="disabled", frpc_running=False, frpc_last_error=None)
        return None
    if not settings.frpc_configured:
        core.set_runtime(
            frpc_state="needs-config",
            frpc_running=False,
            frpc_last_error="FRP_SERVER_ADDR is required to start FRPC.",
        )
        return None

    snapshot = core.runtime_snapshot()
    if settings.dot_enabled and snapshot["dot_state"] != "running":
        core.set_runtime(
            frpc_state="blocked",
            frpc_running=False,
            frpc_last_error="FRPC was not started because the DoT listener is not ready.",
        )
        return None

    config = core.write_frpc_config(settings)
    assert config is not None
    try:
        process = subprocess.Popen(
            [settings.frpc_binary, "-c", str(config)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except OSError as exc:
        core.set_runtime(
            frpc_state="startup-failed",
            frpc_running=False,
            frpc_last_error=core.redact_text(str(exc), settings),
        )
        return None

    core.set_runtime(
        frpc_state="starting",
        frpc_started=True,
        frpc_running=False,
        frpc_exit_code=None,
        frpc_started_at=core.now_iso(),
        frpc_last_exit_at=None,
        frpc_last_error=None,
        frpc_last_log=None,
    )
    threading.Thread(
        target=core._supervise_frpc,
        args=(process, settings),
        daemon=True,
    ).start()
    return process


def certificate_warning(certificate: dict[str, Any]) -> dict[str, Any]:
    if not certificate.get("valid"):
        return {
            "level": "critical",
            "renewal_recommended": True,
            "message": certificate.get("error") or "Certificate is invalid.",
        }
    days = certificate.get("days_remaining")
    if days is None:
        return {
            "level": "unknown",
            "renewal_recommended": False,
            "message": "Certificate expiry could not be determined.",
        }
    if days < 15:
        return {
            "level": "red",
            "renewal_recommended": True,
            "message": f"Certificate renewal is urgent: {days} days remaining.",
        }
    if days <= 30:
        return {
            "level": "yellow",
            "renewal_recommended": True,
            "message": f"Plan certificate renewal soon: {days} days remaining.",
        }
    return {
        "level": "green",
        "renewal_recommended": False,
        "message": f"Certificate is healthy: {days} days remaining.",
    }


def _seconds_since(value: str | None) -> int | None:
    if not value:
        return None
    try:
        started = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, int((datetime.now(timezone.utc) - started).total_seconds()))


def _public_upstream_stats(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    raw_stats = snapshot.get("upstream_stats", {})
    results: list[dict[str, Any]] = []
    for endpoint in UPSTREAMS:
        stats = dict(raw_stats.get(endpoint.key, {}))
        samples = int(stats.get("latency_samples", 0))
        total = float(stats.get("latency_total_ms", 0.0))
        last_success = stats.get("last_success_at")
        last_failure = stats.get("last_failure_at")
        if not stats.get("attempts"):
            state = "unknown"
        elif last_failure and (not last_success or last_failure > last_success):
            state = "degraded"
        else:
            state = "healthy"
        results.append(
            {
                "endpoint": endpoint.key,
                "state": state,
                "attempts": int(stats.get("attempts", 0)),
                "successes": int(stats.get("successes", 0)),
                "failures": int(stats.get("failures", 0)),
                "timeouts": int(stats.get("timeouts", 0)),
                "last_latency_ms": stats.get("last_latency_ms"),
                "average_latency_ms": round(total / samples, 2) if samples else None,
                "last_success_at": last_success,
                "last_failure_at": last_failure,
                "last_error_type": stats.get("last_error_type"),
            }
        )
    return results


def _upstream_overall_state(upstreams: list[dict[str, Any]]) -> str:
    states = {item["state"] for item in upstreams}
    if states == {"unknown"}:
        return "unknown"
    if "healthy" in states and "degraded" in states:
        return "degraded"
    if "healthy" in states:
        return "healthy"
    if "degraded" in states:
        return "failed"
    return "unknown"


def _diagnostics(
    payload: dict[str, Any],
    telemetry: dict[str, Any],
    upstream_state: str,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    warning = payload["certificate"]["warning"]
    if warning["level"] in {"critical", "red", "yellow"}:
        findings.append(
            {
                "severity": "critical" if warning["level"] == "critical" else "warning",
                "code": "certificate_renewal",
                "message": warning["message"],
            }
        )

    frpc_state = payload["checks"]["frpc"]
    if frpc_state not in {"running", "disabled"}:
        findings.append(
            {
                "severity": "critical" if frpc_state in {"exited", "startup-failed"} else "warning",
                "code": "frpc_state",
                "message": f"FRPC state is {frpc_state}.",
            }
        )

    if upstream_state == "failed":
        findings.append(
            {
                "severity": "critical",
                "code": "all_upstreams_failed",
                "message": "All configured upstream resolvers are currently degraded.",
            }
        )
    elif upstream_state == "degraded":
        findings.append(
            {
                "severity": "warning",
                "code": "upstream_degraded",
                "message": "At least one upstream resolver is degraded; automatic failover remains available.",
            }
        )

    if telemetry["dns_errors"]:
        findings.append(
            {
                "severity": "warning",
                "code": "dns_errors",
                "message": f"{telemetry['dns_errors']} DNS processing errors have been recorded.",
            }
        )

    if not findings:
        findings.append(
            {
                "severity": "ok",
                "code": "healthy",
                "message": "All monitored systems are healthy.",
            }
        )
    return findings


def status_payload(settings: core.Settings = core.SETTINGS) -> dict[str, Any]:
    payload = _original_status_payload(settings)
    snapshot = core.runtime_snapshot()
    with core.RUNTIME_LOCK:
        samples = int(core.RUNTIME.get("upstream_latency_samples", 0))
        total = float(core.RUNTIME.get("upstream_latency_total_ms", 0.0))
        telemetry = {
            "dns_queries": int(core.RUNTIME.get("dns_queries", 0)),
            "dns_errors": int(core.RUNTIME.get("dns_errors", 0)),
            "dns_error_types": dict(core.RUNTIME.get("dns_error_types", {})),
            "client_disconnects": int(core.RUNTIME.get("client_disconnects", 0)),
            "active_connections": int(core.RUNTIME.get("active_connections", 0)),
            "peak_connections": int(core.RUNTIME.get("peak_connections", 0)),
            "last_query_at": core.RUNTIME.get("last_query_at"),
            "upstream_last_used": core.RUNTIME.get("upstream_last_used"),
            "upstream_failovers": int(core.RUNTIME.get("upstream_failovers", 0)),
            "upstream_last_latency_ms": core.RUNTIME.get("upstream_last_latency_ms"),
            "upstream_average_latency_ms": round(total / samples, 2) if samples else None,
            "upstream_samples": samples,
            "upstream_last_success_at": core.RUNTIME.get("upstream_last_success_at"),
            "upstream_last_failure_at": core.RUNTIME.get("upstream_last_failure_at"),
        }

    upstreams = _public_upstream_stats(snapshot)
    upstream_state = _upstream_overall_state(upstreams)
    payload["certificate"] = dict(payload["certificate"])
    payload["certificate"]["warning"] = certificate_warning(payload["certificate"])
    payload["metrics"].update(telemetry)
    payload["metrics"]["upstreams"] = upstreams
    payload["checks"]["upstream"] = upstream_state
    payload["frpc"].pop("last_log", None)
    payload["frpc"]["session_seconds"] = (
        _seconds_since(payload["frpc"].get("started_at"))
        if payload["frpc"].get("state") == "running"
        else None
    )
    payload["endpoints"]["upstream_resolver"] = f"{len(UPSTREAMS)} configured resolvers"
    payload["configuration"].update(
        {
            "tls_secret_format": "base64" if os_environ_has_base64() else "pem",
            "runtime_logging": "disabled",
            "upstream_servers": [endpoint.key for endpoint in UPSTREAMS],
            "upstream_strategy": UPSTREAM_STRATEGY,
            "upstream_timeout_seconds": UPSTREAM_TIMEOUT_SECONDS,
        }
    )
    payload["diagnostics"] = _diagnostics(payload, telemetry, upstream_state)
    return payload


def os_environ_has_base64() -> bool:
    return bool(os.getenv("DOT_CERT_B64") and os.getenv("DOT_KEY_B64"))


def quiet_http_log(_self: Any, _fmt: str, *_args: Any) -> None:
    return None


_ensure_telemetry_state()
core.reset_runtime = reset_runtime
core.forward_dns_query = forward_dns_query
core.handle_dot = handle_dot
core.start_frpc = quiet_start_frpc
core.status_payload = status_payload
core.DashboardHandler.log_message = quiet_http_log
core.DashboardHandler.server_version = "DnsDashboard/2.2"


if __name__ == "__main__":
    core.main()
