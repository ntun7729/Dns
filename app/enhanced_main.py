#!/usr/bin/env python3
"""Operational telemetry extensions for the DNS Dashboard."""

from __future__ import annotations

import asyncio
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

import main as core

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ERROR_TYPES = (
    "upstream_timeout",
    "upstream_socket",
    "malformed_message",
    "internal_error",
)

_original_reset_runtime = core.reset_runtime
_original_status_payload = core.status_payload


def _telemetry_defaults() -> dict[str, Any]:
    return {
        "dns_error_types": {name: 0 for name in ERROR_TYPES},
        "client_disconnects": 0,
        "active_connections": 0,
        "peak_connections": 0,
        "upstream_last_latency_ms": None,
        "upstream_latency_total_ms": 0.0,
        "upstream_latency_samples": 0,
        "upstream_last_success_at": None,
        "upstream_last_failure_at": None,
    }


def _ensure_telemetry_state() -> None:
    with core.RUNTIME_LOCK:
        defaults = _telemetry_defaults()
        for key, value in defaults.items():
            if key not in core.RUNTIME:
                core.RUNTIME[key] = value
        if not isinstance(core.RUNTIME.get("dns_error_types"), dict):
            core.RUNTIME["dns_error_types"] = defaults["dns_error_types"]


def reset_runtime() -> None:
    _original_reset_runtime()
    with core.RUNTIME_LOCK:
        core.RUNTIME.update(_telemetry_defaults())


def strip_ansi(value: str | None) -> str | None:
    if not value:
        return value
    return ANSI_ESCAPE_RE.sub("", value).strip()


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


def _record_upstream_success(latency_ms: float) -> None:
    with core.RUNTIME_LOCK:
        core.RUNTIME["upstream_last_latency_ms"] = round(latency_ms, 2)
        core.RUNTIME["upstream_latency_total_ms"] = float(
            core.RUNTIME.get("upstream_latency_total_ms", 0.0)
        ) + latency_ms
        core.RUNTIME["upstream_latency_samples"] = int(
            core.RUNTIME.get("upstream_latency_samples", 0)
        ) + 1
        core.RUNTIME["upstream_last_success_at"] = core.now_iso()


def _record_dns_error(kind: str, message: str) -> None:
    with core.RUNTIME_LOCK:
        error_types = dict(core.RUNTIME.get("dns_error_types", {}))
        error_types[kind] = int(error_types.get(kind, 0)) + 1
        core.RUNTIME["dns_error_types"] = error_types
        core.RUNTIME["dns_errors"] = int(core.RUNTIME.get("dns_errors", 0)) + 1
        core.RUNTIME["dot_last_error"] = message
        if kind in {"upstream_timeout", "upstream_socket"}:
            core.RUNTIME["upstream_last_failure_at"] = core.now_iso()


async def forward_dns_query(payload: bytes, settings: core.Settings) -> bytes:
    loop = asyncio.get_running_loop()
    started = time.perf_counter()

    def send_udp() -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(payload, (settings.upstream_dns, settings.upstream_dns_port))
            response, _ = sock.recvfrom(4096)
            return response

    response = await loop.run_in_executor(None, send_udp)
    _record_upstream_success((time.perf_counter() - started) * 1000)
    return response


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
        print(f"[dot] query error: {safe_error}", flush=True)
    finally:
        _record_connection_delta(-1)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


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


def _diagnostics(
    payload: dict[str, Any], telemetry: dict[str, Any]
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

    if telemetry["dns_errors"]:
        findings.append(
            {
                "severity": "warning",
                "code": "dns_errors",
                "message": f"{telemetry['dns_errors']} DNS processing errors have been recorded.",
            }
        )

    last_failure = telemetry.get("upstream_last_failure_at")
    last_success = telemetry.get("upstream_last_success_at")
    if last_failure and (not last_success or last_failure > last_success):
        findings.append(
            {
                "severity": "warning",
                "code": "upstream_failure",
                "message": "The most recent upstream DNS attempt failed.",
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
            "upstream_last_latency_ms": core.RUNTIME.get("upstream_last_latency_ms"),
            "upstream_average_latency_ms": round(total / samples, 2) if samples else None,
            "upstream_samples": samples,
            "upstream_last_success_at": core.RUNTIME.get("upstream_last_success_at"),
            "upstream_last_failure_at": core.RUNTIME.get("upstream_last_failure_at"),
        }

    payload["certificate"] = dict(payload["certificate"])
    payload["certificate"]["warning"] = certificate_warning(payload["certificate"])
    payload["metrics"].update(telemetry)
    payload["frpc"]["last_log"] = strip_ansi(payload["frpc"].get("last_log"))
    payload["frpc"]["session_seconds"] = (
        _seconds_since(payload["frpc"].get("started_at"))
        if payload["frpc"].get("state") == "running"
        else None
    )
    payload["configuration"]["tls_secret_format"] = (
        "base64" if os_environ_has_base64() else "pem"
    )
    payload["diagnostics"] = _diagnostics(payload, telemetry)
    return payload


def os_environ_has_base64() -> bool:
    return bool(os.getenv("DOT_CERT_B64") and os.getenv("DOT_KEY_B64"))


_ensure_telemetry_state()
core.reset_runtime = reset_runtime
core.forward_dns_query = forward_dns_query
core.handle_dot = handle_dot
core.status_payload = status_payload
core.DashboardHandler.server_version = "DnsDashboard/2.1"


if __name__ == "__main__":
    core.main()
