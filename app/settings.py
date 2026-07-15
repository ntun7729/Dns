#!/usr/bin/env python3
"""DNS-over-TLS service configuration and constants."""

from __future__ import annotations

import ipaddress
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
STATIC_ROOT = ROOT / "static"

HAGEZI_LIGHT_URL = (
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt"
)
BLOCKLIST_PRESETS: dict[str, dict[str, str | None]] = {
    "off": {"name": "Off", "url": None},
    "hagezi_light": {"name": "HaGeZi Light", "url": HAGEZI_LIGHT_URL},
}
RAW_GITHUB_HOST = "raw.githubusercontent.com"
SUPPORTED_UPSTREAM_STRATEGIES = {"primary_failover", "round_robin"}
ERROR_TYPES = (
    "upstream_timeout",
    "upstream_socket",
    "malformed_message",
    "internal_error",
)

MAX_DNS_MESSAGE_BYTES = 65535
MAX_CONTROL_BODY_BYTES = 2 * 1024 * 1024
MAX_PRESET_BLOCKLIST_BYTES = 24 * 1024 * 1024
MAX_CUSTOM_BLOCKLIST_BYTES = 12 * 1024 * 1024
MAX_BLOCKLIST_DOMAINS_PER_SOURCE = 1_000_000
MAX_TOTAL_ACTIVE_BLOCKLIST_DOMAINS = 2_000_000
MAX_PROFILES = 20
MAX_MANUAL_DOMAINS = 5000
MAX_CUSTOM_SOURCES = 5
MAX_UPSTREAMS = 8

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)
_CERTIFICATE_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)
_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(
    name: str,
    default: int,
    *,
    minimum: int = 1,
    maximum: int = 65535,
) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer; got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise SystemExit(f"{name} must be between {minimum} and {maximum}; got {value}")
    return value


def env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a number; got {raw!r}") from exc
    if value < minimum:
        raise SystemExit(f"{name} must be at least {minimum}; got {value}")
    return value


@dataclass(frozen=True)
class UpstreamEndpoint:
    host: str
    port: int

    @property
    def key(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


def parse_upstream_servers(
    value: str | None,
    *,
    fallback_host: str = "1.1.1.1",
    fallback_port: int = 53,
) -> tuple[UpstreamEndpoint, ...]:
    """Parse comma/newline separated host[:port] values, including IPv6."""
    raw_items = [
        item.strip()
        for item in (value or "").replace("\n", ",").split(",")
        if item.strip()
    ]
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
                if not remainder.startswith(":") or not remainder[1:]:
                    raise ValueError(f"Invalid upstream address: {item}")
                try:
                    port = int(remainder[1:])
                except ValueError as exc:
                    raise ValueError(f"Invalid upstream port: {item}") from exc
        elif item.count(":") == 1:
            host, raw_port = item.rsplit(":", 1)
            try:
                port = int(raw_port)
            except ValueError as exc:
                raise ValueError(f"Invalid upstream port: {item}") from exc
        elif item.count(":") > 1:
            try:
                ipaddress.IPv6Address(item)
            except ValueError as exc:
                raise ValueError(
                    "IPv6 upstreams with an explicit port must use [address]:port."
                ) from exc
            host = item

        host = host.strip().rstrip(".")
        if not host or not 1 <= port <= 65535:
            raise ValueError(f"Invalid upstream resolver: {item}")
        endpoint = UpstreamEndpoint(host, port)
        if endpoint.key not in seen:
            endpoints.append(endpoint)
            seen.add(endpoint.key)

    if not endpoints:
        raise ValueError("At least one upstream resolver is required.")
    if len(endpoints) > MAX_UPSTREAMS:
        raise ValueError(f"A maximum of {MAX_UPSTREAMS} upstream resolvers is supported.")
    return tuple(endpoints)


@dataclass(frozen=True)
class Settings:
    service_name: str = "DNS Dashboard"
    app_env: str = "development"
    port: int = 10000
    bind_host: str = "0.0.0.0"
    dot_enabled: bool = True
    dot_bind_host: str = "127.0.0.1"
    dot_port: int = 8853
    dot_public_hostname: str = ""
    dot_cert_pem: str = ""
    dot_key_pem: str = ""
    dot_cert_file: str = "/tmp/dns-dashboard/tls.crt"
    dot_key_file: str = "/tmp/dns-dashboard/tls.key"
    upstreams: tuple[UpstreamEndpoint, ...] = field(
        default_factory=lambda: (UpstreamEndpoint("1.1.1.1", 53),)
    )
    upstream_strategy: str = "primary_failover"
    upstream_timeout_seconds: float = 2.0
    resolver_cooldown_seconds: float = 15.0
    resolver_cooldown_max_seconds: float = 120.0
    frpc_enabled: bool = True
    frp_server_addr: str = ""
    frp_server_port: int = 7000
    frp_auth_token: str = ""
    frp_remote_port: int = 853
    frpc_binary: str = "/usr/local/bin/frpc"
    frpc_config_file: str = "/tmp/dns-dashboard/frpc.toml"
    frpc_startup_grace_seconds: float = 1.5
    history_minutes: int = 120
    filter_update_hours: int = 24
    dashboard_username: str = ""
    dashboard_password: str = ""
    initial_filter_enabled: bool = False
    initial_filter_preset: str = "off"
    initial_manual_block: str = ""
    initial_allow: str = ""
    initial_custom_sources: str = ""
    profiles_file: str = ""

    @classmethod
    def from_env(cls) -> "Settings":
        fallback_host = os.getenv("UPSTREAM_DNS", "1.1.1.1").strip() or "1.1.1.1"
        fallback_port = env_int("UPSTREAM_DNS_PORT", 53)
        try:
            upstreams = parse_upstream_servers(
                os.getenv("UPSTREAM_DNS_SERVERS"),
                fallback_host=fallback_host,
                fallback_port=fallback_port,
            )
        except ValueError as exc:
            raise SystemExit(f"UPSTREAM_DNS_SERVERS is invalid: {exc}") from exc

        strategy = os.getenv("UPSTREAM_STRATEGY", "primary_failover").strip().lower()
        if strategy not in SUPPORTED_UPSTREAM_STRATEGIES:
            raise SystemExit(
                "UPSTREAM_STRATEGY must be primary_failover or round_robin."
            )

        preset = os.getenv("BLOCKLIST_PRESET", "off").strip().lower() or "off"
        if preset not in BLOCKLIST_PRESETS:
            raise SystemExit(f"Unsupported BLOCKLIST_PRESET: {preset}")

        return cls(
            service_name=os.getenv("SERVICE_NAME", "DNS Dashboard").strip()
            or "DNS Dashboard",
            app_env=os.getenv("APP_ENV", "development").strip().lower()
            or "development",
            port=env_int("PORT", 10000),
            bind_host=os.getenv("BIND_HOST", "0.0.0.0").strip() or "0.0.0.0",
            dot_enabled=env_bool("DOT_ENABLED", True),
            dot_bind_host=os.getenv("DOT_BIND_HOST", "127.0.0.1").strip()
            or "127.0.0.1",
            dot_port=env_int("DOT_PORT", 8853),
            dot_public_hostname=os.getenv("DOT_PUBLIC_HOSTNAME", "")
            .strip()
            .rstrip("."),
            dot_cert_pem=os.getenv("DOT_CERT_PEM", ""),
            dot_key_pem=os.getenv("DOT_KEY_PEM", ""),
            dot_cert_file=os.getenv(
                "DOT_CERT_FILE", "/tmp/dns-dashboard/tls.crt"
            ).strip(),
            dot_key_file=os.getenv(
                "DOT_KEY_FILE", "/tmp/dns-dashboard/tls.key"
            ).strip(),
            upstreams=upstreams,
            upstream_strategy=strategy,
            upstream_timeout_seconds=env_float(
                "UPSTREAM_TIMEOUT_SECONDS", 2.0, minimum=0.2
            ),
            resolver_cooldown_seconds=env_float(
                "RESOLVER_COOLDOWN_SECONDS", 15.0, minimum=0.0
            ),
            resolver_cooldown_max_seconds=env_float(
                "RESOLVER_COOLDOWN_MAX_SECONDS", 120.0, minimum=1.0
            ),
            frpc_enabled=env_bool("FRPC_ENABLED", True),
            frp_server_addr=os.getenv("FRP_SERVER_ADDR", "").strip(),
            frp_server_port=env_int("FRP_SERVER_PORT", 7000),
            frp_auth_token=os.getenv("FRP_AUTH_TOKEN", "").strip(),
            frp_remote_port=env_int("FRP_REMOTE_PORT", 853),
            frpc_binary=os.getenv("FRPC_BINARY", "/usr/local/bin/frpc").strip(),
            frpc_config_file=os.getenv(
                "FRPC_CONFIG_FILE", "/tmp/dns-dashboard/frpc.toml"
            ).strip(),
            frpc_startup_grace_seconds=env_float(
                "FRPC_STARTUP_GRACE_SECONDS", 1.5, minimum=0.05
            ),
            history_minutes=env_int(
                "HISTORY_MINUTES", 120, minimum=15, maximum=1440
            ),
            filter_update_hours=env_int(
                "FILTER_UPDATE_HOURS", 24, minimum=1, maximum=168
            ),
            dashboard_username=os.getenv("DASHBOARD_USERNAME", "").strip(),
            dashboard_password=os.getenv("DASHBOARD_PASSWORD", ""),
            initial_filter_enabled=env_bool("FILTER_ENABLED", False),
            initial_filter_preset=preset,
            initial_manual_block=os.getenv("MANUAL_BLOCK_DOMAINS", ""),
            initial_allow=os.getenv("ALLOW_DOMAINS", ""),
            initial_custom_sources=os.getenv("CUSTOM_BLOCKLIST_URLS", ""),
            profiles_file=os.getenv("PROFILES_FILE", "").strip(),
        )

    @property
    def production(self) -> bool:
        return self.app_env in {"prod", "production"}

    @property
    def auth_enabled(self) -> bool:
        return bool(self.dashboard_username and self.dashboard_password)

    @property
    def frpc_configured(self) -> bool:
        return bool(self.frp_server_addr)

    @property
    def frp_auth_mode(self) -> str:
        return "token" if self.frp_auth_token else "none"

    def public_config(self) -> dict[str, Any]:
        return {
            "app_env": self.app_env,
            "production": self.production,
            "dot_enabled": self.dot_enabled,
            "dot_bind_host": self.dot_bind_host,
            "dot_port": self.dot_port,
            "dot_public_hostname": self.dot_public_hostname or None,
            "frpc_enabled": self.frpc_enabled,
            "frp_server_addr": self.frp_server_addr or None,
            "frp_server_port": self.frp_server_port,
            "frp_remote_port": self.frp_remote_port,
            "frp_auth_mode": self.frp_auth_mode,
            "upstream_servers": [endpoint.key for endpoint in self.upstreams],
            "upstream_strategy": self.upstream_strategy,
            "upstream_timeout_seconds": self.upstream_timeout_seconds,
            "resolver_cooldown_seconds": self.resolver_cooldown_seconds,
            "history_minutes": self.history_minutes,
            "runtime_controls": "memory-only",
            "runtime_logging": "disabled",
            "tls_secret_format": (
                "base64"
                if os.getenv("DOT_CERT_B64") and os.getenv("DOT_KEY_B64")
                else "pem"
            ),
        }


def now_iso(timestamp: float | None = None) -> str:
    value = time.time() if timestamp is None else timestamp
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
