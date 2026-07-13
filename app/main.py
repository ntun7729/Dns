#!/usr/bin/env python3
"""Render DNS dashboard, DNS-over-TLS listener, and FRPC supervisor."""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
STATIC_ROOT = ROOT / "static"
STARTED_AT = time.time()
RUNTIME_LOCK = threading.Lock()
RUNTIME: dict[str, Any] = {
    "dot_state": "not-started",
    "dot_last_error": None,
    "dns_queries": 0,
    "dns_errors": 0,
    "last_query_at": None,
    "frpc_state": "not-started",
    "frpc_started": False,
    "frpc_running": False,
    "frpc_exit_code": None,
    "frpc_started_at": None,
    "frpc_last_exit_at": None,
    "frpc_last_error": None,
    "frpc_last_log": None,
    "certificate": {
        "source": "missing",
        "configured": False,
        "valid": False,
        "hostname_match": False,
        "key_match": False,
        "expired": False,
        "not_yet_valid": False,
        "not_before": None,
        "expires_at": None,
        "days_remaining": None,
        "error": "Certificate has not been loaded.",
    },
}

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)
_CERTIFICATE_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, *, minimum: int = 1, maximum: int = 65535) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer; got {raw!r}") from exc
    if value < minimum or value > maximum:
        raise SystemExit(f"{name} must be between {minimum} and {maximum}; got {value}")
    return value


def env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a number; got {raw!r}") from exc
    if value < minimum:
        raise SystemExit(f"{name} must be at least {minimum}; got {value}")
    return value


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
    upstream_dns: str = "1.1.1.1"
    upstream_dns_port: int = 53
    frpc_enabled: bool = True
    frp_server_addr: str = ""
    frp_server_port: int = 7000
    frp_auth_token: str = ""
    frp_remote_port: int = 853
    frpc_binary: str = "/usr/local/bin/frpc"
    frpc_config_file: str = "/tmp/dns-dashboard/frpc.toml"
    frpc_startup_grace_seconds: float = 1.5

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            service_name=os.getenv("SERVICE_NAME", "DNS Dashboard").strip() or "DNS Dashboard",
            app_env=os.getenv("APP_ENV", "development").strip().lower() or "development",
            port=env_int("PORT", 10000),
            bind_host=os.getenv("BIND_HOST", "0.0.0.0").strip() or "0.0.0.0",
            dot_enabled=env_bool("DOT_ENABLED", True),
            dot_bind_host=os.getenv("DOT_BIND_HOST", "127.0.0.1").strip() or "127.0.0.1",
            dot_port=env_int("DOT_PORT", 8853),
            dot_public_hostname=os.getenv("DOT_PUBLIC_HOSTNAME", "").strip().rstrip("."),
            dot_cert_pem=os.getenv("DOT_CERT_PEM", ""),
            dot_key_pem=os.getenv("DOT_KEY_PEM", ""),
            dot_cert_file=os.getenv("DOT_CERT_FILE", "/tmp/dns-dashboard/tls.crt").strip(),
            dot_key_file=os.getenv("DOT_KEY_FILE", "/tmp/dns-dashboard/tls.key").strip(),
            upstream_dns=os.getenv("UPSTREAM_DNS", "1.1.1.1").strip() or "1.1.1.1",
            upstream_dns_port=env_int("UPSTREAM_DNS_PORT", 53),
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
        )

    @property
    def production(self) -> bool:
        return self.app_env in {"prod", "production"}

    @property
    def frpc_configured(self) -> bool:
        return bool(self.frp_server_addr)

    @property
    def frp_auth_mode(self) -> str:
        return "token" if self.frp_auth_token else "none"

    def public_config(self) -> dict[str, Any]:
        """Return only non-secret configuration suitable for APIs and the UI."""
        return {
            "app_env": self.app_env,
            "production": self.production,
            "dot_enabled": self.dot_enabled,
            "dot_bind_host": self.dot_bind_host,
            "dot_port": self.dot_port,
            "dot_public_hostname": self.dot_public_hostname or None,
            "upstream_dns": self.upstream_dns,
            "upstream_dns_port": self.upstream_dns_port,
            "frpc_enabled": self.frpc_enabled,
            "frp_server_addr": self.frp_server_addr or None,
            "frp_server_port": self.frp_server_port,
            "frp_remote_port": self.frp_remote_port,
            "frp_auth_mode": self.frp_auth_mode,
        }


@dataclass(frozen=True)
class CertificateStatus:
    source: str = "missing"
    configured: bool = False
    valid: bool = False
    hostname_match: bool = False
    key_match: bool = False
    expired: bool = False
    not_yet_valid: bool = False
    not_before: str | None = None
    expires_at: str | None = None
    days_remaining: int | None = None
    error: str | None = None

    def as_public(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "configured": self.configured,
            "valid": self.valid,
            "hostname_match": self.hostname_match,
            "key_match": self.key_match,
            "expired": self.expired,
            "not_yet_valid": self.not_yet_valid,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "days_remaining": self.days_remaining,
            "error": self.error,
        }


SETTINGS = Settings.from_env()


def now_iso(timestamp: float | None = None) -> str:
    value = time.time() if timestamp is None else timestamp
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def set_runtime(**values: Any) -> None:
    with RUNTIME_LOCK:
        RUNTIME.update(values)


def runtime_snapshot() -> dict[str, Any]:
    with RUNTIME_LOCK:
        snapshot = dict(RUNTIME)
        snapshot["certificate"] = dict(RUNTIME["certificate"])
        return snapshot


def reset_runtime() -> None:
    """Reset process state. Primarily useful for deterministic tests."""
    with RUNTIME_LOCK:
        RUNTIME.update(
            {
                "dot_state": "not-started",
                "dot_last_error": None,
                "dns_queries": 0,
                "dns_errors": 0,
                "last_query_at": None,
                "frpc_state": "not-started",
                "frpc_started": False,
                "frpc_running": False,
                "frpc_exit_code": None,
                "frpc_started_at": None,
                "frpc_last_exit_at": None,
                "frpc_last_error": None,
                "frpc_last_log": None,
                "certificate": CertificateStatus(
                    error="Certificate has not been loaded."
                ).as_public(),
            }
        )


def redact_text(text: str, settings: Settings) -> str:
    """Remove configured secrets and PEM blocks before logging or returning text."""
    redacted = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    redacted = _CERTIFICATE_RE.sub("[REDACTED CERTIFICATE]", redacted)
    redacted = re.sub(
        r"(?im)^\s*auth\.token\s*=\s*.*$",
        'auth.token = "[REDACTED]"',
        redacted,
    )

    secrets = (settings.frp_auth_token, settings.dot_key_pem, settings.dot_cert_pem)
    for secret in secrets:
        if not secret:
            continue
        redacted = redacted.replace(secret, "[REDACTED]")
        for line in normalize_pem(secret).splitlines():
            if len(line) >= 16:
                redacted = redacted.replace(line, "[REDACTED]")
    return redacted


def normalize_pem(value: str) -> str:
    """Normalize multiline Render secrets without flattening PEM boundaries."""
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if "\n" not in normalized and "\\n" in normalized:
        normalized = normalized.replace("\\n", "\n")
    return normalized + "\n" if normalized else ""


def secure_write(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except PermissionError:
        pass

    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def valid_dns_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = ascii_hostname.rstrip(".").split(".")
    label_pattern = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    return len(labels) >= 2 and all(label_pattern.fullmatch(label) for label in labels)


def _dns_pattern_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    if "*" not in pattern:
        return pattern == hostname
    pattern_labels = pattern.split(".")
    hostname_labels = hostname.split(".")
    return (
        pattern_labels[0] == "*"
        and all("*" not in label for label in pattern_labels[1:])
        and len(pattern_labels) == len(hostname_labels)
        and pattern_labels[1:] == hostname_labels[1:]
        and bool(hostname_labels[0])
    )


def certificate_matches_hostname(cert_info: dict[str, Any], hostname: str) -> bool:
    dns_names = [
        value
        for kind, value in cert_info.get("subjectAltName", ())
        if kind == "DNS"
    ]
    if dns_names:
        return any(_dns_pattern_matches(pattern, hostname) for pattern in dns_names)

    common_names: list[str] = []
    for relative_distinguished_name in cert_info.get("subject", ()):
        for key, value in relative_distinguished_name:
            if key == "commonName":
                common_names.append(value)
    return any(_dns_pattern_matches(pattern, hostname) for pattern in common_names)


def validate_certificate_files(
    cert_path: Path,
    key_path: Path,
    hostname: str,
    *,
    source: str,
    now: float | None = None,
) -> CertificateStatus:
    current_time = time.time() if now is None else now
    errors: list[str] = []
    key_match = False
    hostname_match = False
    expired = False
    not_yet_valid = False
    not_before_iso: str | None = None
    expires_at_iso: str | None = None
    days_remaining: int | None = None

    if not valid_dns_hostname(hostname):
        errors.append("DOT_PUBLIC_HOSTNAME is missing or is not a valid DNS hostname.")

    if not cert_path.is_file() or not key_path.is_file():
        errors.append("Certificate or private-key file is missing.")
        return CertificateStatus(
            source=source,
            configured=False,
            error=" ".join(errors),
        )

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        key_match = True
    except (OSError, ssl.SSLError, ValueError) as exc:
        errors.append(f"Certificate and private key could not be loaded together: {exc}")

    cert_info: dict[str, Any] = {}
    try:
        cert_info = ssl._ssl._test_decode_cert(str(cert_path))  # type: ignore[attr-defined]
    except (OSError, ssl.SSLError, ValueError) as exc:
        errors.append(f"Certificate could not be decoded: {exc}")

    if cert_info and valid_dns_hostname(hostname):
        hostname_match = certificate_matches_hostname(cert_info, hostname)
        if not hostname_match:
            errors.append(f"Certificate does not match {hostname}.")

    not_before = cert_info.get("notBefore") if cert_info else None
    not_after = cert_info.get("notAfter") if cert_info else None
    try:
        if not_before:
            not_before_timestamp = ssl.cert_time_to_seconds(not_before)
            not_before_iso = now_iso(not_before_timestamp)
            not_yet_valid = current_time < not_before_timestamp
            if not_yet_valid:
                errors.append("Certificate is not valid yet.")
        if not_after:
            expiry_timestamp = ssl.cert_time_to_seconds(not_after)
            expires_at_iso = now_iso(expiry_timestamp)
            expired = current_time >= expiry_timestamp
            days_remaining = max(0, int((expiry_timestamp - current_time) // 86400))
            if expired:
                errors.append("Certificate has expired.")
        else:
            errors.append("Certificate expiry could not be determined.")
    except (TypeError, ValueError, OverflowError) as exc:
        errors.append(f"Certificate validity dates could not be parsed: {exc}")

    valid = key_match and hostname_match and not expired and not not_yet_valid and not errors
    return CertificateStatus(
        source=source,
        configured=True,
        valid=valid,
        hostname_match=hostname_match,
        key_match=key_match,
        expired=expired,
        not_yet_valid=not_yet_valid,
        not_before=not_before_iso,
        expires_at=expires_at_iso,
        days_remaining=days_remaining,
        error=" ".join(errors) or None,
    )


def generate_development_certificate(settings: Settings) -> None:
    hostname = settings.dot_public_hostname or "dns-dashboard.local"
    cert_path = Path(settings.dot_cert_file)
    key_path = Path(settings.dot_key_file)
    cert_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    command = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "30",
        "-subj",
        f"/CN={hostname}",
        "-addext",
        f"subjectAltName=DNS:{hostname}",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
    ]
    subprocess.run(
        command,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    cert_path.chmod(0o600)
    key_path.chmod(0o600)


def prepare_tls_material(settings: Settings, *, now: float | None = None) -> CertificateStatus:
    cert_path = Path(settings.dot_cert_file)
    key_path = Path(settings.dot_key_file)
    has_cert_env = bool(settings.dot_cert_pem.strip())
    has_key_env = bool(settings.dot_key_pem.strip())

    if has_cert_env or has_key_env:
        if not (has_cert_env and has_key_env):
            return CertificateStatus(
                source="environment",
                configured=False,
                error="DOT_CERT_PEM and DOT_KEY_PEM must both be provided.",
            )
        try:
            secure_write(cert_path, normalize_pem(settings.dot_cert_pem), 0o600)
            secure_write(key_path, normalize_pem(settings.dot_key_pem), 0o600)
        except OSError as exc:
            return CertificateStatus(
                source="environment",
                configured=False,
                error=f"TLS files could not be written securely: {exc}",
            )
        source = "environment"
    elif settings.production:
        return CertificateStatus(
            source="missing",
            configured=False,
            error="Production requires DOT_CERT_PEM and DOT_KEY_PEM.",
        )
    elif cert_path.exists() or key_path.exists():
        source = "file"
    else:
        try:
            generate_development_certificate(settings)
        except (OSError, subprocess.CalledProcessError) as exc:
            return CertificateStatus(
                source="self-signed",
                configured=False,
                error=f"Development certificate generation failed: {exc}",
            )
        source = "self-signed"

    hostname = settings.dot_public_hostname or (
        "dns-dashboard.local" if not settings.production else ""
    )
    return validate_certificate_files(
        cert_path,
        key_path,
        hostname,
        source=source,
        now=now,
    )


def toml_string(value: str) -> str:
    return json.dumps(value)


def frpc_config(settings: Settings) -> str:
    lines = [
        f"serverAddr = {toml_string(settings.frp_server_addr)}",
        f"serverPort = {settings.frp_server_port}",
        "",
    ]
    if settings.frp_auth_token:
        lines.extend(
            [
                'auth.method = "token"',
                f"auth.token = {toml_string(settings.frp_auth_token)}",
                "",
            ]
        )
    lines.extend(
        [
            "[[proxies]]",
            'name = "dns-over-tls"',
            'type = "tcp"',
            f"localIP = {toml_string(settings.dot_bind_host)}",
            f"localPort = {settings.dot_port}",
            f"remotePort = {settings.frp_remote_port}",
            "",
        ]
    )
    return "\n".join(lines)


def write_frpc_config(settings: Settings) -> Path | None:
    if not settings.frpc_enabled or not settings.frpc_configured:
        return None
    path = Path(settings.frpc_config_file)
    secure_write(path, frpc_config(settings), 0o600)
    return path


def _capture_frpc_output(process: subprocess.Popen[str], settings: Settings) -> None:
    if process.stdout is None:
        return
    try:
        for line in process.stdout:
            safe_line = redact_text(line.strip(), settings)
            if safe_line:
                set_runtime(frpc_last_log=safe_line)
                print(f"[frpc] {safe_line}", flush=True)
    finally:
        process.stdout.close()


def _supervise_frpc(process: subprocess.Popen[str], settings: Settings) -> None:
    try:
        code = process.wait(timeout=settings.frpc_startup_grace_seconds)
    except subprocess.TimeoutExpired:
        set_runtime(frpc_state="running", frpc_running=True, frpc_last_error=None)
        code = process.wait()
        set_runtime(
            frpc_state="exited",
            frpc_running=False,
            frpc_exit_code=code,
            frpc_last_exit_at=now_iso(),
            frpc_last_error=f"FRPC exited unexpectedly with code {code}.",
        )
        return

    set_runtime(
        frpc_state="startup-failed",
        frpc_running=False,
        frpc_exit_code=code,
        frpc_last_exit_at=now_iso(),
        frpc_last_error=f"FRPC exited during startup with code {code}.",
    )


def start_frpc(settings: Settings) -> subprocess.Popen[str] | None:
    if not settings.frpc_enabled:
        set_runtime(frpc_state="disabled", frpc_running=False, frpc_last_error=None)
        return None
    if not settings.frpc_configured:
        set_runtime(
            frpc_state="needs-config",
            frpc_running=False,
            frpc_last_error="FRP_SERVER_ADDR is required to start FRPC.",
        )
        return None

    snapshot = runtime_snapshot()
    if settings.dot_enabled and snapshot["dot_state"] != "running":
        set_runtime(
            frpc_state="blocked",
            frpc_running=False,
            frpc_last_error="FRPC was not started because the DoT listener is not ready.",
        )
        return None

    config = write_frpc_config(settings)
    assert config is not None
    try:
        process = subprocess.Popen(
            [settings.frpc_binary, "-c", str(config)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        set_runtime(
            frpc_state="startup-failed",
            frpc_running=False,
            frpc_last_error=redact_text(str(exc), settings),
        )
        return None

    set_runtime(
        frpc_state="starting",
        frpc_started=True,
        frpc_running=False,
        frpc_exit_code=None,
        frpc_started_at=now_iso(),
        frpc_last_exit_at=None,
        frpc_last_error=None,
    )
    threading.Thread(
        target=_capture_frpc_output,
        args=(process, settings),
        daemon=True,
    ).start()
    threading.Thread(
        target=_supervise_frpc,
        args=(process, settings),
        daemon=True,
    ).start()
    return process


async def forward_dns_query(payload: bytes, settings: Settings) -> bytes:
    loop = asyncio.get_running_loop()

    def send_udp() -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(payload, (settings.upstream_dns, settings.upstream_dns_port))
            response, _ = sock.recvfrom(4096)
            return response

    return await loop.run_in_executor(None, send_udp)


async def handle_dot(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    settings: Settings = SETTINGS,
) -> None:
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
            with RUNTIME_LOCK:
                RUNTIME["dns_queries"] += 1
                RUNTIME["last_query_at"] = now_iso()
    except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
        pass
    except Exception as exc:  # noqa: BLE001 - operational telemetry only.
        with RUNTIME_LOCK:
            RUNTIME["dns_errors"] += 1
            RUNTIME["dot_last_error"] = redact_text(str(exc), settings)
        print(f"[dot] query error: {redact_text(str(exc), settings)}", flush=True)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


async def run_dot_server(settings: Settings, startup_complete: threading.Event) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(settings.dot_cert_file, settings.dot_key_file)
    server = await asyncio.start_server(
        lambda reader, writer: handle_dot(reader, writer, settings),
        host=settings.dot_bind_host,
        port=settings.dot_port,
        ssl=context,
    )
    set_runtime(dot_state="running", dot_last_error=None)
    startup_complete.set()
    print(f"[dot] listening on {settings.dot_bind_host}:{settings.dot_port}", flush=True)
    async with server:
        await server.serve_forever()


def start_dot_thread(settings: Settings) -> threading.Event:
    startup_complete = threading.Event()
    if not settings.dot_enabled:
        set_runtime(dot_state="disabled", dot_last_error=None)
        startup_complete.set()
        return startup_complete

    set_runtime(dot_state="starting", dot_last_error=None)

    def runner() -> None:
        certificate = prepare_tls_material(settings)
        set_runtime(certificate=certificate.as_public())
        if not certificate.valid:
            set_runtime(
                dot_state="certificate-error",
                dot_last_error=certificate.error,
            )
            startup_complete.set()
            return
        try:
            asyncio.run(run_dot_server(settings, startup_complete))
        except Exception as exc:  # noqa: BLE001 - readiness surfaces startup failures.
            safe_error = redact_text(str(exc), settings)
            set_runtime(dot_state="failed", dot_last_error=safe_error)
            print(f"[dot] failed to start: {safe_error}", flush=True)
            startup_complete.set()

    threading.Thread(target=runner, daemon=True).start()
    return startup_complete


def readiness_payload(settings: Settings = SETTINGS) -> dict[str, Any]:
    snapshot = runtime_snapshot()
    certificate = snapshot["certificate"]
    dot_ready = not settings.dot_enabled or snapshot["dot_state"] == "running"
    certificate_ready = not settings.dot_enabled or bool(certificate.get("valid"))
    hostname_ready = not settings.production or valid_dns_hostname(
        settings.dot_public_hostname
    )
    frpc_ready = not settings.frpc_enabled or snapshot["frpc_state"] == "running"
    ready = dot_ready and certificate_ready and hostname_ready and frpc_ready
    return {
        "ready": ready,
        "public_dns_hostname": settings.dot_public_hostname or None,
        "dot_ready": dot_ready,
        "dot_state": snapshot["dot_state"],
        "frpc_ready": frpc_ready,
        "frpc_state": snapshot["frpc_state"],
        "frp_auth_mode": settings.frp_auth_mode,
        "certificate_valid": bool(certificate.get("valid")),
        "certificate_error": certificate.get("error"),
    }


def status_payload(settings: Settings = SETTINGS) -> dict[str, Any]:
    snapshot = runtime_snapshot()
    readiness = readiness_payload(settings)
    certificate = snapshot["certificate"]
    public_endpoint = (
        f"{settings.dot_public_hostname}:{settings.frp_remote_port}"
        if settings.dot_public_hostname
        else None
    )
    return {
        "service": settings.service_name,
        "time": now_iso(),
        "uptime_seconds": max(0, int(time.time() - STARTED_AT)),
        "ready": readiness["ready"],
        "public_dns_hostname": settings.dot_public_hostname or None,
        "checks": {
            "http": "healthy",
            "dot_listener": snapshot["dot_state"],
            "frpc": snapshot["frpc_state"],
            "frp_auth_mode": settings.frp_auth_mode,
            "certificate": "valid" if certificate.get("valid") else "invalid",
        },
        "certificate": certificate,
        "endpoints": {
            "http": f"{settings.bind_host}:{settings.port}",
            "dot_local": f"{settings.dot_bind_host}:{settings.dot_port}",
            "dot_public": public_endpoint,
            "frps_control": (
                f"{settings.frp_server_addr}:{settings.frp_server_port}"
                if settings.frp_server_addr
                else None
            ),
            "upstream_resolver": f"{settings.upstream_dns}:{settings.upstream_dns_port}",
        },
        "frpc": {
            "state": snapshot["frpc_state"],
            "authentication": settings.frp_auth_mode,
            "started_at": snapshot["frpc_started_at"],
            "last_exit_at": snapshot["frpc_last_exit_at"],
            "exit_code": snapshot["frpc_exit_code"],
            "last_error": snapshot["frpc_last_error"],
            "last_log": snapshot["frpc_last_log"],
        },
        "metrics": {
            "dns_queries": snapshot["dns_queries"],
            "dns_errors": snapshot["dns_errors"],
            "last_query_at": snapshot["last_query_at"],
        },
        "configuration": settings.public_config(),
    }


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "DnsDashboard/2.0"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._serve_static("index.html", "text/html; charset=utf-8")
        elif path == "/app.js":
            self._serve_static("app.js", "text/javascript; charset=utf-8")
        elif path == "/styles.css":
            self._serve_static("styles.css", "text/css; charset=utf-8")
        elif path == "/api/status":
            self._json(status_payload())
        elif path == "/healthz":
            self._json({"ok": True, "time": now_iso()})
        elif path == "/readyz":
            payload = readiness_payload()
            self._json(
                payload,
                HTTPStatus.OK if payload["ready"] else HTTPStatus.SERVICE_UNAVAILABLE,
            )
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[http] {self.address_string()} {fmt % args}", flush=True)

    def _serve_static(self, name: str, content_type: str) -> None:
        path = STATIC_ROOT / name
        try:
            body = path.read_bytes()
        except FileNotFoundError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_http(settings: Settings) -> None:
    httpd = ThreadingHTTPServer((settings.bind_host, settings.port), DashboardHandler)
    print(f"[http] listening on {settings.bind_host}:{settings.port}", flush=True)
    httpd.serve_forever()


def main() -> None:
    reset_runtime()
    dot_startup = start_dot_thread(SETTINGS)
    dot_startup.wait(timeout=15)
    frpc = start_frpc(SETTINGS)

    def shutdown(signum: int, _frame: Any) -> None:
        print(f"[main] received signal {signum}; shutting down", flush=True)
        if frpc and frpc.poll() is None:
            frpc.terminate()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    run_http(SETTINGS)


if __name__ == "__main__":
    main()
