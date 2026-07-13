#!/usr/bin/env python3
"""DNS dashboard, health API, DoT listener, and runtime config helpers."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
STATIC_ROOT = ROOT / "static"
STARTED_AT = time.time()
METRICS_LOCK = threading.Lock()
METRICS = {
    "dot_queries": 0,
    "dot_errors": 0,
    "last_query_at": None,
    "frpc_started": False,
    "frpc_running": False,
    "frpc_exit_code": None,
    "frpc_last_error": None,
    "frpc_last_log": None,
}
DOT_READY = threading.Event()


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


@dataclass(frozen=True)
class Settings:
    service_name: str = os.getenv("SERVICE_NAME", "DNS Dashboard")
    port: int = env_int("PORT", 10000)
    bind_host: str = os.getenv("BIND_HOST", "0.0.0.0")
    dot_enabled: bool = env_bool("DOT_ENABLED", True)
    dot_bind_host: str = os.getenv("DOT_BIND_HOST", "127.0.0.1")
    dot_port: int = env_int("DOT_PORT", 8853)
    dot_cert_file: str = os.getenv("DOT_CERT_FILE", "/tmp/dns-dashboard/tls.crt")
    dot_key_file: str = os.getenv("DOT_KEY_FILE", "/tmp/dns-dashboard/tls.key")
    upstream_dns: str = os.getenv("UPSTREAM_DNS", "1.1.1.1")
    upstream_dns_port: int = env_int("UPSTREAM_DNS_PORT", 53)
    frpc_enabled: bool = env_bool("FRPC_ENABLED", True)
    frp_server_addr: str = os.getenv("FRP_SERVER_ADDR", "")
    frp_server_port: int = env_int("FRP_SERVER_PORT", 7000)
    frp_auth_token: str = os.getenv("FRP_AUTH_TOKEN", "")
    frp_remote_port: int = env_int("FRP_REMOTE_PORT", 853)
    frpc_binary: str = os.getenv("FRPC_BINARY", "/usr/local/bin/frpc")

    @property
    def frpc_configured(self) -> bool:
        return bool(self.frp_server_addr and self.frp_auth_token)

    def public_config(self) -> dict[str, Any]:
        data = asdict(self)
        data["frp_auth_token"] = "***configured***" if self.frp_auth_token else ""
        return data


SETTINGS = Settings()


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def ensure_self_signed_certificate(settings: Settings) -> None:
    cert = Path(settings.dot_cert_file)
    key = Path(settings.dot_key_file)
    if cert.exists() and key.exists():
        return

    cert.parent.mkdir(parents=True, exist_ok=True)
    key.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "30",
        "-subj",
        "/CN=dns-dashboard.local",
        "-keyout",
        str(key),
        "-out",
        str(cert),
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def toml_string(value: str) -> str:
    return json.dumps(value)


def frpc_config(settings: Settings) -> str:
    return f"""serverAddr = {toml_string(settings.frp_server_addr)}
serverPort = {settings.frp_server_port}

auth.method = "token"
auth.token = {toml_string(settings.frp_auth_token)}

[[proxies]]
name = "dns-over-tls"
type = "tcp"
localIP = {toml_string(settings.dot_bind_host)}
localPort = {settings.dot_port}
remotePort = {settings.frp_remote_port}
"""


def write_frpc_config(settings: Settings) -> Path | None:
    if not settings.frpc_enabled or not settings.frpc_configured:
        return None
    path = Path(os.getenv("FRPC_CONFIG_FILE", "/tmp/dns-dashboard/frpc.toml"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(frpc_config(settings), encoding="utf-8")
    path.chmod(0o600)
    return path


def set_metric(**values: Any) -> None:
    with METRICS_LOCK:
        METRICS.update(values)


def start_frpc(settings: Settings) -> subprocess.Popen[str] | None:
    if not settings.frpc_enabled:
        set_metric(frpc_last_error="FRPC is disabled by FRPC_ENABLED=false.")
        return None
    if not settings.frpc_configured:
        set_metric(frpc_last_error="FRP_SERVER_ADDR and FRP_AUTH_TOKEN are required to start FRPC.")
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
        set_metric(frpc_last_error=str(exc), frpc_running=False)
        return None

    set_metric(frpc_started=True, frpc_running=True, frpc_exit_code=None, frpc_last_error=None)
    threading.Thread(target=_capture_frpc_output, args=(process,), daemon=True).start()
    threading.Thread(target=_watch_frpc_exit, args=(process,), daemon=True).start()
    return process


def _capture_frpc_output(process: subprocess.Popen[str]) -> None:
    if process.stdout is None:
        return
    for line in process.stdout:
        line = line.strip()
        if line:
            set_metric(frpc_last_log=line)
            print(f"[frpc] {line}", flush=True)


def _watch_frpc_exit(process: subprocess.Popen[str]) -> None:
    code = process.wait()
    set_metric(
        frpc_running=False,
        frpc_exit_code=code,
        frpc_last_error=None if code == 0 else f"FRPC exited with code {code}.",
    )


async def forward_dns_query(payload: bytes, settings: Settings) -> bytes:
    loop = asyncio.get_running_loop()

    def send_udp() -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(payload, (settings.upstream_dns, settings.upstream_dns_port))
            response, _ = sock.recvfrom(4096)
            return response

    return await loop.run_in_executor(None, send_udp)


async def handle_dot(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            header = await reader.readexactly(2)
            length = int.from_bytes(header, "big")
            if length <= 0 or length > 4096:
                raise ValueError(f"Invalid DNS message length: {length}")
            payload = await reader.readexactly(length)
            response = await forward_dns_query(payload, SETTINGS)
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
            with METRICS_LOCK:
                METRICS["dot_queries"] += 1
                METRICS["last_query_at"] = now_iso()
    except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
        pass
    except Exception as exc:  # noqa: BLE001 - operational metric for malformed client traffic.
        with METRICS_LOCK:
            METRICS["dot_errors"] += 1
        print(f"[dot] {exc}", flush=True)
    finally:
        writer.close()
        await writer.wait_closed()


async def run_dot_server(settings: Settings, ready: threading.Event) -> None:
    if not settings.dot_enabled:
        ready.set()
        DOT_READY.set()
        return

    ensure_self_signed_certificate(settings)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(settings.dot_cert_file, settings.dot_key_file)
    server = await asyncio.start_server(
        handle_dot,
        host=settings.dot_bind_host,
        port=settings.dot_port,
        ssl=context,
    )
    ready.set()
    DOT_READY.set()
    print(f"[dot] listening on {settings.dot_bind_host}:{settings.dot_port}", flush=True)
    async with server:
        await server.serve_forever()


def start_dot_thread(settings: Settings) -> threading.Event:
    ready = threading.Event()

    def runner() -> None:
        try:
            asyncio.run(run_dot_server(settings, ready))
        except Exception as exc:  # noqa: BLE001 - readiness should surface startup failures.
            print(f"[dot] failed to start: {exc}", flush=True)
            ready.set()

    threading.Thread(target=runner, daemon=True).start()
    return ready


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "DnsDashboard/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        if self.path == "/":
            self._serve_static("index.html", "text/html; charset=utf-8")
        elif self.path == "/app.js":
            self._serve_static("app.js", "text/javascript; charset=utf-8")
        elif self.path == "/styles.css":
            self._serve_static("styles.css", "text/css; charset=utf-8")
        elif self.path == "/api/status":
            self._json(status_payload())
        elif self.path == "/healthz":
            self._json({"ok": True, "time": now_iso()})
        elif self.path == "/readyz":
            payload = readiness_payload()
            self._json(payload, HTTPStatus.OK if payload["ready"] else HTTPStatus.SERVICE_UNAVAILABLE)
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


def dot_ready() -> bool:
    return not SETTINGS.dot_enabled or DOT_READY.is_set()


def readiness_payload() -> dict[str, Any]:
    return {
        "ready": dot_ready(),
        "dot_enabled": SETTINGS.dot_enabled,
        "dot_ready": dot_ready(),
        "frpc_enabled": SETTINGS.frpc_enabled,
        "frpc_configured": SETTINGS.frpc_configured,
    }


def frpc_state(metrics: dict[str, Any]) -> str:
    if not SETTINGS.frpc_enabled:
        return "disabled"
    if not SETTINGS.frpc_configured:
        return "needs-config"
    if metrics["frpc_running"]:
        return "running"
    if metrics["frpc_started"]:
        return "exited"
    return "not-started"


def status_payload() -> dict[str, Any]:
    with METRICS_LOCK:
        metrics = dict(METRICS)
    uptime = max(0, int(time.time() - STARTED_AT))
    dot_state = "ready" if dot_ready() and SETTINGS.dot_enabled else "disabled"
    if SETTINGS.dot_enabled and not dot_ready():
        dot_state = "starting"
    return {
        "service": SETTINGS.service_name,
        "time": now_iso(),
        "uptime_seconds": uptime,
        "settings": SETTINGS.public_config(),
        "endpoints": {
            "http": f"{SETTINGS.bind_host}:{SETTINGS.port}",
            "dot_local": f"{SETTINGS.dot_bind_host}:{SETTINGS.dot_port}",
            "dot_remote_port": SETTINGS.frp_remote_port,
            "upstream_dns": f"{SETTINGS.upstream_dns}:{SETTINGS.upstream_dns_port}",
        },
        "checks": {
            "http": "healthy",
            "dot": dot_state,
            "frpc": frpc_state(metrics),
            "frpc_configured": SETTINGS.frpc_configured,
        },
        "metrics": metrics,
    }


def run_http(settings: Settings) -> None:
    httpd = ThreadingHTTPServer((settings.bind_host, settings.port), DashboardHandler)
    print(f"[http] listening on {settings.bind_host}:{settings.port}", flush=True)
    httpd.serve_forever()


def main() -> None:
    ready = start_dot_thread(SETTINGS)
    ready.wait(timeout=10)
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
