from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import signal
import socket
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping

CONFIG_FORMAT = "dns-bridge-config-v1"
BACKUP_FORMAT = "dns-bridge-backup-v1"
LEGACY_CONFIG_FORMAT = "dns-dashboard-config-v2"
LEGACY_BACKUP_FORMAT = "dns-dashboard-backup-v1"
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 256
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
MAX_BODY_BYTES = 2 * 1024 * 1024

DEFAULT_CONFIG = {
    "enabled": False,
    "server_addr": "",
    "server_port": 7000,
    "auth_token": "",
    "transport_tls": True,
    "proxies": {
        "dot": {"enabled": True, "type": "tcp", "local_port": 853, "remote_port": 853},
        "doq": {"enabled": False, "type": "udp", "local_port": 853, "remote_port": 853},
        "dns_tcp": {"enabled": False, "type": "tcp", "local_port": 53, "remote_port": 53},
        "dns_udp": {"enabled": False, "type": "udp", "local_port": 53, "remote_port": 53},
    },
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _password_hash(password: str) -> str:
    if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters.")
    salt = os.urandom(16)
    n, r, p = 16384, 8, 1
    derived = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        n,
        r,
        p,
        base64.urlsafe_b64encode(salt).decode().rstrip("="),
        base64.urlsafe_b64encode(derived).decode().rstrip("="),
    )


def _decode_urlsafe(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_password(password: str, encoded: str) -> bool:
    try:
        method, raw_n, raw_r, raw_p, raw_salt, raw_digest = encoded.split("$", 5)
        if method != "scrypt":
            return False
        n, r, p = int(raw_n), int(raw_r), int(raw_p)
        if (n, r, p) != (16384, 8, 1):
            return False
        salt = _decode_urlsafe(raw_salt)
        expected = _decode_urlsafe(raw_digest)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ValueError(f"{field} must be true or false.")


def _port(value: Any, field: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer.") from exc
    if not 1 <= parsed <= 65535:
        raise ValueError(f"{field} must be between 1 and 65535.")
    return parsed


def _host(value: Any) -> str:
    candidate = str(value or "").strip().rstrip(".")
    if not candidate:
        return ""
    if len(candidate) > 253 or any(ch.isspace() for ch in candidate):
        raise ValueError("FRPS address is invalid.")
    try:
        socket.inet_pton(socket.AF_INET, candidate)
        return candidate
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, candidate)
        return candidate
    except OSError:
        pass
    if not HOST_RE.fullmatch(candidate) or ".." in candidate:
        raise ValueError("FRPS address must be an IP address or hostname.")
    return candidate.lower()


def _toml_string(value: str) -> str:
    # JSON string escaping is compatible with TOML basic strings for these values.
    return json.dumps(value, ensure_ascii=True)


def validate_frp(payload: Mapping[str, Any], current: Mapping[str, Any] | None = None) -> dict[str, Any]:
    base = json.loads(json.dumps(current if current is not None else DEFAULT_CONFIG))
    result = {
        "enabled": _bool(payload.get("enabled", base["enabled"]), "enabled"),
        "server_addr": _host(payload.get("server_addr", base["server_addr"])),
        "server_port": _port(payload.get("server_port", base["server_port"]), "server_port"),
        "auth_token": str(base.get("auth_token", "")),
        "transport_tls": _bool(payload.get("transport_tls", base["transport_tls"]), "transport_tls"),
        "proxies": {},
    }
    if "auth_token" in payload:
        token = str(payload.get("auth_token", ""))
        if len(token) > 4096:
            raise ValueError("FRP token is too long.")
        if token:
            result["auth_token"] = token
    if _bool(payload.get("clear_auth_token", False), "clear_auth_token"):
        result["auth_token"] = ""

    raw_proxies = payload.get("proxies", {})
    if raw_proxies is None:
        raw_proxies = {}
    if not isinstance(raw_proxies, Mapping):
        raise ValueError("proxies must be an object.")

    for name, default_proxy in DEFAULT_CONFIG["proxies"].items():
        existing = base.get("proxies", {}).get(name, default_proxy)
        supplied = raw_proxies.get(name, {})
        if supplied is None:
            supplied = {}
        if not isinstance(supplied, Mapping):
            raise ValueError(f"{name} proxy must be an object.")
        proxy_type = default_proxy["type"]
        result["proxies"][name] = {
            "enabled": _bool(supplied.get("enabled", existing.get("enabled", default_proxy["enabled"])), f"{name}.enabled"),
            "type": proxy_type,
            "local_port": _port(supplied.get("local_port", existing.get("local_port", default_proxy["local_port"])), f"{name}.local_port"),
            "remote_port": _port(supplied.get("remote_port", existing.get("remote_port", default_proxy["remote_port"])), f"{name}.remote_port"),
        }

    if result["enabled"] and not result["server_addr"]:
        raise ValueError("FRPS address is required when FRP is enabled.")
    return result


def render_frpc_toml(frp: Mapping[str, Any]) -> str:
    lines = [
        f"serverAddr = {_toml_string(str(frp['server_addr']))}",
        f"serverPort = {int(frp['server_port'])}",
        f"transport.tls.enable = {'true' if frp.get('transport_tls', True) else 'false'}",
    ]
    token = str(frp.get("auth_token", ""))
    if token:
        lines.extend(["auth.method = \"token\"", f"auth.token = {_toml_string(token)}"])
    lines.append("")
    for name, proxy in frp.get("proxies", {}).items():
        if not proxy.get("enabled"):
            continue
        lines.extend(
            [
                "[[proxies]]",
                f"name = {_toml_string('dns-bridge-' + name)}",
                f"type = {_toml_string(str(proxy['type']))}",
                "localIP = \"127.0.0.1\"",
                f"localPort = {int(proxy['local_port'])}",
                f"remotePort = {int(proxy['remote_port'])}",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _safe_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


class ConfigStore:
    def __init__(self, root: Path, legacy_root: Path | None = None) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.path = self.root / "bridge.json"
        self.frpc_path = self.root / "frpc.toml"
        self.lock = threading.RLock()
        self.legacy_root = legacy_root
        if not self.path.exists():
            self._initialize()

    def _initialize(self) -> None:
        migrated = self._migrate_legacy_file()
        if migrated is None:
            migrated = {
                "format": CONFIG_FORMAT,
                "updated_at": now_iso(),
                "admin": {"username": "", "password_hash": ""},
                "frp": json.loads(json.dumps(DEFAULT_CONFIG)),
                "migration": None,
            }
        self._write(migrated)

    def _migrate_legacy_file(self) -> dict[str, Any] | None:
        if self.legacy_root is None:
            return None
        path = self.legacy_root / "config.json"
        if not path.is_file():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if raw.get("format") != LEGACY_CONFIG_FORMAT:
                return None
            old = raw.get("settings", {})
            auth = raw.get("auth", {})
            frp = validate_frp(
                {
                    "enabled": old.get("frpc_enabled", False),
                    "server_addr": old.get("frp_server_addr", ""),
                    "server_port": old.get("frp_server_port", 7000),
                    "auth_token": old.get("frp_auth_token", ""),
                    "transport_tls": True,
                    "proxies": {
                        "dot": {
                            "enabled": old.get("dot_enabled", True),
                            "local_port": old.get("dot_port", 853),
                            "remote_port": old.get("frp_remote_port", 853),
                        }
                    },
                }
            )
            old_user = str(auth.get("username", ""))
            old_hash = str(auth.get("password_hash", ""))
            if not USERNAME_RE.fullmatch(old_user) or not old_hash.startswith("scrypt$"):
                old_user, old_hash = "", ""
            return {
                "format": CONFIG_FORMAT,
                "updated_at": now_iso(),
                "admin": {"username": old_user, "password_hash": old_hash},
                "frp": frp,
                "migration": {"source": str(path), "migrated_at": now_iso()},
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None

    def _read(self) -> dict[str, Any]:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("format") != CONFIG_FORMAT:
            raise ValueError("Unsupported bridge configuration format.")
        return raw

    def _write(self, document: Mapping[str, Any]) -> None:
        _safe_write(self.path, json.dumps(document, indent=2, sort_keys=True) + "\n")

    def auth_enabled(self) -> bool:
        with self.lock:
            admin = self._read().get("admin", {})
            return bool(admin.get("username") and admin.get("password_hash"))

    def verify(self, username: str, password: str) -> bool:
        with self.lock:
            admin = self._read().get("admin", {})
        expected = str(admin.get("username", ""))
        encoded = str(admin.get("password_hash", ""))
        return bool(expected and encoded and hmac.compare_digest(username, expected) and verify_password(password, encoded))

    def set_admin(self, username: str, password: str, require_unconfigured: bool = False) -> None:
        username = username.strip()
        if not USERNAME_RE.fullmatch(username):
            raise ValueError("Username must be 1-64 characters using letters, numbers, dot, dash, or underscore.")
        encoded = _password_hash(password)
        with self.lock:
            doc = self._read()
            if require_unconfigured and doc.get("admin", {}).get("username"):
                raise ValueError("Bridge administrator is already configured.")
            doc["admin"] = {"username": username, "password_hash": encoded}
            doc["updated_at"] = now_iso()
            self._write(doc)

    def get_frp(self) -> dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self._read().get("frp", DEFAULT_CONFIG)))

    def public_config(self) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
        frp = json.loads(json.dumps(doc.get("frp", DEFAULT_CONFIG)))
        token_configured = bool(frp.get("auth_token"))
        frp.pop("auth_token", None)
        return {
            "format": CONFIG_FORMAT,
            "setup_required": not bool(doc.get("admin", {}).get("username")),
            "username": str(doc.get("admin", {}).get("username", "")),
            "frp": frp,
            "secrets": {"auth_token_configured": token_configured},
            "migration": doc.get("migration"),
            "updated_at": doc.get("updated_at"),
        }

    def save_frp(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
            frp = validate_frp(payload, doc.get("frp", DEFAULT_CONFIG))
            doc["frp"] = frp
            doc["updated_at"] = now_iso()
            self._write(doc)
        return self.public_config()

    def export_backup(self) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
        return {
            "format": BACKUP_FORMAT,
            "exported_at": now_iso(),
            "config": doc,
            "warning": "This backup may contain the FRP authentication token and bridge administrator password hash. Store it securely.",
        }

    def import_backup(self, backup: Mapping[str, Any]) -> None:
        fmt = backup.get("format")
        if fmt == BACKUP_FORMAT:
            candidate = backup.get("config")
            if not isinstance(candidate, Mapping) or candidate.get("format") != CONFIG_FORMAT:
                raise ValueError("Bridge backup is incomplete.")
            frp = validate_frp(candidate.get("frp", {}))
            admin = candidate.get("admin", {})
            if not isinstance(admin, Mapping):
                admin = {}
            username = str(admin.get("username", ""))
            password_hash = str(admin.get("password_hash", ""))
            if username and (not USERNAME_RE.fullmatch(username) or not password_hash.startswith("scrypt$")):
                raise ValueError("Bridge backup administrator data is invalid.")
            doc = {
                "format": CONFIG_FORMAT,
                "updated_at": now_iso(),
                "admin": {"username": username, "password_hash": password_hash},
                "frp": frp,
                "migration": candidate.get("migration"),
            }
        elif fmt == LEGACY_BACKUP_FORMAT:
            old = backup.get("settings", {})
            if not isinstance(old, Mapping):
                raise ValueError("Legacy backup settings are missing.")
            with self.lock:
                current = self._read()
            frp = validate_frp(
                {
                    "enabled": old.get("frpc_enabled", False),
                    "server_addr": old.get("frp_server_addr", ""),
                    "server_port": old.get("frp_server_port", 7000),
                    "auth_token": old.get("frp_auth_token", ""),
                    "transport_tls": True,
                    "proxies": {
                        "dot": {
                            "enabled": old.get("dot_enabled", True),
                            "local_port": old.get("dot_port", 853),
                            "remote_port": old.get("frp_remote_port", 853),
                        }
                    },
                },
                current.get("frp", DEFAULT_CONFIG),
            )
            doc = current
            doc["frp"] = frp
            doc["updated_at"] = now_iso()
            doc["migration"] = {"source": "legacy-backup", "migrated_at": now_iso()}
        else:
            raise ValueError("Unsupported backup format.")
        with self.lock:
            self._write(doc)


class FrpcSupervisor:
    def __init__(self, store: ConfigStore, frpc_binary: str = "/usr/local/bin/frpc") -> None:
        self.store = store
        self.frpc_binary = frpc_binary
        self.process: subprocess.Popen[str] | None = None
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.reload_event = threading.Event()
        self.lock = threading.RLock()
        self.logs: deque[str] = deque(maxlen=40)
        self.last_error: str | None = None
        self.last_exit_code: int | None = None
        self.started_at: str | None = None
        self.restart_count = 0
        self.applied_hash = ""

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, name="frpc-supervisor", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.reload_event.set()
        self._stop_process()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)

    def reload(self) -> None:
        self.applied_hash = ""
        self.reload_event.set()

    def _stop_process(self) -> None:
        with self.lock:
            proc = self.process
            self.process = None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

    def _drain(self, proc: subprocess.Popen[str]) -> None:
        if proc.stdout is None:
            return
        for line in proc.stdout:
            clean = line.rstrip()
            if clean:
                with self.lock:
                    self.logs.append(clean[-1000:])

    def _write_config(self, frp: Mapping[str, Any]) -> None:
        _safe_write(self.store.frpc_path, render_frpc_toml(frp))

    def _config_hash(self, frp: Mapping[str, Any]) -> str:
        return hashlib.sha256(json.dumps(frp, sort_keys=True).encode()).hexdigest()

    def _run(self) -> None:
        backoff = 1.0
        while not self.stop_event.is_set():
            try:
                frp = self.store.get_frp()
                desired = bool(frp.get("enabled") and frp.get("server_addr"))
                config_hash = self._config_hash(frp)
                with self.lock:
                    proc = self.process
                running = bool(proc and proc.poll() is None)

                if not desired:
                    if running:
                        self._stop_process()
                    self.applied_hash = config_hash
                    self.last_error = None
                    self.reload_event.wait(2.0)
                    self.reload_event.clear()
                    continue

                if running and self.applied_hash == config_hash:
                    self.reload_event.wait(2.0)
                    if self.reload_event.is_set():
                        self.reload_event.clear()
                        self._stop_process()
                    continue

                if running:
                    self._stop_process()

                self._write_config(frp)
                proc = subprocess.Popen(
                    [self.frpc_binary, "-c", str(self.store.frpc_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env={
                        "PATH": "/usr/local/bin:/usr/bin:/bin",
                        "HOME": "/tmp",
                        "TMPDIR": "/tmp",
                        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
                    },
                )
                with self.lock:
                    self.process = proc
                    self.started_at = now_iso()
                    self.last_error = None
                    self.last_exit_code = None
                    self.restart_count += 1
                    self.logs.append(f"{now_iso()} frpc started (pid {proc.pid})")
                self.applied_hash = config_hash
                threading.Thread(target=self._drain, args=(proc,), daemon=True).start()

                # A stable 30 second run resets backoff. During the wait, config changes restart immediately.
                stable_until = time.monotonic() + 30.0
                while not self.stop_event.is_set() and proc.poll() is None:
                    if self.reload_event.wait(1.0):
                        self.reload_event.clear()
                        self._stop_process()
                        break
                    if time.monotonic() >= stable_until:
                        backoff = 1.0
                        stable_until = float("inf")

                code = proc.poll()
                if code is not None:
                    with self.lock:
                        if self.process is proc:
                            self.process = None
                        self.last_exit_code = code
                        self.last_error = f"frpc exited with code {code}"
                        self.logs.append(f"{now_iso()} {self.last_error}")
                    if not self.stop_event.wait(backoff):
                        backoff = min(backoff * 2.0, 60.0)
            except Exception as exc:  # supervisor must stay alive
                with self.lock:
                    self.last_error = f"{type(exc).__name__}: {exc}"
                    self.logs.append(f"{now_iso()} supervisor error: {self.last_error}")
                if self.stop_event.wait(backoff):
                    break
                backoff = min(backoff * 2.0, 60.0)

    @staticmethod
    def _tcp_probe(port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            return False

    def status(self) -> dict[str, Any]:
        frp = self.store.get_frp()
        with self.lock:
            proc = self.process
            running = bool(proc and proc.poll() is None)
            logs = list(self.logs)
            pid = proc.pid if running and proc else None
            last_error = self.last_error
            exit_code = self.last_exit_code
            started_at = self.started_at
            restarts = self.restart_count
        probes: dict[str, bool | None] = {}
        for name, proxy in frp.get("proxies", {}).items():
            if not proxy.get("enabled"):
                probes[name] = None
            elif proxy.get("type") == "tcp":
                probes[name] = self._tcp_probe(int(proxy["local_port"]))
            else:
                probes[name] = None
        return {
            "enabled": bool(frp.get("enabled")),
            "configured": bool(frp.get("server_addr")),
            "running": running,
            "pid": pid,
            "started_at": started_at,
            "last_exit_code": exit_code,
            "last_error": last_error,
            "restart_count": restarts,
            "local_service_probes": probes,
            "logs": logs,
        }


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


class BridgeApp:
    def __init__(self, store: ConfigStore, supervisor: FrpcSupervisor, index_file: Path) -> None:
        self.store = store
        self.supervisor = supervisor
        self.index_file = index_file

    @staticmethod
    def technitium_ready() -> bool:
        try:
            with socket.create_connection(("127.0.0.1", 5380), timeout=0.5):
                return True
        except OSError:
            return False

    def handler(self) -> type[BaseHTTPRequestHandler]:
        app = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "DnsBridge/5"
            sys_version = ""
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _security_headers(self) -> None:
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

            def _write(self, body: bytes) -> None:
                try:
                    self.wfile.write(body)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
                    self.close_connection = True

            def _json(self, payload: Mapping[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
                body = json.dumps(payload, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._security_headers()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self._write(body)

            def _auth(self) -> bool:
                if not app.store.auth_enabled():
                    return False
                header = self.headers.get("Authorization", "")
                if not header.startswith("Basic "):
                    return False
                try:
                    decoded = base64.b64decode(header[6:], validate=True).decode()
                    username, password = decoded.split(":", 1)
                except (ValueError, UnicodeDecodeError):
                    return False
                return app.store.verify(username, password)

            def _require_auth(self) -> bool:
                if self._auth():
                    return True
                body = b"Bridge authentication required."
                self.send_response(HTTPStatus.UNAUTHORIZED)
                self.send_header("WWW-Authenticate", 'Basic realm="DNS Bridge"')
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self._security_headers()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self._write(body)
                return False

            def _body(self) -> dict[str, Any] | None:
                origin = self.headers.get("Origin")
                if origin:
                    try:
                        from urllib.parse import urlsplit
                        parsed = urlsplit(origin)
                        if parsed.netloc != self.headers.get("Host", ""):
                            self._json({"ok": False, "error": "Cross-origin control requests are rejected."}, HTTPStatus.FORBIDDEN)
                            return None
                    except ValueError:
                        self._json({"ok": False, "error": "Invalid Origin header."}, HTTPStatus.FORBIDDEN)
                        return None
                if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
                    self._json({"ok": False, "error": "Content-Type must be application/json."}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
                    return None
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = -1
                if length <= 0 or length > MAX_BODY_BYTES:
                    self._json({"ok": False, "error": "Invalid request size."}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                    return None
                try:
                    raw = json.loads(self.rfile.read(length).decode())
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    self._json({"ok": False, "error": f"Invalid JSON: {exc}"}, HTTPStatus.BAD_REQUEST)
                    return None
                if not isinstance(raw, dict):
                    self._json({"ok": False, "error": "JSON body must be an object."}, HTTPStatus.BAD_REQUEST)
                    return None
                return raw

            def do_GET(self) -> None:  # noqa: N802
                path = self.path.split("?", 1)[0]
                if path == "/_healthz":
                    ready = app.technitium_ready()
                    self._json({"ok": ready, "technitium": ready, "time": now_iso()}, HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE)
                    return
                if path in {"/_bridge", "/_bridge/"}:
                    if app.store.auth_enabled() and not self._require_auth():
                        return
                    body = app.index_file.read_bytes()
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self._security_headers()
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self._write(body)
                    return
                if path == "/_bridge/api/public":
                    self._json({"ok": True, "config": app.store.public_config(), "technitium_ready": app.technitium_ready()})
                    return
                if not path.startswith("/_bridge/api/"):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                if not self._require_auth():
                    return
                if path == "/_bridge/api/status":
                    self._json({"ok": True, "config": app.store.public_config(), "frpc": app.supervisor.status(), "technitium_ready": app.technitium_ready()})
                elif path == "/_bridge/api/backup":
                    payload = json.dumps(app.store.export_backup(), indent=2).encode()
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Disposition", f'attachment; filename="dns-bridge-{datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")}.json"')
                    self._security_headers()
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self._write(payload)
                else:
                    self.send_error(HTTPStatus.NOT_FOUND)

            def do_POST(self) -> None:  # noqa: N802
                path = self.path.split("?", 1)[0]
                if path == "/_bridge/api/setup":
                    if app.store.auth_enabled():
                        self._json({"ok": False, "error": "Bridge administrator is already configured."}, HTTPStatus.CONFLICT)
                        return
                    data = self._body()
                    if data is None:
                        return
                    try:
                        app.store.set_admin(str(data.get("username", "")), str(data.get("password", "")), require_unconfigured=True)
                    except ValueError as exc:
                        self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                        return
                    self._json({"ok": True, "message": "Bridge administrator created. Reload and sign in."})
                    return

                # A legacy or bridge backup can be restored on an unclaimed deployment.
                if path == "/_bridge/api/restore" and not app.store.auth_enabled():
                    data = self._body()
                    if data is None:
                        return
                    try:
                        backup = data.get("backup")
                        if not isinstance(backup, Mapping):
                            raise ValueError("Backup object is missing.")
                        app.store.import_backup(backup)
                        app.supervisor.reload()
                    except ValueError as exc:
                        self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                        return
                    self._json({"ok": True, "message": "Backup restored."})
                    return

                if not self._require_auth():
                    return
                data = self._body()
                if data is None:
                    return
                try:
                    if path == "/_bridge/api/settings":
                        config = app.store.save_frp(data)
                        app.supervisor.reload()
                        self._json({"ok": True, "config": config})
                    elif path == "/_bridge/api/admin":
                        app.store.set_admin(str(data.get("username", "")), str(data.get("password", "")))
                        self._json({"ok": True, "message": "Bridge administrator updated."})
                    elif path == "/_bridge/api/restore":
                        backup = data.get("backup")
                        if not isinstance(backup, Mapping):
                            raise ValueError("Backup object is missing.")
                        app.store.import_backup(backup)
                        app.supervisor.reload()
                        self._json({"ok": True, "message": "Backup restored."})
                    else:
                        self.send_error(HTTPStatus.NOT_FOUND)
                except ValueError as exc:
                    self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)

        return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9080)
    parser.add_argument("--data-dir", default=os.environ.get("DNS_BRIDGE_DATA_DIR", "/data/bridge"))
    parser.add_argument("--legacy-dir", default="/data/dns-dashboard")
    parser.add_argument("--index-file", default="/opt/dns-bridge/index.html")
    args = parser.parse_args()

    root = Path(args.data_dir)
    try:
        root.mkdir(parents=True, exist_ok=True)
        test = root / ".write-test"
        test.write_text("ok")
        test.unlink()
    except OSError:
        root = Path("/tmp/dns-bridge")
        root.mkdir(parents=True, exist_ok=True)

    store = ConfigStore(root, Path(args.legacy_dir))
    supervisor = FrpcSupervisor(store)
    supervisor.start()
    app = BridgeApp(store, supervisor, Path(args.index_file))
    server = Server((args.bind, args.port), app.handler())

    stopping = threading.Event()

    def shutdown(_signum: int, _frame: Any) -> None:
        if stopping.is_set():
            return
        stopping.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        supervisor.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
