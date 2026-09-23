from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import select
import signal
import socket
import ssl
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

CONFIG_FORMAT = "dns-bridge-config-v1"
BACKUP_FORMAT = "dns-bridge-backup-v1"
LEGACY_CONFIG_FORMAT = "dns-dashboard-config-v2"
LEGACY_BACKUP_FORMAT = "dns-dashboard-backup-v1"
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 256
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_TOML_BYTES = 128 * 1024
CERT_CONFIG_FORMAT = "dns-bridge-certificate-v1"
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
ACME_CA = "zerossl"
ACME_CA_LABEL = "ZeroSSL"
DOT_TLS_PROXY_PORT = 8853
DOT_TCP_BACKEND_PORT = 53
LEGACY_CROSS_CERT_SHA256 = "92F351BF3D54164DFA8DD8F9E1139D3150349786485D2B9EECD00E2971C1E6C5"

DEFAULT_CERT_CONFIG = {
    "format": CERT_CONFIG_FORMAT,
    "acme_ca": ACME_CA,
    "mode": "manual",
    "domain": "",
    "email": "",
    "auto_renew": False,
    "accept_tos": False,
    "manage_dns_record": True,
    "dns_target": "",
    "updated_at": None,
}

DEFAULT_CONFIG = {
    "enabled": False,
    "server_addr": "",
    "server_port": 7000,
    "transport_tls": True,
    "proxies": {
        "dot": {"enabled": True, "type": "tcp", "local_port": DOT_TLS_PROXY_PORT, "remote_port": 853},
        "doq": {"enabled": False, "type": "udp", "local_port": 853, "remote_port": 853},
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


def validate_frp(
    payload: Mapping[str, Any],
    current: Mapping[str, Any] | None = None,
    require_server_addr: bool = True,
) -> dict[str, Any]:
    base = json.loads(json.dumps(current if current is not None else DEFAULT_CONFIG))
    result = {
        "enabled": _bool(payload.get("enabled", base["enabled"]), "enabled"),
        "server_addr": _host(payload.get("server_addr", base["server_addr"])),
        "server_port": _port(payload.get("server_port", base["server_port"]), "server_port"),
        "transport_tls": _bool(payload.get("transport_tls", base["transport_tls"]), "transport_tls"),
        "proxies": {},
    }
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

    if require_server_addr and result["enabled"] and not result["server_addr"]:
        raise ValueError("FRPS address is required when FRP is enabled.")
    return result


def render_frpc_toml(frp: Mapping[str, Any]) -> str:
    lines = [
        f"serverAddr = {_toml_string(str(frp['server_addr']))}",
        f"serverPort = {int(frp['server_port'])}",
        f"transport.tls.enable = {'true' if frp.get('transport_tls', True) else 'false'}",
    ]
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


def sanitize_frpc_toml(value: Any) -> str:
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    if "\x00" in text:
        raise ValueError("frpc.toml cannot contain NUL bytes.")
    if len(text.encode("utf-8")) > MAX_TOML_BYTES:
        raise ValueError("frpc.toml is too large.")
    if re.search(r"(?mi)^\s*auth\.(?:token|method)\s*=", text):
        raise ValueError("FRP token authentication is disabled for this deployment.")
    return text.rstrip() + "\n" if text.strip() else ""


def migrate_dot_tls_proxy_toml(value: str) -> str:
    """Move the known DoT FRP proxy from Technitium:853 to our TLS front end."""
    text = sanitize_frpc_toml(value)
    if not text:
        return text
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == "[[proxies]]"]
    starts.append(len(lines))
    for pos in range(len(starts) - 1):
        block_start, block_end = starts[pos], starts[pos + 1]
        block = "".join(lines[block_start:block_end])
        name = re.search(r'(?m)^\s*name\s*=\s*"([^"]+)"\s*$', block)
        ptype = re.search(r'(?m)^\s*type\s*=\s*"([^"]+)"\s*$', block)
        local = re.search(r'(?m)^\s*localPort\s*=\s*(\d+)\s*$', block)
        remote = re.search(r'(?m)^\s*remotePort\s*=\s*(\d+)\s*$', block)
        if not (name and ptype and local and remote):
            continue
        if (
            name.group(1) in {"dns-bridge-dot", "dot"}
            and ptype.group(1) == "tcp"
            and int(local.group(1)) == 853
            and int(remote.group(1)) == 853
        ):
            for i in range(block_start, block_end):
                if re.match(r"^\s*localPort\s*=\s*853\s*$", lines[i].rstrip("\r\n")):
                    newline = "\n" if lines[i].endswith("\n") else ""
                    indent = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
                    lines[i] = f"{indent}localPort = {DOT_TLS_PROXY_PORT}{newline}"
                    break
    return "".join(lines).rstrip() + "\n"


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
                "frpc_toml": render_frpc_toml(DEFAULT_CONFIG),
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
                "frpc_toml": render_frpc_toml(frp),
                "migration": {"source": str(path), "migrated_at": now_iso()},
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None

    def _read(self) -> dict[str, Any]:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("format") != CONFIG_FORMAT:
            raise ValueError("Unsupported bridge configuration format.")
        changed = False
        frp = raw.get("frp")
        if not isinstance(frp, dict):
            frp = json.loads(json.dumps(DEFAULT_CONFIG))
            raw["frp"] = frp
            changed = True
        if "auth_token" in frp:
            frp.pop("auth_token", None)
            changed = True
        proxies = frp.get("proxies")
        if isinstance(proxies, dict):
            for obsolete in ("dns_tcp", "dns_udp"):
                if obsolete in proxies:
                    proxies.pop(obsolete, None)
                    changed = True
        proxies = frp.get("proxies")
        if isinstance(proxies, dict):
            dot = proxies.get("dot")
            if (
                isinstance(dot, dict)
                and dot.get("type", "tcp") == "tcp"
                and int(dot.get("local_port", 0)) == 853
                and int(dot.get("remote_port", 0)) == 853
            ):
                dot["local_port"] = DOT_TLS_PROXY_PORT
                changed = True
        normalized_frp = validate_frp(frp, require_server_addr=False)
        if normalized_frp != frp:
            raw["frp"] = normalized_frp
            frp = normalized_frp
            changed = True
        raw_toml = raw.get("frpc_toml")
        if not isinstance(raw_toml, str):
            raw["frpc_toml"] = render_frpc_toml(frp)
            changed = True
        else:
            cleaned = migrate_dot_tls_proxy_toml(raw_toml)
            if cleaned != raw_toml:
                raw["frpc_toml"] = cleaned
                changed = True
        if changed:
            raw["updated_at"] = now_iso()
            _safe_write(self.path, json.dumps(raw, indent=2, sort_keys=True) + "\n")
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

    def get_frpc_toml(self) -> str:
        with self.lock:
            doc = self._read()
            return sanitize_frpc_toml(doc.get("frpc_toml", render_frpc_toml(doc.get("frp", DEFAULT_CONFIG))))

    def save_frpc_toml(self, text: str, enabled: bool) -> dict[str, Any]:
        cleaned = migrate_dot_tls_proxy_toml(text)
        with self.lock:
            doc = self._read()
            frp = validate_frp(doc.get("frp", DEFAULT_CONFIG), require_server_addr=False)
            frp["enabled"] = bool(enabled)
            doc["frp"] = frp
            doc["frpc_toml"] = cleaned
            doc["updated_at"] = now_iso()
            self._write(doc)
        return self.public_config()

    def public_config(self) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
        frp = validate_frp(doc.get("frp", DEFAULT_CONFIG), require_server_addr=False)
        return {
            "format": CONFIG_FORMAT,
            "setup_required": not bool(doc.get("admin", {}).get("username")),
            "username": str(doc.get("admin", {}).get("username", "")),
            "frp": frp,
            "frpc_toml": sanitize_frpc_toml(doc.get("frpc_toml", render_frpc_toml(frp))),
            "migration": doc.get("migration"),
            "updated_at": doc.get("updated_at"),
        }

    def save_frp(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
            frp = validate_frp(payload, doc.get("frp", DEFAULT_CONFIG))
            doc["frp"] = frp
            doc["frpc_toml"] = render_frpc_toml(frp)
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
            "warning": "This backup contains FRP connection settings and the bridge administrator password hash. Store it securely.",
        }

    def import_backup(self, backup: Mapping[str, Any]) -> None:
        fmt = backup.get("format")
        if fmt == BACKUP_FORMAT:
            candidate = backup.get("config")
            if not isinstance(candidate, Mapping) or candidate.get("format") != CONFIG_FORMAT:
                raise ValueError("Bridge backup is incomplete.")
            frp = validate_frp(candidate.get("frp", {}), require_server_addr=False)
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
                "frpc_toml": sanitize_frpc_toml(candidate.get("frpc_toml", render_frpc_toml(frp))),
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
            doc["frpc_toml"] = render_frpc_toml(frp)
            doc["updated_at"] = now_iso()
            doc["migration"] = {"source": "legacy-backup", "migrated_at": now_iso()}
        else:
            raise ValueError("Unsupported backup format.")
        with self.lock:
            self._write(doc)


class DotTlsProxy:
    """TLS terminator for DoT that preserves the exact PEM certificate chain."""

    def __init__(
        self,
        cert_file: Path,
        key_file: Path,
        listen_host: str = "127.0.0.1",
        listen_port: int = DOT_TLS_PROXY_PORT,
        upstream_host: str = "127.0.0.1",
        upstream_port: int = DOT_TCP_BACKEND_PORT,
    ) -> None:
        self.cert_file = cert_file
        self.key_file = key_file
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.listener: socket.socket | None = None
        self.lock = threading.RLock()
        self.last_error: str | None = None
        self.accepted_connections = 0

    def _context(self) -> ssl.SSLContext:
        if not self.cert_file.is_file() or not self.key_file.is_file():
            raise FileNotFoundError("DoT TLS certificate/key is not installed yet.")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert_file), str(self.key_file))
        try:
            context.set_alpn_protocols(["dot"])
        except NotImplementedError:
            pass
        return context

    @staticmethod
    def _relay(tls_sock: ssl.SSLSocket, upstream: socket.socket) -> None:
        tls_sock.settimeout(None)
        upstream.settimeout(None)
        peers = (tls_sock, upstream)
        while True:
            if tls_sock.pending() > 0:
                readable = [tls_sock]
            else:
                readable, _, _ = select.select(peers, [], [], 60.0)
            if not readable:
                continue
            for src in readable:
                dst = upstream if src is tls_sock else tls_sock
                data = src.recv(65536)
                if not data:
                    return
                dst.sendall(data)

    def _handle(self, raw: socket.socket) -> None:
        try:
            raw.settimeout(15.0)
            context = self._context()
            with context.wrap_socket(raw, server_side=True) as tls_sock:
                with socket.create_connection(
                    (self.upstream_host, self.upstream_port), timeout=5.0
                ) as upstream:
                    with self.lock:
                        self.accepted_connections += 1
                        self.last_error = None
                    self._relay(tls_sock, upstream)
        except (OSError, ssl.SSLError, FileNotFoundError, ValueError) as exc:
            with self.lock:
                self.last_error = f"{type(exc).__name__}: {exc}"
            try:
                raw.close()
            except OSError:
                pass

    def _serve(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.listen_host, self.listen_port))
        listener.listen(128)
        listener.settimeout(1.0)
        self.listener = listener
        try:
            while not self.stop_event.is_set():
                try:
                    raw, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        break
                    raise
                threading.Thread(target=self._handle, args=(raw,), daemon=True).start()
        finally:
            try:
                listener.close()
            except OSError:
                pass
            self.listener = None

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._serve, name="dot-tls-proxy", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        listener = self.listener
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)

    def status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "listen": f"{self.listen_host}:{self.listen_port}",
                "upstream": f"{self.upstream_host}:{self.upstream_port}",
                "running": bool(self.thread and self.thread.is_alive()),
                "certificate_ready": self.cert_file.is_file() and self.key_file.is_file(),
                "accepted_connections": self.accepted_connections,
                "last_error": self.last_error,
            }


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

    def _write_config(self, text: str) -> None:
        _safe_write(self.store.frpc_path, sanitize_frpc_toml(text))

    def _config_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def verify_toml(self, text: str) -> str:
        cleaned = sanitize_frpc_toml(text)
        if not cleaned:
            raise ValueError("frpc.toml cannot be empty.")
        verify_path = self.store.root / "frpc.verify.toml"
        _safe_write(verify_path, cleaned)
        try:
            completed = subprocess.run(
                [self.frpc_binary, "verify", "-c", str(verify_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "HOME": "/tmp",
                    "TMPDIR": "/tmp",
                    "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"Unable to verify frpc.toml: {exc}") from exc
        finally:
            try:
                verify_path.unlink()
            except OSError:
                pass
        output = (completed.stdout or "").strip()
        if completed.returncode != 0:
            raise ValueError("frpc.toml validation failed: " + (output[-4000:] or "unknown error"))
        return cleaned

    def _run(self) -> None:
        backoff = 1.0
        while not self.stop_event.is_set():
            try:
                frp = self.store.get_frp()
                config_text = self.store.get_frpc_toml()
                desired = bool(frp.get("enabled") and config_text.strip())
                config_hash = self._config_hash(config_text)
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

                self._write_config(config_text)
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
        probes: dict[str, bool | None] = {
            "dot_tls_proxy_8853": self._tcp_probe(DOT_TLS_PROXY_PORT),
            "doq_853": None,
        }
        return {
            "enabled": bool(frp.get("enabled")),
            "configured": bool(self.store.get_frpc_toml().strip()),
            "running": running,
            "pid": pid,
            "started_at": started_at,
            "last_exit_code": exit_code,
            "last_error": last_error,
            "restart_count": restarts,
            "local_service_probes": probes,
            "logs": logs,
        }



class CertificateManager:
    def __init__(
        self,
        bridge_root: Path,
        technitium_config_dir: Path,
        lego_binary: str = "/usr/local/bin/lego",
        openssl_binary: str = "/usr/bin/openssl",
    ) -> None:
        self.bridge_root = bridge_root
        self.technitium_config_dir = technitium_config_dir
        self.lego_binary = lego_binary
        self.openssl_binary = openssl_binary
        self.config_path = bridge_root / "certificate.json"
        self.token_path = bridge_root / "cloudflare-dns-api-token"
        self.acme_dir = bridge_root / "acme-zerossl"
        self.legacy_cross_cert_path = Path(__file__).with_name("SectigoPublicServerAuthenticationRootR46_USERTrust.pem")
        self.cert_dir = technitium_config_dir / "certificates"
        self.cert_pem_path = self.cert_dir / "dns-tls.crt.pem"
        self.key_pem_path = self.cert_dir / "dns-tls.key.pem"
        self.pfx_path = self.cert_dir / "dns-tls.pfx"
        self.lock = threading.RLock()
        self.running = False
        self.last_error: str | None = None
        self.last_output = ""
        self.last_attempt: str | None = None
        self.last_success: str | None = None
        self.last_dns_sync: str | None = None
        self.last_dns_error: str | None = None
        self.last_dns_action: str | None = None
        self.stop_event = threading.Event()
        self.auto_thread: threading.Thread | None = None
        self._ensure_dirs()
        if not self.config_path.exists():
            self._write_config(DEFAULT_CERT_CONFIG)

    def _ensure_dirs(self) -> None:
        for path in (self.bridge_root, self.acme_dir, self.cert_dir):
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.bridge_root, 0o700)
        os.chmod(self.acme_dir, 0o700)
        os.chmod(self.cert_dir, 0o700)

    def _read_config(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        cfg = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        raw_ca = ""
        if isinstance(raw, Mapping):
            raw_ca = str(raw.get("acme_ca") or "").strip().lower()
            cfg.update({k: raw.get(k, cfg[k]) for k in cfg})
        cfg["format"] = CERT_CONFIG_FORMAT
        cfg["acme_ca"] = ACME_CA
        cfg["mode"] = "cloudflare" if cfg.get("mode") == "cloudflare" else "manual"
        cfg["domain"] = str(cfg.get("domain") or "").strip().lower().rstrip(".")
        cfg["email"] = str(cfg.get("email") or "").strip()
        cfg["auto_renew"] = bool(cfg.get("auto_renew"))
        cfg["accept_tos"] = bool(cfg.get("accept_tos"))
        if cfg["mode"] == "cloudflare" and raw_ca != ACME_CA:
            # Consent to another CA's terms cannot be carried over automatically.
            cfg["accept_tos"] = False
        cfg["manage_dns_record"] = bool(cfg.get("manage_dns_record", True))
        cfg["dns_target"] = str(cfg.get("dns_target") or "").strip()
        return cfg

    def _write_config(self, cfg: Mapping[str, Any]) -> None:
        document = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        document.update({k: cfg.get(k, document[k]) for k in document})
        document["format"] = CERT_CONFIG_FORMAT
        document["updated_at"] = now_iso()
        _safe_write(self.config_path, json.dumps(document, indent=2, sort_keys=True) + "\n")

    @staticmethod
    def _validate_domain(value: Any) -> str:
        domain = str(value or "").strip().lower().rstrip(".")
        if not domain or len(domain) > 253 or not HOST_RE.fullmatch(domain) or ".." in domain:
            raise ValueError("Certificate domain must be a valid hostname.")
        try:
            socket.inet_pton(socket.AF_INET, domain)
            raise ValueError("Certificate domain must be a hostname, not an IP address.")
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, domain)
            raise ValueError("Certificate domain must be a hostname, not an IP address.")
        except OSError:
            pass
        if "." not in domain:
            raise ValueError("Certificate domain must be a fully qualified hostname.")
        return domain

    @staticmethod
    def _validate_email(value: Any) -> str:
        email = str(value or "").strip()
        if not EMAIL_RE.fullmatch(email) or len(email) > 254:
            raise ValueError("A valid ACME email address is required.")
        return email

    def export_config(self) -> dict[str, Any]:
        with self.lock:
            cfg = self._read_config()
        cfg.pop("updated_at", None)
        return cfg

    def import_config(self, cfg: Any) -> None:
        if not isinstance(cfg, Mapping):
            return
        mode = "cloudflare" if cfg.get("mode") == "cloudflare" else "manual"
        document = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        document["mode"] = mode
        document["acme_ca"] = ACME_CA
        if mode == "cloudflare":
            domain = str(cfg.get("domain") or "").strip()
            email = str(cfg.get("email") or "").strip()
            if domain:
                document["domain"] = self._validate_domain(domain)
            if email:
                document["email"] = self._validate_email(email)
            document["auto_renew"] = bool(cfg.get("auto_renew"))
            document["accept_tos"] = bool(cfg.get("accept_tos")) and str(cfg.get("acme_ca") or "").strip().lower() == ACME_CA
            document["manage_dns_record"] = bool(cfg.get("manage_dns_record", True))
            document["dns_target"] = str(cfg.get("dns_target") or "").strip()
        self._write_config(document)

    @staticmethod
    def _frp_ipv4(frpc_toml: str) -> str:
        match = re.search(r'(?mi)^\s*serverAddr\s*=\s*"([^"]+)"\s*$', frpc_toml)
        if not match:
            raise ValueError("Could not find serverAddr in the saved frpc.toml.")
        host = match.group(1).strip()
        try:
            socket.inet_pton(socket.AF_INET, host)
            return host
        except OSError:
            pass
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"FRPS hostname {host!r} could not be resolved to IPv4.") from exc
        addresses = sorted({info[4][0] for info in infos if info and info[4]})
        if not addresses:
            raise ValueError(f"FRPS hostname {host!r} has no IPv4 address for an A record.")
        return addresses[0]

    @staticmethod
    def _cloudflare_error_message(payload: Any) -> str:
        if not isinstance(payload, Mapping):
            return "unknown Cloudflare API error"
        errors = payload.get("errors")
        if isinstance(errors, list):
            messages = []
            for item in errors:
                if isinstance(item, Mapping):
                    message = str(item.get("message") or "").strip()
                    code = item.get("code")
                    if message:
                        messages.append(f"{code}: {message}" if code is not None else message)
            if messages:
                return "; ".join(messages)
        return str(payload.get("message") or "unknown Cloudflare API error")

    def _cloudflare_api(
        self,
        token: str,
        method: str,
        path: str,
        query: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = "https://api.cloudflare.com/client/v4" + path
        if query:
            url += "?" + urlencode({key: value for key, value in query.items() if value is not None})
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "dns-bridge/1",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=payload, headers=headers, method=method)
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as exc:
            try:
                error_payload = json.loads(exc.read().decode("utf-8", "replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                error_payload = {}
            raise ValueError(
                f"Cloudflare API HTTP {exc.code}: {self._cloudflare_error_message(error_payload)}"
            ) from exc
        except URLError as exc:
            raise ValueError(f"Cloudflare API request failed: {exc.reason}") from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Cloudflare API returned invalid JSON.") from exc
        if not isinstance(parsed, dict) or not parsed.get("success"):
            raise ValueError("Cloudflare API error: " + self._cloudflare_error_message(parsed))
        return parsed

    def _find_cloudflare_zone(self, token: str, domain: str) -> tuple[str, str]:
        labels = domain.rstrip(".").split(".")
        # Try the FQDN and then progressively shorter suffixes. The first
        # active Cloudflare zone returned is the most-specific matching zone.
        for index in range(max(1, len(labels) - 1)):
            candidate = ".".join(labels[index:])
            if "." not in candidate:
                continue
            response = self._cloudflare_api(
                token,
                "GET",
                "/zones",
                {"name": candidate, "status": "active", "per_page": 1},
            )
            result = response.get("result")
            if isinstance(result, list) and result:
                zone = result[0]
                if isinstance(zone, Mapping) and zone.get("id") and str(zone.get("name", "")).lower() == candidate.lower():
                    return str(zone["id"]), str(zone["name"])
        raise ValueError(
            f"Cloudflare zone for {domain} was not found. The token needs Zone Read access to the zone."
        )

    def _sync_cloudflare_a_record(self, domain: str, target: str, token: str) -> dict[str, str]:
        try:
            socket.inet_pton(socket.AF_INET, target)
        except OSError as exc:
            raise ValueError(f"Cloudflare A-record target {target!r} is not a valid IPv4 address.") from exc

        zone_id, zone_name = self._find_cloudflare_zone(token, domain)
        records_response = self._cloudflare_api(
            token,
            "GET",
            f"/zones/{zone_id}/dns_records",
            {"name": domain, "per_page": 100},
        )
        records = records_response.get("result")
        if not isinstance(records, list):
            records = []

        a_record = None
        conflicting = []
        for record in records:
            if not isinstance(record, Mapping):
                continue
            record_type = str(record.get("type") or "").upper()
            if record_type == "A" and a_record is None:
                a_record = record
            elif record_type in {"CNAME", "NS"}:
                conflicting.append(record_type)

        body = {
            "type": "A",
            "name": domain,
            "content": target,
            "ttl": 1,
            "proxied": False,
        }
        if a_record is not None and a_record.get("id"):
            current_content = str(a_record.get("content") or "")
            current_proxied = bool(a_record.get("proxied"))
            if current_content == target and not current_proxied:
                action = "unchanged"
            else:
                self._cloudflare_api(
                    token,
                    "PATCH",
                    f"/zones/{zone_id}/dns_records/{a_record['id']}",
                    body=body,
                )
                action = "updated"
        else:
            if conflicting:
                kinds = ", ".join(sorted(set(conflicting)))
                raise ValueError(
                    f"Cannot create A record for {domain}: a conflicting {kinds} record already exists."
                )
            self._cloudflare_api(
                token,
                "POST",
                f"/zones/{zone_id}/dns_records",
                body=body,
            )
            action = "created"

        with self.lock:
            self.last_dns_sync = now_iso()
            self.last_dns_error = None
            self.last_dns_action = action
        return {"action": action, "zone": zone_name, "name": domain, "target": target}

    def save_cloudflare(self, payload: Mapping[str, Any], frpc_toml: str) -> dict[str, str] | None:
        domain = self._validate_domain(payload.get("domain"))
        email = self._validate_email(payload.get("email"))
        api_token = str(payload.get("api_token") or "")
        if len(api_token) > 4096:
            raise ValueError("Cloudflare API token is too long.")
        clear_token = _bool(payload.get("clear_token", False), "clear_token")
        manage_dns_record = _bool(payload.get("manage_dns_record", True), "manage_dns_record")
        dns_target = self._frp_ipv4(frpc_toml) if manage_dns_record else ""
        cfg = {
            "format": CERT_CONFIG_FORMAT,
            "acme_ca": ACME_CA,
            "mode": "cloudflare",
            "domain": domain,
            "email": email,
            "auto_renew": _bool(payload.get("auto_renew", True), "auto_renew"),
            "accept_tos": _bool(payload.get("accept_tos", False), "accept_tos"),
            "manage_dns_record": manage_dns_record,
            "dns_target": dns_target,
        }
        with self.lock:
            self._write_config(cfg)
            if api_token:
                _safe_write(self.token_path, api_token.strip() + "\n")
            elif clear_token:
                try:
                    self.token_path.unlink()
                except FileNotFoundError:
                    pass

        if not manage_dns_record:
            with self.lock:
                self.last_dns_error = None
                self.last_dns_action = None
            return None

        if not self.token_path.is_file():
            raise ValueError("Cloudflare API token is required to create or update the DNS A record.")
        token = self.token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("Cloudflare API token is empty.")
        try:
            return self._sync_cloudflare_a_record(domain, dns_target, token)
        except ValueError as exc:
            with self.lock:
                self.last_dns_error = str(exc)
            raise

    def _openssl(self, args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        try:
            completed = subprocess.run(
                [self.openssl_binary, *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"OpenSSL failed: {exc}") from exc
        if completed.returncode != 0:
            raise ValueError("OpenSSL failed: " + (completed.stdout or "unknown error")[-4000:])
        return completed

    def _install_pem(self, certificate_pem: str, private_key_pem: str) -> None:
        if "-----BEGIN CERTIFICATE-----" not in certificate_pem:
            raise ValueError("Certificate file is not PEM encoded.")
        if "-----BEGIN " not in private_key_pem or "PRIVATE KEY-----" not in private_key_pem:
            raise ValueError("Private key file is not PEM encoded.")
        temp_cert = self.cert_dir / ".dns-tls.crt.tmp"
        temp_key = self.cert_dir / ".dns-tls.key.tmp"
        temp_pfx = self.cert_dir / ".dns-tls.pfx.tmp"
        _safe_write(temp_cert, certificate_pem.rstrip() + "\n")
        _safe_write(temp_key, private_key_pem.rstrip() + "\n")
        try:
            cert_pub = self._openssl(["x509", "-in", str(temp_cert), "-pubkey", "-noout"]).stdout
            key_pub = self._openssl(["pkey", "-in", str(temp_key), "-pubout"]).stdout
            if hashlib.sha256(cert_pub.encode()).digest() != hashlib.sha256(key_pub.encode()).digest():
                raise ValueError("Certificate and private key do not match.")
            self._openssl([
                "pkcs12", "-export",
                "-out", str(temp_pfx),
                "-inkey", str(temp_key),
                "-in", str(temp_cert),
                "-passout", "pass:",
            ])
            os.chmod(temp_pfx, 0o600)
            os.replace(temp_cert, self.cert_pem_path)
            os.replace(temp_key, self.key_pem_path)
            os.replace(temp_pfx, self.pfx_path)
            os.chmod(self.cert_pem_path, 0o600)
            os.chmod(self.key_pem_path, 0o600)
            os.chmod(self.pfx_path, 0o600)
        finally:
            for path in (temp_cert, temp_key, temp_pfx):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

    def import_manual(self, certificate_pem: str, private_key_pem: str) -> None:
        with self.lock:
            self._install_pem(certificate_pem, private_key_pem)
            cfg = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
            cfg["mode"] = "manual"
            cfg["auto_renew"] = False
            self._write_config(cfg)
            self.last_error = None
            self.last_success = now_iso()
            self.last_output = "Manual certificate imported and converted to PKCS#12."

    def _expiry(self) -> str | None:
        if not self.cert_pem_path.is_file():
            return None
        try:
            output = self._openssl(["x509", "-in", str(self.cert_pem_path), "-noout", "-enddate"]).stdout.strip()
            return output.split("=", 1)[1] if "=" in output else output
        except ValueError:
            return None

    def _expires_within(self, days: int) -> bool:
        if not self.cert_pem_path.is_file():
            return True
        try:
            completed = subprocess.run(
                [self.openssl_binary, "x509", "-in", str(self.cert_pem_path), "-noout", "-checkend", str(days * 86400)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            return completed.returncode != 0
        except (OSError, subprocess.TimeoutExpired):
            return True

    def _legacy_cross_certificate_pem(self) -> str:
        if not self.legacy_cross_cert_path.is_file():
            raise ValueError(
                "Bundled Sectigo R46 USERTrust cross certificate is missing; "
                "cannot build the Android-compatible ZeroSSL chain."
            )
        pem = self.legacy_cross_cert_path.read_text(encoding="utf-8").strip() + "\n"
        try:
            info = self._openssl([
                "x509", "-in", str(self.legacy_cross_cert_path), "-noout",
                "-subject", "-issuer", "-fingerprint", "-sha256"
            ]).stdout
        except ValueError as exc:
            raise ValueError(f"Bundled ZeroSSL compatibility certificate is invalid: {exc}") from exc
        lowered = info.lower()
        if "sectigo public server authentication root r46" not in lowered:
            raise ValueError("Bundled ZeroSSL compatibility certificate has the wrong subject.")
        if "usertrust rsa certification authority" not in lowered:
            raise ValueError("Bundled ZeroSSL compatibility certificate is not USERTrust cross-signed.")
        fingerprint = re.sub(r"[^0-9A-F]", "", info.upper().split("SHA256 FINGERPRINT=", 1)[-1])
        if fingerprint != LEGACY_CROSS_CERT_SHA256:
            raise ValueError("Bundled ZeroSSL compatibility certificate fingerprint does not match the pinned Sectigo R46 cross-certificate.")
        return pem

    def _installed_chain_has_legacy_cross_certificate(self) -> bool:
        if not self.cert_pem_path.is_file():
            return False
        try:
            installed = self.cert_pem_path.read_text(encoding="utf-8")
            cross = self._legacy_cross_certificate_pem().strip()
        except (OSError, ValueError):
            return False
        return cross in installed

    def _install_lego_certificate(self, domain: str) -> None:
        cert, key, issuer = self._find_lego_certificates(domain)
        certificate_pem = cert.read_text(encoding="utf-8").strip() + "\n"
        if issuer is not None:
            certificate_pem = certificate_pem.rstrip() + "\n" + issuer.read_text(encoding="utf-8").strip() + "\n"
        # ZeroSSL's current RSA intermediate chains to Sectigo R46. Android 13
        # predates R46's addition to AOSP's CA store, so append Sectigo's official
        # R46 cross-certificate to the long-standing USERTrust RSA root.
        certificate_pem = certificate_pem.rstrip() + "\n" + self._legacy_cross_certificate_pem()
        private_key_pem = key.read_text(encoding="utf-8")
        self._install_pem(certificate_pem, private_key_pem)

    def _find_lego_certificates(self, domain: str) -> tuple[Path, Path, Path | None]:
        base = self.acme_dir / "certificates"
        cert = base / f"{domain}.crt"
        key = base / f"{domain}.key"
        issuer = base / f"{domain}.issuer.crt"
        if not cert.is_file() or not key.is_file():
            raise ValueError("ACME client completed but certificate files were not found.")
        return cert, key, issuer if issuer.is_file() else None

    def _certificate_key_algorithm(self, path: Path | None = None) -> str | None:
        certificate = path if path is not None else self.cert_pem_path
        if not certificate.is_file():
            return None
        try:
            output = self._openssl(["x509", "-in", str(certificate), "-noout", "-text"]).stdout
        except ValueError:
            return None
        if "Public Key Algorithm: rsaEncryption" in output:
            return "RSA"
        if "Public Key Algorithm: id-ecPublicKey" in output:
            return "EC"
        return "OTHER"

    def _build_lego_command(
        self,
        domain: str,
        email: str,
        first_issue: bool,
        force_compat_reissue: bool = False,
    ) -> list[str]:
        # Use ZeroSSL RSA2048 intentionally for the Android 13 compatibility A/B test.
        # Keep this ACME state in its own directory so the previous Let's Encrypt
        # account/certificate material remains intact for rollback.
        command = [
            self.lego_binary,
            "run",
            "--server", ACME_CA,
            "--email", email,
            "--dns", "cloudflare",
            "--domains", domain,
            "--path", str(self.acme_dir),
            "--key-type", "RSA2048",
        ]
        if first_issue:
            command.append("--accept-tos")
        elif force_compat_reissue:
            command.extend(["--renew-force", "--no-random-sleep"])
        else:
            command.extend(["--renew-days", "30", "--no-random-sleep"])
        return command

    def _run_cloudflare(self) -> None:
        with self.lock:
            cfg = self._read_config()
        if cfg.get("mode") != "cloudflare":
            raise ValueError("Cloudflare ACME mode is not configured.")
        domain = self._validate_domain(cfg.get("domain"))
        email = self._validate_email(cfg.get("email"))
        if not self.token_path.is_file():
            raise ValueError("Cloudflare API token is not configured.")
        token = self.token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("Cloudflare API token is empty.")
        lego_cert_path = self.acme_dir / "certificates" / f"{domain}.crt"
        first_issue = not lego_cert_path.is_file()
        current_key_algorithm = self._certificate_key_algorithm(lego_cert_path)
        force_compat_reissue = bool(not first_issue and current_key_algorithm != "RSA")
        if first_issue and not cfg.get("accept_tos"):
            raise ValueError("Accept the ACME / ZeroSSL terms before requesting the first certificate.")
        if cfg.get("manage_dns_record"):
            target = str(cfg.get("dns_target") or "").strip()
            if not target:
                raise ValueError("Automatic Cloudflare A-record target is missing. Save the Cloudflare settings again.")
            self._sync_cloudflare_a_record(domain, target, token)

        if not first_issue and not force_compat_reissue and not self._expires_within(30):
            if not self._installed_chain_has_legacy_cross_certificate():
                self._install_lego_certificate(domain)
                self.last_output = (
                    "Reinstalled the existing ZeroSSL certificate with the Sectigo R46 "
                    "USERTrust cross-signed compatibility chain for Android 13."
                )
            else:
                self.last_output = "Certificate is already RSA, Android-compatible, and valid for more than 30 days; renewal is not due."
            return

        command = self._build_lego_command(
            domain,
            email,
            first_issue,
            force_compat_reissue=force_compat_reissue,
        )

        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.bridge_root),
            "TMPDIR": "/tmp",
            "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
            "CLOUDFLARE_DNS_API_TOKEN": token,
        }
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=600,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"ACME client failed: {exc}") from exc
        output = (completed.stdout or "").strip()
        self.last_output = output[-12000:]
        if completed.returncode != 0:
            raise ValueError("ACME client failed: " + (output[-4000:] or "unknown error"))

        self._install_lego_certificate(domain)

    def _worker(self) -> None:
        try:
            with self.lock:
                self.last_attempt = now_iso()
                self.last_error = None
            self._run_cloudflare()
            with self.lock:
                self.last_success = now_iso()
        except ValueError as exc:
            with self.lock:
                self.last_error = str(exc)
        finally:
            with self.lock:
                self.running = False

    def request_renew(self) -> bool:
        with self.lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._worker, name="certificate-renew", daemon=True).start()
        return True

    def _auto_loop(self) -> None:
        # Run the first certificate check shortly after container startup. A missing
        # ZeroSSL certificate state means this deployment still needs the CA migration.
        if self.stop_event.wait(10):
            return
        while not self.stop_event.is_set():
            try:
                with self.lock:
                    cfg = self._read_config()
                    should_check = cfg.get("mode") == "cloudflare" and bool(cfg.get("auto_renew")) and self.token_path.is_file()
                lego_cert_path = self.acme_dir / "certificates" / f"{cfg.get('domain', '')}.crt"
                needs_ca_migration = bool(should_check and not lego_cert_path.is_file())
                needs_android_compat = bool(
                    should_check
                    and lego_cert_path.is_file()
                    and self._certificate_key_algorithm(lego_cert_path) != "RSA"
                )
                needs_legacy_chain = bool(
                    should_check
                    and lego_cert_path.is_file()
                    and not self._installed_chain_has_legacy_cross_certificate()
                )
                if should_check and (needs_ca_migration or needs_android_compat or needs_legacy_chain or self._expires_within(30)):
                    self.request_renew()
            except Exception as exc:
                with self.lock:
                    self.last_error = f"Auto-renew check failed: {exc}"
            if self.stop_event.wait(6 * 3600):
                break

    def start(self) -> None:
        self.auto_thread = threading.Thread(target=self._auto_loop, name="certificate-auto-renew", daemon=True)
        self.auto_thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.auto_thread and self.auto_thread.is_alive():
            self.auto_thread.join(timeout=5)

    def status(self) -> dict[str, Any]:
        with self.lock:
            cfg = self._read_config()
            return {
                "mode": cfg.get("mode"),
                "domain": cfg.get("domain"),
                "email": cfg.get("email"),
                "auto_renew": bool(cfg.get("auto_renew")),
                "accept_tos": bool(cfg.get("accept_tos")),
                "manage_dns_record": bool(cfg.get("manage_dns_record", True)),
                "dns_target": str(cfg.get("dns_target") or ""),
                "dns_record_last_sync": self.last_dns_sync,
                "dns_record_last_action": self.last_dns_action,
                "dns_record_last_error": self.last_dns_error,
                "cloudflare_token_configured": self.token_path.is_file() and self.token_path.stat().st_size > 0,
                "pfx_path": str(self.pfx_path),
                "pfx_password": "",
                "certificate_exists": self.pfx_path.is_file(),
                "acme_ca": ACME_CA_LABEL if cfg.get("mode") == "cloudflare" else None,
                "key_algorithm": self._certificate_key_algorithm(),
                "legacy_cross_chain_installed": self._installed_chain_has_legacy_cross_certificate() if cfg.get("mode") == "cloudflare" else None,
                "android_legacy_compatible": bool(
                    self._certificate_key_algorithm() == "RSA"
                    and (cfg.get("mode") != "cloudflare" or self._installed_chain_has_legacy_cross_certificate())
                ),
                "expires": self._expiry(),
                "running": self.running,
                "last_attempt": self.last_attempt,
                "last_success": self.last_success,
                "last_error": self.last_error,
                "last_output": self.last_output,
            }


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


class BridgeApp:
    def __init__(self, store: ConfigStore, supervisor: FrpcSupervisor, certificates: CertificateManager, index_file: Path) -> None:
        self.store = store
        self.supervisor = supervisor
        self.certificates = certificates
        self.index_file = index_file

    @staticmethod
    def technitium_ready() -> bool:
        targets = ["127.0.0.1"]
        try:
            resolved = socket.gethostbyname(socket.gethostname())
            if resolved not in targets:
                targets.append(resolved)
        except OSError:
            pass
        for host in targets:
            try:
                with socket.create_connection((host, 5380), timeout=0.5):
                    return True
            except OSError:
                continue
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
                    cert_status = app.certificates.status()
                    self._json({
                        "ok": True,
                        "config": app.store.public_config(),
                        "technitium_ready": app.technitium_ready(),
                        "public_health": {
                            "dot_local_ready": app.supervisor._tcp_probe(DOT_TLS_PROXY_PORT),
                            "certificate_exists": bool(cert_status.get("certificate_exists")),
                            "certificate_key_algorithm": cert_status.get("key_algorithm"),
                            "certificate_acme_ca": cert_status.get("acme_ca"),
                            "certificate_legacy_cross_chain_installed": cert_status.get("legacy_cross_chain_installed"),
                            "android_legacy_compatible": bool(cert_status.get("android_legacy_compatible")),
                            "certificate_last_error": cert_status.get("last_error"),
                        },
                    })
                    return
                if not path.startswith("/_bridge/api/"):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                if not self._require_auth():
                    return
                if path == "/_bridge/api/status":
                    self._json({"ok": True, "config": app.store.public_config(), "frpc": app.supervisor.status(), "certificate": app.certificates.status(), "technitium_ready": app.technitium_ready()})
                elif path == "/_bridge/api/backup":
                    backup = app.store.export_backup()
                    backup["certificate"] = app.certificates.export_config()
                    payload = json.dumps(backup, indent=2).encode()
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
                        app.certificates.import_config(backup.get("certificate"))
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
                    if path == "/_bridge/api/frpc-toml":
                        enabled = _bool(data.get("enabled", False), "enabled")
                        text = sanitize_frpc_toml(data.get("toml", ""))
                        if enabled:
                            text = app.supervisor.verify_toml(text)
                        config = app.store.save_frpc_toml(text, enabled)
                        app.supervisor.reload()
                        self._json({"ok": True, "config": config})
                    elif path == "/_bridge/api/certificate/import":
                        certificate_pem = str(data.get("certificate_pem") or "")
                        private_key_pem = str(data.get("private_key_pem") or "")
                        app.certificates.import_manual(certificate_pem, private_key_pem)
                        self._json({"ok": True, "certificate": app.certificates.status()})
                    elif path == "/_bridge/api/certificate/cloudflare":
                        dns_record = app.certificates.save_cloudflare(data, app.store.get_frpc_toml())
                        self._json({"ok": True, "certificate": app.certificates.status(), "dns_record": dns_record})
                    elif path == "/_bridge/api/certificate/renew":
                        started = app.certificates.request_renew()
                        self._json({"ok": True, "started": started, "certificate": app.certificates.status()})
                    elif path == "/_bridge/api/settings":
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
                        app.certificates.import_config(backup.get("certificate"))
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
    parser.add_argument("--technitium-config-dir", default=os.environ.get("TECHNITIUM_CONFIG_DIR", "/data/technitium"))
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
    certificates = CertificateManager(root, Path(args.technitium_config_dir))
    dot_tls_proxy = DotTlsProxy(certificates.cert_pem_path, certificates.key_pem_path)
    dot_tls_proxy.start()
    supervisor.start()
    certificates.start()
    app = BridgeApp(store, supervisor, certificates, Path(args.index_file))
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
        certificates.stop()
        dot_tls_proxy.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
, block)
        ptype = re.search(r'(?m)^\s*type\s*=\s*"([^"]+)"\s*(path: Path, content: str, mode: int = 0o600) -> None:
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
                "frpc_toml": render_frpc_toml(DEFAULT_CONFIG),
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
                "frpc_toml": render_frpc_toml(frp),
                "migration": {"source": str(path), "migrated_at": now_iso()},
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None

    def _read(self) -> dict[str, Any]:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("format") != CONFIG_FORMAT:
            raise ValueError("Unsupported bridge configuration format.")
        changed = False
        frp = raw.get("frp")
        if not isinstance(frp, dict):
            frp = json.loads(json.dumps(DEFAULT_CONFIG))
            raw["frp"] = frp
            changed = True
        if "auth_token" in frp:
            frp.pop("auth_token", None)
            changed = True
        proxies = frp.get("proxies")
        if isinstance(proxies, dict):
            for obsolete in ("dns_tcp", "dns_udp"):
                if obsolete in proxies:
                    proxies.pop(obsolete, None)
                    changed = True
        normalized_frp = validate_frp(frp, require_server_addr=False)
        if normalized_frp != frp:
            raw["frp"] = normalized_frp
            frp = normalized_frp
            changed = True
        raw_toml = raw.get("frpc_toml")
        if not isinstance(raw_toml, str):
            raw["frpc_toml"] = render_frpc_toml(frp)
            changed = True
        else:
            cleaned = sanitize_frpc_toml(raw_toml)
            if cleaned != raw_toml:
                raw["frpc_toml"] = cleaned
                changed = True
        if changed:
            raw["updated_at"] = now_iso()
            _safe_write(self.path, json.dumps(raw, indent=2, sort_keys=True) + "\n")
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

    def get_frpc_toml(self) -> str:
        with self.lock:
            doc = self._read()
            return sanitize_frpc_toml(doc.get("frpc_toml", render_frpc_toml(doc.get("frp", DEFAULT_CONFIG))))

    def save_frpc_toml(self, text: str, enabled: bool) -> dict[str, Any]:
        cleaned = sanitize_frpc_toml(text)
        with self.lock:
            doc = self._read()
            frp = validate_frp(doc.get("frp", DEFAULT_CONFIG), require_server_addr=False)
            frp["enabled"] = bool(enabled)
            doc["frp"] = frp
            doc["frpc_toml"] = cleaned
            doc["updated_at"] = now_iso()
            self._write(doc)
        return self.public_config()

    def public_config(self) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
        frp = validate_frp(doc.get("frp", DEFAULT_CONFIG), require_server_addr=False)
        return {
            "format": CONFIG_FORMAT,
            "setup_required": not bool(doc.get("admin", {}).get("username")),
            "username": str(doc.get("admin", {}).get("username", "")),
            "frp": frp,
            "frpc_toml": sanitize_frpc_toml(doc.get("frpc_toml", render_frpc_toml(frp))),
            "migration": doc.get("migration"),
            "updated_at": doc.get("updated_at"),
        }

    def save_frp(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
            frp = validate_frp(payload, doc.get("frp", DEFAULT_CONFIG))
            doc["frp"] = frp
            doc["frpc_toml"] = render_frpc_toml(frp)
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
            "warning": "This backup contains FRP connection settings and the bridge administrator password hash. Store it securely.",
        }

    def import_backup(self, backup: Mapping[str, Any]) -> None:
        fmt = backup.get("format")
        if fmt == BACKUP_FORMAT:
            candidate = backup.get("config")
            if not isinstance(candidate, Mapping) or candidate.get("format") != CONFIG_FORMAT:
                raise ValueError("Bridge backup is incomplete.")
            frp = validate_frp(candidate.get("frp", {}), require_server_addr=False)
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
                "frpc_toml": sanitize_frpc_toml(candidate.get("frpc_toml", render_frpc_toml(frp))),
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
            doc["frpc_toml"] = render_frpc_toml(frp)
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

    def _write_config(self, text: str) -> None:
        _safe_write(self.store.frpc_path, sanitize_frpc_toml(text))

    def _config_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def verify_toml(self, text: str) -> str:
        cleaned = sanitize_frpc_toml(text)
        if not cleaned:
            raise ValueError("frpc.toml cannot be empty.")
        verify_path = self.store.root / "frpc.verify.toml"
        _safe_write(verify_path, cleaned)
        try:
            completed = subprocess.run(
                [self.frpc_binary, "verify", "-c", str(verify_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "HOME": "/tmp",
                    "TMPDIR": "/tmp",
                    "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"Unable to verify frpc.toml: {exc}") from exc
        finally:
            try:
                verify_path.unlink()
            except OSError:
                pass
        output = (completed.stdout or "").strip()
        if completed.returncode != 0:
            raise ValueError("frpc.toml validation failed: " + (output[-4000:] or "unknown error"))
        return cleaned

    def _run(self) -> None:
        backoff = 1.0
        while not self.stop_event.is_set():
            try:
                frp = self.store.get_frp()
                config_text = self.store.get_frpc_toml()
                desired = bool(frp.get("enabled") and config_text.strip())
                config_hash = self._config_hash(config_text)
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

                self._write_config(config_text)
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
        probes: dict[str, bool | None] = {
            "dot_853": self._tcp_probe(853),
            "doq_853": None,
        }
        return {
            "enabled": bool(frp.get("enabled")),
            "configured": bool(self.store.get_frpc_toml().strip()),
            "running": running,
            "pid": pid,
            "started_at": started_at,
            "last_exit_code": exit_code,
            "last_error": last_error,
            "restart_count": restarts,
            "local_service_probes": probes,
            "logs": logs,
        }



class CertificateManager:
    def __init__(
        self,
        bridge_root: Path,
        technitium_config_dir: Path,
        lego_binary: str = "/usr/local/bin/lego",
        openssl_binary: str = "/usr/bin/openssl",
    ) -> None:
        self.bridge_root = bridge_root
        self.technitium_config_dir = technitium_config_dir
        self.lego_binary = lego_binary
        self.openssl_binary = openssl_binary
        self.config_path = bridge_root / "certificate.json"
        self.token_path = bridge_root / "cloudflare-dns-api-token"
        self.acme_dir = bridge_root / "acme-zerossl"
        self.legacy_cross_cert_path = Path(__file__).with_name("SectigoPublicServerAuthenticationRootR46_USERTrust.pem")
        self.cert_dir = technitium_config_dir / "certificates"
        self.cert_pem_path = self.cert_dir / "dns-tls.crt.pem"
        self.key_pem_path = self.cert_dir / "dns-tls.key.pem"
        self.pfx_path = self.cert_dir / "dns-tls.pfx"
        self.lock = threading.RLock()
        self.running = False
        self.last_error: str | None = None
        self.last_output = ""
        self.last_attempt: str | None = None
        self.last_success: str | None = None
        self.last_dns_sync: str | None = None
        self.last_dns_error: str | None = None
        self.last_dns_action: str | None = None
        self.stop_event = threading.Event()
        self.auto_thread: threading.Thread | None = None
        self._ensure_dirs()
        if not self.config_path.exists():
            self._write_config(DEFAULT_CERT_CONFIG)

    def _ensure_dirs(self) -> None:
        for path in (self.bridge_root, self.acme_dir, self.cert_dir):
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.bridge_root, 0o700)
        os.chmod(self.acme_dir, 0o700)
        os.chmod(self.cert_dir, 0o700)

    def _read_config(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        cfg = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        raw_ca = ""
        if isinstance(raw, Mapping):
            raw_ca = str(raw.get("acme_ca") or "").strip().lower()
            cfg.update({k: raw.get(k, cfg[k]) for k in cfg})
        cfg["format"] = CERT_CONFIG_FORMAT
        cfg["acme_ca"] = ACME_CA
        cfg["mode"] = "cloudflare" if cfg.get("mode") == "cloudflare" else "manual"
        cfg["domain"] = str(cfg.get("domain") or "").strip().lower().rstrip(".")
        cfg["email"] = str(cfg.get("email") or "").strip()
        cfg["auto_renew"] = bool(cfg.get("auto_renew"))
        cfg["accept_tos"] = bool(cfg.get("accept_tos"))
        if cfg["mode"] == "cloudflare" and raw_ca != ACME_CA:
            # Consent to another CA's terms cannot be carried over automatically.
            cfg["accept_tos"] = False
        cfg["manage_dns_record"] = bool(cfg.get("manage_dns_record", True))
        cfg["dns_target"] = str(cfg.get("dns_target") or "").strip()
        return cfg

    def _write_config(self, cfg: Mapping[str, Any]) -> None:
        document = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        document.update({k: cfg.get(k, document[k]) for k in document})
        document["format"] = CERT_CONFIG_FORMAT
        document["updated_at"] = now_iso()
        _safe_write(self.config_path, json.dumps(document, indent=2, sort_keys=True) + "\n")

    @staticmethod
    def _validate_domain(value: Any) -> str:
        domain = str(value or "").strip().lower().rstrip(".")
        if not domain or len(domain) > 253 or not HOST_RE.fullmatch(domain) or ".." in domain:
            raise ValueError("Certificate domain must be a valid hostname.")
        try:
            socket.inet_pton(socket.AF_INET, domain)
            raise ValueError("Certificate domain must be a hostname, not an IP address.")
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, domain)
            raise ValueError("Certificate domain must be a hostname, not an IP address.")
        except OSError:
            pass
        if "." not in domain:
            raise ValueError("Certificate domain must be a fully qualified hostname.")
        return domain

    @staticmethod
    def _validate_email(value: Any) -> str:
        email = str(value or "").strip()
        if not EMAIL_RE.fullmatch(email) or len(email) > 254:
            raise ValueError("A valid ACME email address is required.")
        return email

    def export_config(self) -> dict[str, Any]:
        with self.lock:
            cfg = self._read_config()
        cfg.pop("updated_at", None)
        return cfg

    def import_config(self, cfg: Any) -> None:
        if not isinstance(cfg, Mapping):
            return
        mode = "cloudflare" if cfg.get("mode") == "cloudflare" else "manual"
        document = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        document["mode"] = mode
        document["acme_ca"] = ACME_CA
        if mode == "cloudflare":
            domain = str(cfg.get("domain") or "").strip()
            email = str(cfg.get("email") or "").strip()
            if domain:
                document["domain"] = self._validate_domain(domain)
            if email:
                document["email"] = self._validate_email(email)
            document["auto_renew"] = bool(cfg.get("auto_renew"))
            document["accept_tos"] = bool(cfg.get("accept_tos")) and str(cfg.get("acme_ca") or "").strip().lower() == ACME_CA
            document["manage_dns_record"] = bool(cfg.get("manage_dns_record", True))
            document["dns_target"] = str(cfg.get("dns_target") or "").strip()
        self._write_config(document)

    @staticmethod
    def _frp_ipv4(frpc_toml: str) -> str:
        match = re.search(r'(?mi)^\s*serverAddr\s*=\s*"([^"]+)"\s*$', frpc_toml)
        if not match:
            raise ValueError("Could not find serverAddr in the saved frpc.toml.")
        host = match.group(1).strip()
        try:
            socket.inet_pton(socket.AF_INET, host)
            return host
        except OSError:
            pass
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"FRPS hostname {host!r} could not be resolved to IPv4.") from exc
        addresses = sorted({info[4][0] for info in infos if info and info[4]})
        if not addresses:
            raise ValueError(f"FRPS hostname {host!r} has no IPv4 address for an A record.")
        return addresses[0]

    @staticmethod
    def _cloudflare_error_message(payload: Any) -> str:
        if not isinstance(payload, Mapping):
            return "unknown Cloudflare API error"
        errors = payload.get("errors")
        if isinstance(errors, list):
            messages = []
            for item in errors:
                if isinstance(item, Mapping):
                    message = str(item.get("message") or "").strip()
                    code = item.get("code")
                    if message:
                        messages.append(f"{code}: {message}" if code is not None else message)
            if messages:
                return "; ".join(messages)
        return str(payload.get("message") or "unknown Cloudflare API error")

    def _cloudflare_api(
        self,
        token: str,
        method: str,
        path: str,
        query: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = "https://api.cloudflare.com/client/v4" + path
        if query:
            url += "?" + urlencode({key: value for key, value in query.items() if value is not None})
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "dns-bridge/1",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=payload, headers=headers, method=method)
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as exc:
            try:
                error_payload = json.loads(exc.read().decode("utf-8", "replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                error_payload = {}
            raise ValueError(
                f"Cloudflare API HTTP {exc.code}: {self._cloudflare_error_message(error_payload)}"
            ) from exc
        except URLError as exc:
            raise ValueError(f"Cloudflare API request failed: {exc.reason}") from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Cloudflare API returned invalid JSON.") from exc
        if not isinstance(parsed, dict) or not parsed.get("success"):
            raise ValueError("Cloudflare API error: " + self._cloudflare_error_message(parsed))
        return parsed

    def _find_cloudflare_zone(self, token: str, domain: str) -> tuple[str, str]:
        labels = domain.rstrip(".").split(".")
        # Try the FQDN and then progressively shorter suffixes. The first
        # active Cloudflare zone returned is the most-specific matching zone.
        for index in range(max(1, len(labels) - 1)):
            candidate = ".".join(labels[index:])
            if "." not in candidate:
                continue
            response = self._cloudflare_api(
                token,
                "GET",
                "/zones",
                {"name": candidate, "status": "active", "per_page": 1},
            )
            result = response.get("result")
            if isinstance(result, list) and result:
                zone = result[0]
                if isinstance(zone, Mapping) and zone.get("id") and str(zone.get("name", "")).lower() == candidate.lower():
                    return str(zone["id"]), str(zone["name"])
        raise ValueError(
            f"Cloudflare zone for {domain} was not found. The token needs Zone Read access to the zone."
        )

    def _sync_cloudflare_a_record(self, domain: str, target: str, token: str) -> dict[str, str]:
        try:
            socket.inet_pton(socket.AF_INET, target)
        except OSError as exc:
            raise ValueError(f"Cloudflare A-record target {target!r} is not a valid IPv4 address.") from exc

        zone_id, zone_name = self._find_cloudflare_zone(token, domain)
        records_response = self._cloudflare_api(
            token,
            "GET",
            f"/zones/{zone_id}/dns_records",
            {"name": domain, "per_page": 100},
        )
        records = records_response.get("result")
        if not isinstance(records, list):
            records = []

        a_record = None
        conflicting = []
        for record in records:
            if not isinstance(record, Mapping):
                continue
            record_type = str(record.get("type") or "").upper()
            if record_type == "A" and a_record is None:
                a_record = record
            elif record_type in {"CNAME", "NS"}:
                conflicting.append(record_type)

        body = {
            "type": "A",
            "name": domain,
            "content": target,
            "ttl": 1,
            "proxied": False,
        }
        if a_record is not None and a_record.get("id"):
            current_content = str(a_record.get("content") or "")
            current_proxied = bool(a_record.get("proxied"))
            if current_content == target and not current_proxied:
                action = "unchanged"
            else:
                self._cloudflare_api(
                    token,
                    "PATCH",
                    f"/zones/{zone_id}/dns_records/{a_record['id']}",
                    body=body,
                )
                action = "updated"
        else:
            if conflicting:
                kinds = ", ".join(sorted(set(conflicting)))
                raise ValueError(
                    f"Cannot create A record for {domain}: a conflicting {kinds} record already exists."
                )
            self._cloudflare_api(
                token,
                "POST",
                f"/zones/{zone_id}/dns_records",
                body=body,
            )
            action = "created"

        with self.lock:
            self.last_dns_sync = now_iso()
            self.last_dns_error = None
            self.last_dns_action = action
        return {"action": action, "zone": zone_name, "name": domain, "target": target}

    def save_cloudflare(self, payload: Mapping[str, Any], frpc_toml: str) -> dict[str, str] | None:
        domain = self._validate_domain(payload.get("domain"))
        email = self._validate_email(payload.get("email"))
        api_token = str(payload.get("api_token") or "")
        if len(api_token) > 4096:
            raise ValueError("Cloudflare API token is too long.")
        clear_token = _bool(payload.get("clear_token", False), "clear_token")
        manage_dns_record = _bool(payload.get("manage_dns_record", True), "manage_dns_record")
        dns_target = self._frp_ipv4(frpc_toml) if manage_dns_record else ""
        cfg = {
            "format": CERT_CONFIG_FORMAT,
            "acme_ca": ACME_CA,
            "mode": "cloudflare",
            "domain": domain,
            "email": email,
            "auto_renew": _bool(payload.get("auto_renew", True), "auto_renew"),
            "accept_tos": _bool(payload.get("accept_tos", False), "accept_tos"),
            "manage_dns_record": manage_dns_record,
            "dns_target": dns_target,
        }
        with self.lock:
            self._write_config(cfg)
            if api_token:
                _safe_write(self.token_path, api_token.strip() + "\n")
            elif clear_token:
                try:
                    self.token_path.unlink()
                except FileNotFoundError:
                    pass

        if not manage_dns_record:
            with self.lock:
                self.last_dns_error = None
                self.last_dns_action = None
            return None

        if not self.token_path.is_file():
            raise ValueError("Cloudflare API token is required to create or update the DNS A record.")
        token = self.token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("Cloudflare API token is empty.")
        try:
            return self._sync_cloudflare_a_record(domain, dns_target, token)
        except ValueError as exc:
            with self.lock:
                self.last_dns_error = str(exc)
            raise

    def _openssl(self, args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        try:
            completed = subprocess.run(
                [self.openssl_binary, *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"OpenSSL failed: {exc}") from exc
        if completed.returncode != 0:
            raise ValueError("OpenSSL failed: " + (completed.stdout or "unknown error")[-4000:])
        return completed

    def _install_pem(self, certificate_pem: str, private_key_pem: str) -> None:
        if "-----BEGIN CERTIFICATE-----" not in certificate_pem:
            raise ValueError("Certificate file is not PEM encoded.")
        if "-----BEGIN " not in private_key_pem or "PRIVATE KEY-----" not in private_key_pem:
            raise ValueError("Private key file is not PEM encoded.")
        temp_cert = self.cert_dir / ".dns-tls.crt.tmp"
        temp_key = self.cert_dir / ".dns-tls.key.tmp"
        temp_pfx = self.cert_dir / ".dns-tls.pfx.tmp"
        _safe_write(temp_cert, certificate_pem.rstrip() + "\n")
        _safe_write(temp_key, private_key_pem.rstrip() + "\n")
        try:
            cert_pub = self._openssl(["x509", "-in", str(temp_cert), "-pubkey", "-noout"]).stdout
            key_pub = self._openssl(["pkey", "-in", str(temp_key), "-pubout"]).stdout
            if hashlib.sha256(cert_pub.encode()).digest() != hashlib.sha256(key_pub.encode()).digest():
                raise ValueError("Certificate and private key do not match.")
            self._openssl([
                "pkcs12", "-export",
                "-out", str(temp_pfx),
                "-inkey", str(temp_key),
                "-in", str(temp_cert),
                "-passout", "pass:",
            ])
            os.chmod(temp_pfx, 0o600)
            os.replace(temp_cert, self.cert_pem_path)
            os.replace(temp_key, self.key_pem_path)
            os.replace(temp_pfx, self.pfx_path)
            os.chmod(self.cert_pem_path, 0o600)
            os.chmod(self.key_pem_path, 0o600)
            os.chmod(self.pfx_path, 0o600)
        finally:
            for path in (temp_cert, temp_key, temp_pfx):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

    def import_manual(self, certificate_pem: str, private_key_pem: str) -> None:
        with self.lock:
            self._install_pem(certificate_pem, private_key_pem)
            cfg = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
            cfg["mode"] = "manual"
            cfg["auto_renew"] = False
            self._write_config(cfg)
            self.last_error = None
            self.last_success = now_iso()
            self.last_output = "Manual certificate imported and converted to PKCS#12."

    def _expiry(self) -> str | None:
        if not self.cert_pem_path.is_file():
            return None
        try:
            output = self._openssl(["x509", "-in", str(self.cert_pem_path), "-noout", "-enddate"]).stdout.strip()
            return output.split("=", 1)[1] if "=" in output else output
        except ValueError:
            return None

    def _expires_within(self, days: int) -> bool:
        if not self.cert_pem_path.is_file():
            return True
        try:
            completed = subprocess.run(
                [self.openssl_binary, "x509", "-in", str(self.cert_pem_path), "-noout", "-checkend", str(days * 86400)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            return completed.returncode != 0
        except (OSError, subprocess.TimeoutExpired):
            return True

    def _legacy_cross_certificate_pem(self) -> str:
        if not self.legacy_cross_cert_path.is_file():
            raise ValueError(
                "Bundled Sectigo R46 USERTrust cross certificate is missing; "
                "cannot build the Android-compatible ZeroSSL chain."
            )
        pem = self.legacy_cross_cert_path.read_text(encoding="utf-8").strip() + "\n"
        try:
            info = self._openssl([
                "x509", "-in", str(self.legacy_cross_cert_path), "-noout",
                "-subject", "-issuer", "-fingerprint", "-sha256"
            ]).stdout
        except ValueError as exc:
            raise ValueError(f"Bundled ZeroSSL compatibility certificate is invalid: {exc}") from exc
        lowered = info.lower()
        if "sectigo public server authentication root r46" not in lowered:
            raise ValueError("Bundled ZeroSSL compatibility certificate has the wrong subject.")
        if "usertrust rsa certification authority" not in lowered:
            raise ValueError("Bundled ZeroSSL compatibility certificate is not USERTrust cross-signed.")
        fingerprint = re.sub(r"[^0-9A-F]", "", info.upper().split("SHA256 FINGERPRINT=", 1)[-1])
        if fingerprint != LEGACY_CROSS_CERT_SHA256:
            raise ValueError("Bundled ZeroSSL compatibility certificate fingerprint does not match the pinned Sectigo R46 cross-certificate.")
        return pem

    def _installed_chain_has_legacy_cross_certificate(self) -> bool:
        if not self.cert_pem_path.is_file():
            return False
        try:
            installed = self.cert_pem_path.read_text(encoding="utf-8")
            cross = self._legacy_cross_certificate_pem().strip()
        except (OSError, ValueError):
            return False
        return cross in installed

    def _install_lego_certificate(self, domain: str) -> None:
        cert, key, issuer = self._find_lego_certificates(domain)
        certificate_pem = cert.read_text(encoding="utf-8").strip() + "\n"
        if issuer is not None:
            certificate_pem = certificate_pem.rstrip() + "\n" + issuer.read_text(encoding="utf-8").strip() + "\n"
        # ZeroSSL's current RSA intermediate chains to Sectigo R46. Android 13
        # predates R46's addition to AOSP's CA store, so append Sectigo's official
        # R46 cross-certificate to the long-standing USERTrust RSA root.
        certificate_pem = certificate_pem.rstrip() + "\n" + self._legacy_cross_certificate_pem()
        private_key_pem = key.read_text(encoding="utf-8")
        self._install_pem(certificate_pem, private_key_pem)

    def _find_lego_certificates(self, domain: str) -> tuple[Path, Path, Path | None]:
        base = self.acme_dir / "certificates"
        cert = base / f"{domain}.crt"
        key = base / f"{domain}.key"
        issuer = base / f"{domain}.issuer.crt"
        if not cert.is_file() or not key.is_file():
            raise ValueError("ACME client completed but certificate files were not found.")
        return cert, key, issuer if issuer.is_file() else None

    def _certificate_key_algorithm(self, path: Path | None = None) -> str | None:
        certificate = path if path is not None else self.cert_pem_path
        if not certificate.is_file():
            return None
        try:
            output = self._openssl(["x509", "-in", str(certificate), "-noout", "-text"]).stdout
        except ValueError:
            return None
        if "Public Key Algorithm: rsaEncryption" in output:
            return "RSA"
        if "Public Key Algorithm: id-ecPublicKey" in output:
            return "EC"
        return "OTHER"

    def _build_lego_command(
        self,
        domain: str,
        email: str,
        first_issue: bool,
        force_compat_reissue: bool = False,
    ) -> list[str]:
        # Use ZeroSSL RSA2048 intentionally for the Android 13 compatibility A/B test.
        # Keep this ACME state in its own directory so the previous Let's Encrypt
        # account/certificate material remains intact for rollback.
        command = [
            self.lego_binary,
            "run",
            "--server", ACME_CA,
            "--email", email,
            "--dns", "cloudflare",
            "--domains", domain,
            "--path", str(self.acme_dir),
            "--key-type", "RSA2048",
        ]
        if first_issue:
            command.append("--accept-tos")
        elif force_compat_reissue:
            command.extend(["--renew-force", "--no-random-sleep"])
        else:
            command.extend(["--renew-days", "30", "--no-random-sleep"])
        return command

    def _run_cloudflare(self) -> None:
        with self.lock:
            cfg = self._read_config()
        if cfg.get("mode") != "cloudflare":
            raise ValueError("Cloudflare ACME mode is not configured.")
        domain = self._validate_domain(cfg.get("domain"))
        email = self._validate_email(cfg.get("email"))
        if not self.token_path.is_file():
            raise ValueError("Cloudflare API token is not configured.")
        token = self.token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("Cloudflare API token is empty.")
        lego_cert_path = self.acme_dir / "certificates" / f"{domain}.crt"
        first_issue = not lego_cert_path.is_file()
        current_key_algorithm = self._certificate_key_algorithm(lego_cert_path)
        force_compat_reissue = bool(not first_issue and current_key_algorithm != "RSA")
        if first_issue and not cfg.get("accept_tos"):
            raise ValueError("Accept the ACME / ZeroSSL terms before requesting the first certificate.")
        if cfg.get("manage_dns_record"):
            target = str(cfg.get("dns_target") or "").strip()
            if not target:
                raise ValueError("Automatic Cloudflare A-record target is missing. Save the Cloudflare settings again.")
            self._sync_cloudflare_a_record(domain, target, token)

        if not first_issue and not force_compat_reissue and not self._expires_within(30):
            if not self._installed_chain_has_legacy_cross_certificate():
                self._install_lego_certificate(domain)
                self.last_output = (
                    "Reinstalled the existing ZeroSSL certificate with the Sectigo R46 "
                    "USERTrust cross-signed compatibility chain for Android 13."
                )
            else:
                self.last_output = "Certificate is already RSA, Android-compatible, and valid for more than 30 days; renewal is not due."
            return

        command = self._build_lego_command(
            domain,
            email,
            first_issue,
            force_compat_reissue=force_compat_reissue,
        )

        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.bridge_root),
            "TMPDIR": "/tmp",
            "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
            "CLOUDFLARE_DNS_API_TOKEN": token,
        }
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=600,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"ACME client failed: {exc}") from exc
        output = (completed.stdout or "").strip()
        self.last_output = output[-12000:]
        if completed.returncode != 0:
            raise ValueError("ACME client failed: " + (output[-4000:] or "unknown error"))

        self._install_lego_certificate(domain)

    def _worker(self) -> None:
        try:
            with self.lock:
                self.last_attempt = now_iso()
                self.last_error = None
            self._run_cloudflare()
            with self.lock:
                self.last_success = now_iso()
        except ValueError as exc:
            with self.lock:
                self.last_error = str(exc)
        finally:
            with self.lock:
                self.running = False

    def request_renew(self) -> bool:
        with self.lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._worker, name="certificate-renew", daemon=True).start()
        return True

    def _auto_loop(self) -> None:
        # Run the first certificate check shortly after container startup. A missing
        # ZeroSSL certificate state means this deployment still needs the CA migration.
        if self.stop_event.wait(10):
            return
        while not self.stop_event.is_set():
            try:
                with self.lock:
                    cfg = self._read_config()
                    should_check = cfg.get("mode") == "cloudflare" and bool(cfg.get("auto_renew")) and self.token_path.is_file()
                lego_cert_path = self.acme_dir / "certificates" / f"{cfg.get('domain', '')}.crt"
                needs_ca_migration = bool(should_check and not lego_cert_path.is_file())
                needs_android_compat = bool(
                    should_check
                    and lego_cert_path.is_file()
                    and self._certificate_key_algorithm(lego_cert_path) != "RSA"
                )
                needs_legacy_chain = bool(
                    should_check
                    and lego_cert_path.is_file()
                    and not self._installed_chain_has_legacy_cross_certificate()
                )
                if should_check and (needs_ca_migration or needs_android_compat or needs_legacy_chain or self._expires_within(30)):
                    self.request_renew()
            except Exception as exc:
                with self.lock:
                    self.last_error = f"Auto-renew check failed: {exc}"
            if self.stop_event.wait(6 * 3600):
                break

    def start(self) -> None:
        self.auto_thread = threading.Thread(target=self._auto_loop, name="certificate-auto-renew", daemon=True)
        self.auto_thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.auto_thread and self.auto_thread.is_alive():
            self.auto_thread.join(timeout=5)

    def status(self) -> dict[str, Any]:
        with self.lock:
            cfg = self._read_config()
            return {
                "mode": cfg.get("mode"),
                "domain": cfg.get("domain"),
                "email": cfg.get("email"),
                "auto_renew": bool(cfg.get("auto_renew")),
                "accept_tos": bool(cfg.get("accept_tos")),
                "manage_dns_record": bool(cfg.get("manage_dns_record", True)),
                "dns_target": str(cfg.get("dns_target") or ""),
                "dns_record_last_sync": self.last_dns_sync,
                "dns_record_last_action": self.last_dns_action,
                "dns_record_last_error": self.last_dns_error,
                "cloudflare_token_configured": self.token_path.is_file() and self.token_path.stat().st_size > 0,
                "pfx_path": str(self.pfx_path),
                "pfx_password": "",
                "certificate_exists": self.pfx_path.is_file(),
                "acme_ca": ACME_CA_LABEL if cfg.get("mode") == "cloudflare" else None,
                "key_algorithm": self._certificate_key_algorithm(),
                "legacy_cross_chain_installed": self._installed_chain_has_legacy_cross_certificate() if cfg.get("mode") == "cloudflare" else None,
                "android_legacy_compatible": bool(
                    self._certificate_key_algorithm() == "RSA"
                    and (cfg.get("mode") != "cloudflare" or self._installed_chain_has_legacy_cross_certificate())
                ),
                "expires": self._expiry(),
                "running": self.running,
                "last_attempt": self.last_attempt,
                "last_success": self.last_success,
                "last_error": self.last_error,
                "last_output": self.last_output,
            }


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


class BridgeApp:
    def __init__(self, store: ConfigStore, supervisor: FrpcSupervisor, certificates: CertificateManager, index_file: Path) -> None:
        self.store = store
        self.supervisor = supervisor
        self.certificates = certificates
        self.index_file = index_file

    @staticmethod
    def technitium_ready() -> bool:
        targets = ["127.0.0.1"]
        try:
            resolved = socket.gethostbyname(socket.gethostname())
            if resolved not in targets:
                targets.append(resolved)
        except OSError:
            pass
        for host in targets:
            try:
                with socket.create_connection((host, 5380), timeout=0.5):
                    return True
            except OSError:
                continue
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
                    cert_status = app.certificates.status()
                    self._json({
                        "ok": True,
                        "config": app.store.public_config(),
                        "technitium_ready": app.technitium_ready(),
                        "public_health": {
                            "dot_local_ready": app.supervisor._tcp_probe(853),
                            "certificate_exists": bool(cert_status.get("certificate_exists")),
                            "certificate_key_algorithm": cert_status.get("key_algorithm"),
                            "certificate_acme_ca": cert_status.get("acme_ca"),
                            "certificate_legacy_cross_chain_installed": cert_status.get("legacy_cross_chain_installed"),
                            "android_legacy_compatible": bool(cert_status.get("android_legacy_compatible")),
                            "certificate_last_error": cert_status.get("last_error"),
                        },
                    })
                    return
                if not path.startswith("/_bridge/api/"):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                if not self._require_auth():
                    return
                if path == "/_bridge/api/status":
                    self._json({"ok": True, "config": app.store.public_config(), "frpc": app.supervisor.status(), "certificate": app.certificates.status(), "technitium_ready": app.technitium_ready()})
                elif path == "/_bridge/api/backup":
                    backup = app.store.export_backup()
                    backup["certificate"] = app.certificates.export_config()
                    payload = json.dumps(backup, indent=2).encode()
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
                        app.certificates.import_config(backup.get("certificate"))
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
                    if path == "/_bridge/api/frpc-toml":
                        enabled = _bool(data.get("enabled", False), "enabled")
                        text = sanitize_frpc_toml(data.get("toml", ""))
                        if enabled:
                            text = app.supervisor.verify_toml(text)
                        config = app.store.save_frpc_toml(text, enabled)
                        app.supervisor.reload()
                        self._json({"ok": True, "config": config})
                    elif path == "/_bridge/api/certificate/import":
                        certificate_pem = str(data.get("certificate_pem") or "")
                        private_key_pem = str(data.get("private_key_pem") or "")
                        app.certificates.import_manual(certificate_pem, private_key_pem)
                        self._json({"ok": True, "certificate": app.certificates.status()})
                    elif path == "/_bridge/api/certificate/cloudflare":
                        dns_record = app.certificates.save_cloudflare(data, app.store.get_frpc_toml())
                        self._json({"ok": True, "certificate": app.certificates.status(), "dns_record": dns_record})
                    elif path == "/_bridge/api/certificate/renew":
                        started = app.certificates.request_renew()
                        self._json({"ok": True, "started": started, "certificate": app.certificates.status()})
                    elif path == "/_bridge/api/settings":
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
                        app.certificates.import_config(backup.get("certificate"))
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
    parser.add_argument("--technitium-config-dir", default=os.environ.get("TECHNITIUM_CONFIG_DIR", "/data/technitium"))
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
    certificates = CertificateManager(root, Path(args.technitium_config_dir))
    supervisor.start()
    certificates.start()
    app = BridgeApp(store, supervisor, certificates, Path(args.index_file))
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
        certificates.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
, block)
        local = re.search(r'(?m)^\s*localPort\s*=\s*(\d+)\s*(path: Path, content: str, mode: int = 0o600) -> None:
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
                "frpc_toml": render_frpc_toml(DEFAULT_CONFIG),
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
                "frpc_toml": render_frpc_toml(frp),
                "migration": {"source": str(path), "migrated_at": now_iso()},
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None

    def _read(self) -> dict[str, Any]:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("format") != CONFIG_FORMAT:
            raise ValueError("Unsupported bridge configuration format.")
        changed = False
        frp = raw.get("frp")
        if not isinstance(frp, dict):
            frp = json.loads(json.dumps(DEFAULT_CONFIG))
            raw["frp"] = frp
            changed = True
        if "auth_token" in frp:
            frp.pop("auth_token", None)
            changed = True
        proxies = frp.get("proxies")
        if isinstance(proxies, dict):
            for obsolete in ("dns_tcp", "dns_udp"):
                if obsolete in proxies:
                    proxies.pop(obsolete, None)
                    changed = True
        normalized_frp = validate_frp(frp, require_server_addr=False)
        if normalized_frp != frp:
            raw["frp"] = normalized_frp
            frp = normalized_frp
            changed = True
        raw_toml = raw.get("frpc_toml")
        if not isinstance(raw_toml, str):
            raw["frpc_toml"] = render_frpc_toml(frp)
            changed = True
        else:
            cleaned = sanitize_frpc_toml(raw_toml)
            if cleaned != raw_toml:
                raw["frpc_toml"] = cleaned
                changed = True
        if changed:
            raw["updated_at"] = now_iso()
            _safe_write(self.path, json.dumps(raw, indent=2, sort_keys=True) + "\n")
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

    def get_frpc_toml(self) -> str:
        with self.lock:
            doc = self._read()
            return sanitize_frpc_toml(doc.get("frpc_toml", render_frpc_toml(doc.get("frp", DEFAULT_CONFIG))))

    def save_frpc_toml(self, text: str, enabled: bool) -> dict[str, Any]:
        cleaned = sanitize_frpc_toml(text)
        with self.lock:
            doc = self._read()
            frp = validate_frp(doc.get("frp", DEFAULT_CONFIG), require_server_addr=False)
            frp["enabled"] = bool(enabled)
            doc["frp"] = frp
            doc["frpc_toml"] = cleaned
            doc["updated_at"] = now_iso()
            self._write(doc)
        return self.public_config()

    def public_config(self) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
        frp = validate_frp(doc.get("frp", DEFAULT_CONFIG), require_server_addr=False)
        return {
            "format": CONFIG_FORMAT,
            "setup_required": not bool(doc.get("admin", {}).get("username")),
            "username": str(doc.get("admin", {}).get("username", "")),
            "frp": frp,
            "frpc_toml": sanitize_frpc_toml(doc.get("frpc_toml", render_frpc_toml(frp))),
            "migration": doc.get("migration"),
            "updated_at": doc.get("updated_at"),
        }

    def save_frp(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
            frp = validate_frp(payload, doc.get("frp", DEFAULT_CONFIG))
            doc["frp"] = frp
            doc["frpc_toml"] = render_frpc_toml(frp)
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
            "warning": "This backup contains FRP connection settings and the bridge administrator password hash. Store it securely.",
        }

    def import_backup(self, backup: Mapping[str, Any]) -> None:
        fmt = backup.get("format")
        if fmt == BACKUP_FORMAT:
            candidate = backup.get("config")
            if not isinstance(candidate, Mapping) or candidate.get("format") != CONFIG_FORMAT:
                raise ValueError("Bridge backup is incomplete.")
            frp = validate_frp(candidate.get("frp", {}), require_server_addr=False)
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
                "frpc_toml": sanitize_frpc_toml(candidate.get("frpc_toml", render_frpc_toml(frp))),
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
            doc["frpc_toml"] = render_frpc_toml(frp)
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

    def _write_config(self, text: str) -> None:
        _safe_write(self.store.frpc_path, sanitize_frpc_toml(text))

    def _config_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def verify_toml(self, text: str) -> str:
        cleaned = sanitize_frpc_toml(text)
        if not cleaned:
            raise ValueError("frpc.toml cannot be empty.")
        verify_path = self.store.root / "frpc.verify.toml"
        _safe_write(verify_path, cleaned)
        try:
            completed = subprocess.run(
                [self.frpc_binary, "verify", "-c", str(verify_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "HOME": "/tmp",
                    "TMPDIR": "/tmp",
                    "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"Unable to verify frpc.toml: {exc}") from exc
        finally:
            try:
                verify_path.unlink()
            except OSError:
                pass
        output = (completed.stdout or "").strip()
        if completed.returncode != 0:
            raise ValueError("frpc.toml validation failed: " + (output[-4000:] or "unknown error"))
        return cleaned

    def _run(self) -> None:
        backoff = 1.0
        while not self.stop_event.is_set():
            try:
                frp = self.store.get_frp()
                config_text = self.store.get_frpc_toml()
                desired = bool(frp.get("enabled") and config_text.strip())
                config_hash = self._config_hash(config_text)
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

                self._write_config(config_text)
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
        probes: dict[str, bool | None] = {
            "dot_853": self._tcp_probe(853),
            "doq_853": None,
        }
        return {
            "enabled": bool(frp.get("enabled")),
            "configured": bool(self.store.get_frpc_toml().strip()),
            "running": running,
            "pid": pid,
            "started_at": started_at,
            "last_exit_code": exit_code,
            "last_error": last_error,
            "restart_count": restarts,
            "local_service_probes": probes,
            "logs": logs,
        }



class CertificateManager:
    def __init__(
        self,
        bridge_root: Path,
        technitium_config_dir: Path,
        lego_binary: str = "/usr/local/bin/lego",
        openssl_binary: str = "/usr/bin/openssl",
    ) -> None:
        self.bridge_root = bridge_root
        self.technitium_config_dir = technitium_config_dir
        self.lego_binary = lego_binary
        self.openssl_binary = openssl_binary
        self.config_path = bridge_root / "certificate.json"
        self.token_path = bridge_root / "cloudflare-dns-api-token"
        self.acme_dir = bridge_root / "acme-zerossl"
        self.legacy_cross_cert_path = Path(__file__).with_name("SectigoPublicServerAuthenticationRootR46_USERTrust.pem")
        self.cert_dir = technitium_config_dir / "certificates"
        self.cert_pem_path = self.cert_dir / "dns-tls.crt.pem"
        self.key_pem_path = self.cert_dir / "dns-tls.key.pem"
        self.pfx_path = self.cert_dir / "dns-tls.pfx"
        self.lock = threading.RLock()
        self.running = False
        self.last_error: str | None = None
        self.last_output = ""
        self.last_attempt: str | None = None
        self.last_success: str | None = None
        self.last_dns_sync: str | None = None
        self.last_dns_error: str | None = None
        self.last_dns_action: str | None = None
        self.stop_event = threading.Event()
        self.auto_thread: threading.Thread | None = None
        self._ensure_dirs()
        if not self.config_path.exists():
            self._write_config(DEFAULT_CERT_CONFIG)

    def _ensure_dirs(self) -> None:
        for path in (self.bridge_root, self.acme_dir, self.cert_dir):
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.bridge_root, 0o700)
        os.chmod(self.acme_dir, 0o700)
        os.chmod(self.cert_dir, 0o700)

    def _read_config(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        cfg = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        raw_ca = ""
        if isinstance(raw, Mapping):
            raw_ca = str(raw.get("acme_ca") or "").strip().lower()
            cfg.update({k: raw.get(k, cfg[k]) for k in cfg})
        cfg["format"] = CERT_CONFIG_FORMAT
        cfg["acme_ca"] = ACME_CA
        cfg["mode"] = "cloudflare" if cfg.get("mode") == "cloudflare" else "manual"
        cfg["domain"] = str(cfg.get("domain") or "").strip().lower().rstrip(".")
        cfg["email"] = str(cfg.get("email") or "").strip()
        cfg["auto_renew"] = bool(cfg.get("auto_renew"))
        cfg["accept_tos"] = bool(cfg.get("accept_tos"))
        if cfg["mode"] == "cloudflare" and raw_ca != ACME_CA:
            # Consent to another CA's terms cannot be carried over automatically.
            cfg["accept_tos"] = False
        cfg["manage_dns_record"] = bool(cfg.get("manage_dns_record", True))
        cfg["dns_target"] = str(cfg.get("dns_target") or "").strip()
        return cfg

    def _write_config(self, cfg: Mapping[str, Any]) -> None:
        document = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        document.update({k: cfg.get(k, document[k]) for k in document})
        document["format"] = CERT_CONFIG_FORMAT
        document["updated_at"] = now_iso()
        _safe_write(self.config_path, json.dumps(document, indent=2, sort_keys=True) + "\n")

    @staticmethod
    def _validate_domain(value: Any) -> str:
        domain = str(value or "").strip().lower().rstrip(".")
        if not domain or len(domain) > 253 or not HOST_RE.fullmatch(domain) or ".." in domain:
            raise ValueError("Certificate domain must be a valid hostname.")
        try:
            socket.inet_pton(socket.AF_INET, domain)
            raise ValueError("Certificate domain must be a hostname, not an IP address.")
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, domain)
            raise ValueError("Certificate domain must be a hostname, not an IP address.")
        except OSError:
            pass
        if "." not in domain:
            raise ValueError("Certificate domain must be a fully qualified hostname.")
        return domain

    @staticmethod
    def _validate_email(value: Any) -> str:
        email = str(value or "").strip()
        if not EMAIL_RE.fullmatch(email) or len(email) > 254:
            raise ValueError("A valid ACME email address is required.")
        return email

    def export_config(self) -> dict[str, Any]:
        with self.lock:
            cfg = self._read_config()
        cfg.pop("updated_at", None)
        return cfg

    def import_config(self, cfg: Any) -> None:
        if not isinstance(cfg, Mapping):
            return
        mode = "cloudflare" if cfg.get("mode") == "cloudflare" else "manual"
        document = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        document["mode"] = mode
        document["acme_ca"] = ACME_CA
        if mode == "cloudflare":
            domain = str(cfg.get("domain") or "").strip()
            email = str(cfg.get("email") or "").strip()
            if domain:
                document["domain"] = self._validate_domain(domain)
            if email:
                document["email"] = self._validate_email(email)
            document["auto_renew"] = bool(cfg.get("auto_renew"))
            document["accept_tos"] = bool(cfg.get("accept_tos")) and str(cfg.get("acme_ca") or "").strip().lower() == ACME_CA
            document["manage_dns_record"] = bool(cfg.get("manage_dns_record", True))
            document["dns_target"] = str(cfg.get("dns_target") or "").strip()
        self._write_config(document)

    @staticmethod
    def _frp_ipv4(frpc_toml: str) -> str:
        match = re.search(r'(?mi)^\s*serverAddr\s*=\s*"([^"]+)"\s*$', frpc_toml)
        if not match:
            raise ValueError("Could not find serverAddr in the saved frpc.toml.")
        host = match.group(1).strip()
        try:
            socket.inet_pton(socket.AF_INET, host)
            return host
        except OSError:
            pass
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"FRPS hostname {host!r} could not be resolved to IPv4.") from exc
        addresses = sorted({info[4][0] for info in infos if info and info[4]})
        if not addresses:
            raise ValueError(f"FRPS hostname {host!r} has no IPv4 address for an A record.")
        return addresses[0]

    @staticmethod
    def _cloudflare_error_message(payload: Any) -> str:
        if not isinstance(payload, Mapping):
            return "unknown Cloudflare API error"
        errors = payload.get("errors")
        if isinstance(errors, list):
            messages = []
            for item in errors:
                if isinstance(item, Mapping):
                    message = str(item.get("message") or "").strip()
                    code = item.get("code")
                    if message:
                        messages.append(f"{code}: {message}" if code is not None else message)
            if messages:
                return "; ".join(messages)
        return str(payload.get("message") or "unknown Cloudflare API error")

    def _cloudflare_api(
        self,
        token: str,
        method: str,
        path: str,
        query: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = "https://api.cloudflare.com/client/v4" + path
        if query:
            url += "?" + urlencode({key: value for key, value in query.items() if value is not None})
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "dns-bridge/1",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=payload, headers=headers, method=method)
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as exc:
            try:
                error_payload = json.loads(exc.read().decode("utf-8", "replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                error_payload = {}
            raise ValueError(
                f"Cloudflare API HTTP {exc.code}: {self._cloudflare_error_message(error_payload)}"
            ) from exc
        except URLError as exc:
            raise ValueError(f"Cloudflare API request failed: {exc.reason}") from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Cloudflare API returned invalid JSON.") from exc
        if not isinstance(parsed, dict) or not parsed.get("success"):
            raise ValueError("Cloudflare API error: " + self._cloudflare_error_message(parsed))
        return parsed

    def _find_cloudflare_zone(self, token: str, domain: str) -> tuple[str, str]:
        labels = domain.rstrip(".").split(".")
        # Try the FQDN and then progressively shorter suffixes. The first
        # active Cloudflare zone returned is the most-specific matching zone.
        for index in range(max(1, len(labels) - 1)):
            candidate = ".".join(labels[index:])
            if "." not in candidate:
                continue
            response = self._cloudflare_api(
                token,
                "GET",
                "/zones",
                {"name": candidate, "status": "active", "per_page": 1},
            )
            result = response.get("result")
            if isinstance(result, list) and result:
                zone = result[0]
                if isinstance(zone, Mapping) and zone.get("id") and str(zone.get("name", "")).lower() == candidate.lower():
                    return str(zone["id"]), str(zone["name"])
        raise ValueError(
            f"Cloudflare zone for {domain} was not found. The token needs Zone Read access to the zone."
        )

    def _sync_cloudflare_a_record(self, domain: str, target: str, token: str) -> dict[str, str]:
        try:
            socket.inet_pton(socket.AF_INET, target)
        except OSError as exc:
            raise ValueError(f"Cloudflare A-record target {target!r} is not a valid IPv4 address.") from exc

        zone_id, zone_name = self._find_cloudflare_zone(token, domain)
        records_response = self._cloudflare_api(
            token,
            "GET",
            f"/zones/{zone_id}/dns_records",
            {"name": domain, "per_page": 100},
        )
        records = records_response.get("result")
        if not isinstance(records, list):
            records = []

        a_record = None
        conflicting = []
        for record in records:
            if not isinstance(record, Mapping):
                continue
            record_type = str(record.get("type") or "").upper()
            if record_type == "A" and a_record is None:
                a_record = record
            elif record_type in {"CNAME", "NS"}:
                conflicting.append(record_type)

        body = {
            "type": "A",
            "name": domain,
            "content": target,
            "ttl": 1,
            "proxied": False,
        }
        if a_record is not None and a_record.get("id"):
            current_content = str(a_record.get("content") or "")
            current_proxied = bool(a_record.get("proxied"))
            if current_content == target and not current_proxied:
                action = "unchanged"
            else:
                self._cloudflare_api(
                    token,
                    "PATCH",
                    f"/zones/{zone_id}/dns_records/{a_record['id']}",
                    body=body,
                )
                action = "updated"
        else:
            if conflicting:
                kinds = ", ".join(sorted(set(conflicting)))
                raise ValueError(
                    f"Cannot create A record for {domain}: a conflicting {kinds} record already exists."
                )
            self._cloudflare_api(
                token,
                "POST",
                f"/zones/{zone_id}/dns_records",
                body=body,
            )
            action = "created"

        with self.lock:
            self.last_dns_sync = now_iso()
            self.last_dns_error = None
            self.last_dns_action = action
        return {"action": action, "zone": zone_name, "name": domain, "target": target}

    def save_cloudflare(self, payload: Mapping[str, Any], frpc_toml: str) -> dict[str, str] | None:
        domain = self._validate_domain(payload.get("domain"))
        email = self._validate_email(payload.get("email"))
        api_token = str(payload.get("api_token") or "")
        if len(api_token) > 4096:
            raise ValueError("Cloudflare API token is too long.")
        clear_token = _bool(payload.get("clear_token", False), "clear_token")
        manage_dns_record = _bool(payload.get("manage_dns_record", True), "manage_dns_record")
        dns_target = self._frp_ipv4(frpc_toml) if manage_dns_record else ""
        cfg = {
            "format": CERT_CONFIG_FORMAT,
            "acme_ca": ACME_CA,
            "mode": "cloudflare",
            "domain": domain,
            "email": email,
            "auto_renew": _bool(payload.get("auto_renew", True), "auto_renew"),
            "accept_tos": _bool(payload.get("accept_tos", False), "accept_tos"),
            "manage_dns_record": manage_dns_record,
            "dns_target": dns_target,
        }
        with self.lock:
            self._write_config(cfg)
            if api_token:
                _safe_write(self.token_path, api_token.strip() + "\n")
            elif clear_token:
                try:
                    self.token_path.unlink()
                except FileNotFoundError:
                    pass

        if not manage_dns_record:
            with self.lock:
                self.last_dns_error = None
                self.last_dns_action = None
            return None

        if not self.token_path.is_file():
            raise ValueError("Cloudflare API token is required to create or update the DNS A record.")
        token = self.token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("Cloudflare API token is empty.")
        try:
            return self._sync_cloudflare_a_record(domain, dns_target, token)
        except ValueError as exc:
            with self.lock:
                self.last_dns_error = str(exc)
            raise

    def _openssl(self, args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        try:
            completed = subprocess.run(
                [self.openssl_binary, *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"OpenSSL failed: {exc}") from exc
        if completed.returncode != 0:
            raise ValueError("OpenSSL failed: " + (completed.stdout or "unknown error")[-4000:])
        return completed

    def _install_pem(self, certificate_pem: str, private_key_pem: str) -> None:
        if "-----BEGIN CERTIFICATE-----" not in certificate_pem:
            raise ValueError("Certificate file is not PEM encoded.")
        if "-----BEGIN " not in private_key_pem or "PRIVATE KEY-----" not in private_key_pem:
            raise ValueError("Private key file is not PEM encoded.")
        temp_cert = self.cert_dir / ".dns-tls.crt.tmp"
        temp_key = self.cert_dir / ".dns-tls.key.tmp"
        temp_pfx = self.cert_dir / ".dns-tls.pfx.tmp"
        _safe_write(temp_cert, certificate_pem.rstrip() + "\n")
        _safe_write(temp_key, private_key_pem.rstrip() + "\n")
        try:
            cert_pub = self._openssl(["x509", "-in", str(temp_cert), "-pubkey", "-noout"]).stdout
            key_pub = self._openssl(["pkey", "-in", str(temp_key), "-pubout"]).stdout
            if hashlib.sha256(cert_pub.encode()).digest() != hashlib.sha256(key_pub.encode()).digest():
                raise ValueError("Certificate and private key do not match.")
            self._openssl([
                "pkcs12", "-export",
                "-out", str(temp_pfx),
                "-inkey", str(temp_key),
                "-in", str(temp_cert),
                "-passout", "pass:",
            ])
            os.chmod(temp_pfx, 0o600)
            os.replace(temp_cert, self.cert_pem_path)
            os.replace(temp_key, self.key_pem_path)
            os.replace(temp_pfx, self.pfx_path)
            os.chmod(self.cert_pem_path, 0o600)
            os.chmod(self.key_pem_path, 0o600)
            os.chmod(self.pfx_path, 0o600)
        finally:
            for path in (temp_cert, temp_key, temp_pfx):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

    def import_manual(self, certificate_pem: str, private_key_pem: str) -> None:
        with self.lock:
            self._install_pem(certificate_pem, private_key_pem)
            cfg = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
            cfg["mode"] = "manual"
            cfg["auto_renew"] = False
            self._write_config(cfg)
            self.last_error = None
            self.last_success = now_iso()
            self.last_output = "Manual certificate imported and converted to PKCS#12."

    def _expiry(self) -> str | None:
        if not self.cert_pem_path.is_file():
            return None
        try:
            output = self._openssl(["x509", "-in", str(self.cert_pem_path), "-noout", "-enddate"]).stdout.strip()
            return output.split("=", 1)[1] if "=" in output else output
        except ValueError:
            return None

    def _expires_within(self, days: int) -> bool:
        if not self.cert_pem_path.is_file():
            return True
        try:
            completed = subprocess.run(
                [self.openssl_binary, "x509", "-in", str(self.cert_pem_path), "-noout", "-checkend", str(days * 86400)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            return completed.returncode != 0
        except (OSError, subprocess.TimeoutExpired):
            return True

    def _legacy_cross_certificate_pem(self) -> str:
        if not self.legacy_cross_cert_path.is_file():
            raise ValueError(
                "Bundled Sectigo R46 USERTrust cross certificate is missing; "
                "cannot build the Android-compatible ZeroSSL chain."
            )
        pem = self.legacy_cross_cert_path.read_text(encoding="utf-8").strip() + "\n"
        try:
            info = self._openssl([
                "x509", "-in", str(self.legacy_cross_cert_path), "-noout",
                "-subject", "-issuer", "-fingerprint", "-sha256"
            ]).stdout
        except ValueError as exc:
            raise ValueError(f"Bundled ZeroSSL compatibility certificate is invalid: {exc}") from exc
        lowered = info.lower()
        if "sectigo public server authentication root r46" not in lowered:
            raise ValueError("Bundled ZeroSSL compatibility certificate has the wrong subject.")
        if "usertrust rsa certification authority" not in lowered:
            raise ValueError("Bundled ZeroSSL compatibility certificate is not USERTrust cross-signed.")
        fingerprint = re.sub(r"[^0-9A-F]", "", info.upper().split("SHA256 FINGERPRINT=", 1)[-1])
        if fingerprint != LEGACY_CROSS_CERT_SHA256:
            raise ValueError("Bundled ZeroSSL compatibility certificate fingerprint does not match the pinned Sectigo R46 cross-certificate.")
        return pem

    def _installed_chain_has_legacy_cross_certificate(self) -> bool:
        if not self.cert_pem_path.is_file():
            return False
        try:
            installed = self.cert_pem_path.read_text(encoding="utf-8")
            cross = self._legacy_cross_certificate_pem().strip()
        except (OSError, ValueError):
            return False
        return cross in installed

    def _install_lego_certificate(self, domain: str) -> None:
        cert, key, issuer = self._find_lego_certificates(domain)
        certificate_pem = cert.read_text(encoding="utf-8").strip() + "\n"
        if issuer is not None:
            certificate_pem = certificate_pem.rstrip() + "\n" + issuer.read_text(encoding="utf-8").strip() + "\n"
        # ZeroSSL's current RSA intermediate chains to Sectigo R46. Android 13
        # predates R46's addition to AOSP's CA store, so append Sectigo's official
        # R46 cross-certificate to the long-standing USERTrust RSA root.
        certificate_pem = certificate_pem.rstrip() + "\n" + self._legacy_cross_certificate_pem()
        private_key_pem = key.read_text(encoding="utf-8")
        self._install_pem(certificate_pem, private_key_pem)

    def _find_lego_certificates(self, domain: str) -> tuple[Path, Path, Path | None]:
        base = self.acme_dir / "certificates"
        cert = base / f"{domain}.crt"
        key = base / f"{domain}.key"
        issuer = base / f"{domain}.issuer.crt"
        if not cert.is_file() or not key.is_file():
            raise ValueError("ACME client completed but certificate files were not found.")
        return cert, key, issuer if issuer.is_file() else None

    def _certificate_key_algorithm(self, path: Path | None = None) -> str | None:
        certificate = path if path is not None else self.cert_pem_path
        if not certificate.is_file():
            return None
        try:
            output = self._openssl(["x509", "-in", str(certificate), "-noout", "-text"]).stdout
        except ValueError:
            return None
        if "Public Key Algorithm: rsaEncryption" in output:
            return "RSA"
        if "Public Key Algorithm: id-ecPublicKey" in output:
            return "EC"
        return "OTHER"

    def _build_lego_command(
        self,
        domain: str,
        email: str,
        first_issue: bool,
        force_compat_reissue: bool = False,
    ) -> list[str]:
        # Use ZeroSSL RSA2048 intentionally for the Android 13 compatibility A/B test.
        # Keep this ACME state in its own directory so the previous Let's Encrypt
        # account/certificate material remains intact for rollback.
        command = [
            self.lego_binary,
            "run",
            "--server", ACME_CA,
            "--email", email,
            "--dns", "cloudflare",
            "--domains", domain,
            "--path", str(self.acme_dir),
            "--key-type", "RSA2048",
        ]
        if first_issue:
            command.append("--accept-tos")
        elif force_compat_reissue:
            command.extend(["--renew-force", "--no-random-sleep"])
        else:
            command.extend(["--renew-days", "30", "--no-random-sleep"])
        return command

    def _run_cloudflare(self) -> None:
        with self.lock:
            cfg = self._read_config()
        if cfg.get("mode") != "cloudflare":
            raise ValueError("Cloudflare ACME mode is not configured.")
        domain = self._validate_domain(cfg.get("domain"))
        email = self._validate_email(cfg.get("email"))
        if not self.token_path.is_file():
            raise ValueError("Cloudflare API token is not configured.")
        token = self.token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("Cloudflare API token is empty.")
        lego_cert_path = self.acme_dir / "certificates" / f"{domain}.crt"
        first_issue = not lego_cert_path.is_file()
        current_key_algorithm = self._certificate_key_algorithm(lego_cert_path)
        force_compat_reissue = bool(not first_issue and current_key_algorithm != "RSA")
        if first_issue and not cfg.get("accept_tos"):
            raise ValueError("Accept the ACME / ZeroSSL terms before requesting the first certificate.")
        if cfg.get("manage_dns_record"):
            target = str(cfg.get("dns_target") or "").strip()
            if not target:
                raise ValueError("Automatic Cloudflare A-record target is missing. Save the Cloudflare settings again.")
            self._sync_cloudflare_a_record(domain, target, token)

        if not first_issue and not force_compat_reissue and not self._expires_within(30):
            if not self._installed_chain_has_legacy_cross_certificate():
                self._install_lego_certificate(domain)
                self.last_output = (
                    "Reinstalled the existing ZeroSSL certificate with the Sectigo R46 "
                    "USERTrust cross-signed compatibility chain for Android 13."
                )
            else:
                self.last_output = "Certificate is already RSA, Android-compatible, and valid for more than 30 days; renewal is not due."
            return

        command = self._build_lego_command(
            domain,
            email,
            first_issue,
            force_compat_reissue=force_compat_reissue,
        )

        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.bridge_root),
            "TMPDIR": "/tmp",
            "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
            "CLOUDFLARE_DNS_API_TOKEN": token,
        }
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=600,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"ACME client failed: {exc}") from exc
        output = (completed.stdout or "").strip()
        self.last_output = output[-12000:]
        if completed.returncode != 0:
            raise ValueError("ACME client failed: " + (output[-4000:] or "unknown error"))

        self._install_lego_certificate(domain)

    def _worker(self) -> None:
        try:
            with self.lock:
                self.last_attempt = now_iso()
                self.last_error = None
            self._run_cloudflare()
            with self.lock:
                self.last_success = now_iso()
        except ValueError as exc:
            with self.lock:
                self.last_error = str(exc)
        finally:
            with self.lock:
                self.running = False

    def request_renew(self) -> bool:
        with self.lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._worker, name="certificate-renew", daemon=True).start()
        return True

    def _auto_loop(self) -> None:
        # Run the first certificate check shortly after container startup. A missing
        # ZeroSSL certificate state means this deployment still needs the CA migration.
        if self.stop_event.wait(10):
            return
        while not self.stop_event.is_set():
            try:
                with self.lock:
                    cfg = self._read_config()
                    should_check = cfg.get("mode") == "cloudflare" and bool(cfg.get("auto_renew")) and self.token_path.is_file()
                lego_cert_path = self.acme_dir / "certificates" / f"{cfg.get('domain', '')}.crt"
                needs_ca_migration = bool(should_check and not lego_cert_path.is_file())
                needs_android_compat = bool(
                    should_check
                    and lego_cert_path.is_file()
                    and self._certificate_key_algorithm(lego_cert_path) != "RSA"
                )
                needs_legacy_chain = bool(
                    should_check
                    and lego_cert_path.is_file()
                    and not self._installed_chain_has_legacy_cross_certificate()
                )
                if should_check and (needs_ca_migration or needs_android_compat or needs_legacy_chain or self._expires_within(30)):
                    self.request_renew()
            except Exception as exc:
                with self.lock:
                    self.last_error = f"Auto-renew check failed: {exc}"
            if self.stop_event.wait(6 * 3600):
                break

    def start(self) -> None:
        self.auto_thread = threading.Thread(target=self._auto_loop, name="certificate-auto-renew", daemon=True)
        self.auto_thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.auto_thread and self.auto_thread.is_alive():
            self.auto_thread.join(timeout=5)

    def status(self) -> dict[str, Any]:
        with self.lock:
            cfg = self._read_config()
            return {
                "mode": cfg.get("mode"),
                "domain": cfg.get("domain"),
                "email": cfg.get("email"),
                "auto_renew": bool(cfg.get("auto_renew")),
                "accept_tos": bool(cfg.get("accept_tos")),
                "manage_dns_record": bool(cfg.get("manage_dns_record", True)),
                "dns_target": str(cfg.get("dns_target") or ""),
                "dns_record_last_sync": self.last_dns_sync,
                "dns_record_last_action": self.last_dns_action,
                "dns_record_last_error": self.last_dns_error,
                "cloudflare_token_configured": self.token_path.is_file() and self.token_path.stat().st_size > 0,
                "pfx_path": str(self.pfx_path),
                "pfx_password": "",
                "certificate_exists": self.pfx_path.is_file(),
                "acme_ca": ACME_CA_LABEL if cfg.get("mode") == "cloudflare" else None,
                "key_algorithm": self._certificate_key_algorithm(),
                "legacy_cross_chain_installed": self._installed_chain_has_legacy_cross_certificate() if cfg.get("mode") == "cloudflare" else None,
                "android_legacy_compatible": bool(
                    self._certificate_key_algorithm() == "RSA"
                    and (cfg.get("mode") != "cloudflare" or self._installed_chain_has_legacy_cross_certificate())
                ),
                "expires": self._expiry(),
                "running": self.running,
                "last_attempt": self.last_attempt,
                "last_success": self.last_success,
                "last_error": self.last_error,
                "last_output": self.last_output,
            }


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


class BridgeApp:
    def __init__(self, store: ConfigStore, supervisor: FrpcSupervisor, certificates: CertificateManager, index_file: Path) -> None:
        self.store = store
        self.supervisor = supervisor
        self.certificates = certificates
        self.index_file = index_file

    @staticmethod
    def technitium_ready() -> bool:
        targets = ["127.0.0.1"]
        try:
            resolved = socket.gethostbyname(socket.gethostname())
            if resolved not in targets:
                targets.append(resolved)
        except OSError:
            pass
        for host in targets:
            try:
                with socket.create_connection((host, 5380), timeout=0.5):
                    return True
            except OSError:
                continue
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
                    cert_status = app.certificates.status()
                    self._json({
                        "ok": True,
                        "config": app.store.public_config(),
                        "technitium_ready": app.technitium_ready(),
                        "public_health": {
                            "dot_local_ready": app.supervisor._tcp_probe(853),
                            "certificate_exists": bool(cert_status.get("certificate_exists")),
                            "certificate_key_algorithm": cert_status.get("key_algorithm"),
                            "certificate_acme_ca": cert_status.get("acme_ca"),
                            "certificate_legacy_cross_chain_installed": cert_status.get("legacy_cross_chain_installed"),
                            "android_legacy_compatible": bool(cert_status.get("android_legacy_compatible")),
                            "certificate_last_error": cert_status.get("last_error"),
                        },
                    })
                    return
                if not path.startswith("/_bridge/api/"):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                if not self._require_auth():
                    return
                if path == "/_bridge/api/status":
                    self._json({"ok": True, "config": app.store.public_config(), "frpc": app.supervisor.status(), "certificate": app.certificates.status(), "technitium_ready": app.technitium_ready()})
                elif path == "/_bridge/api/backup":
                    backup = app.store.export_backup()
                    backup["certificate"] = app.certificates.export_config()
                    payload = json.dumps(backup, indent=2).encode()
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
                        app.certificates.import_config(backup.get("certificate"))
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
                    if path == "/_bridge/api/frpc-toml":
                        enabled = _bool(data.get("enabled", False), "enabled")
                        text = sanitize_frpc_toml(data.get("toml", ""))
                        if enabled:
                            text = app.supervisor.verify_toml(text)
                        config = app.store.save_frpc_toml(text, enabled)
                        app.supervisor.reload()
                        self._json({"ok": True, "config": config})
                    elif path == "/_bridge/api/certificate/import":
                        certificate_pem = str(data.get("certificate_pem") or "")
                        private_key_pem = str(data.get("private_key_pem") or "")
                        app.certificates.import_manual(certificate_pem, private_key_pem)
                        self._json({"ok": True, "certificate": app.certificates.status()})
                    elif path == "/_bridge/api/certificate/cloudflare":
                        dns_record = app.certificates.save_cloudflare(data, app.store.get_frpc_toml())
                        self._json({"ok": True, "certificate": app.certificates.status(), "dns_record": dns_record})
                    elif path == "/_bridge/api/certificate/renew":
                        started = app.certificates.request_renew()
                        self._json({"ok": True, "started": started, "certificate": app.certificates.status()})
                    elif path == "/_bridge/api/settings":
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
                        app.certificates.import_config(backup.get("certificate"))
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
    parser.add_argument("--technitium-config-dir", default=os.environ.get("TECHNITIUM_CONFIG_DIR", "/data/technitium"))
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
    certificates = CertificateManager(root, Path(args.technitium_config_dir))
    supervisor.start()
    certificates.start()
    app = BridgeApp(store, supervisor, certificates, Path(args.index_file))
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
        certificates.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
, block)
        remote = re.search(r'(?m)^\s*remotePort\s*=\s*(\d+)\s*(path: Path, content: str, mode: int = 0o600) -> None:
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
                "frpc_toml": render_frpc_toml(DEFAULT_CONFIG),
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
                "frpc_toml": render_frpc_toml(frp),
                "migration": {"source": str(path), "migrated_at": now_iso()},
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None

    def _read(self) -> dict[str, Any]:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("format") != CONFIG_FORMAT:
            raise ValueError("Unsupported bridge configuration format.")
        changed = False
        frp = raw.get("frp")
        if not isinstance(frp, dict):
            frp = json.loads(json.dumps(DEFAULT_CONFIG))
            raw["frp"] = frp
            changed = True
        if "auth_token" in frp:
            frp.pop("auth_token", None)
            changed = True
        proxies = frp.get("proxies")
        if isinstance(proxies, dict):
            for obsolete in ("dns_tcp", "dns_udp"):
                if obsolete in proxies:
                    proxies.pop(obsolete, None)
                    changed = True
        normalized_frp = validate_frp(frp, require_server_addr=False)
        if normalized_frp != frp:
            raw["frp"] = normalized_frp
            frp = normalized_frp
            changed = True
        raw_toml = raw.get("frpc_toml")
        if not isinstance(raw_toml, str):
            raw["frpc_toml"] = render_frpc_toml(frp)
            changed = True
        else:
            cleaned = sanitize_frpc_toml(raw_toml)
            if cleaned != raw_toml:
                raw["frpc_toml"] = cleaned
                changed = True
        if changed:
            raw["updated_at"] = now_iso()
            _safe_write(self.path, json.dumps(raw, indent=2, sort_keys=True) + "\n")
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

    def get_frpc_toml(self) -> str:
        with self.lock:
            doc = self._read()
            return sanitize_frpc_toml(doc.get("frpc_toml", render_frpc_toml(doc.get("frp", DEFAULT_CONFIG))))

    def save_frpc_toml(self, text: str, enabled: bool) -> dict[str, Any]:
        cleaned = sanitize_frpc_toml(text)
        with self.lock:
            doc = self._read()
            frp = validate_frp(doc.get("frp", DEFAULT_CONFIG), require_server_addr=False)
            frp["enabled"] = bool(enabled)
            doc["frp"] = frp
            doc["frpc_toml"] = cleaned
            doc["updated_at"] = now_iso()
            self._write(doc)
        return self.public_config()

    def public_config(self) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
        frp = validate_frp(doc.get("frp", DEFAULT_CONFIG), require_server_addr=False)
        return {
            "format": CONFIG_FORMAT,
            "setup_required": not bool(doc.get("admin", {}).get("username")),
            "username": str(doc.get("admin", {}).get("username", "")),
            "frp": frp,
            "frpc_toml": sanitize_frpc_toml(doc.get("frpc_toml", render_frpc_toml(frp))),
            "migration": doc.get("migration"),
            "updated_at": doc.get("updated_at"),
        }

    def save_frp(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
            frp = validate_frp(payload, doc.get("frp", DEFAULT_CONFIG))
            doc["frp"] = frp
            doc["frpc_toml"] = render_frpc_toml(frp)
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
            "warning": "This backup contains FRP connection settings and the bridge administrator password hash. Store it securely.",
        }

    def import_backup(self, backup: Mapping[str, Any]) -> None:
        fmt = backup.get("format")
        if fmt == BACKUP_FORMAT:
            candidate = backup.get("config")
            if not isinstance(candidate, Mapping) or candidate.get("format") != CONFIG_FORMAT:
                raise ValueError("Bridge backup is incomplete.")
            frp = validate_frp(candidate.get("frp", {}), require_server_addr=False)
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
                "frpc_toml": sanitize_frpc_toml(candidate.get("frpc_toml", render_frpc_toml(frp))),
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
            doc["frpc_toml"] = render_frpc_toml(frp)
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

    def _write_config(self, text: str) -> None:
        _safe_write(self.store.frpc_path, sanitize_frpc_toml(text))

    def _config_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def verify_toml(self, text: str) -> str:
        cleaned = sanitize_frpc_toml(text)
        if not cleaned:
            raise ValueError("frpc.toml cannot be empty.")
        verify_path = self.store.root / "frpc.verify.toml"
        _safe_write(verify_path, cleaned)
        try:
            completed = subprocess.run(
                [self.frpc_binary, "verify", "-c", str(verify_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "HOME": "/tmp",
                    "TMPDIR": "/tmp",
                    "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"Unable to verify frpc.toml: {exc}") from exc
        finally:
            try:
                verify_path.unlink()
            except OSError:
                pass
        output = (completed.stdout or "").strip()
        if completed.returncode != 0:
            raise ValueError("frpc.toml validation failed: " + (output[-4000:] or "unknown error"))
        return cleaned

    def _run(self) -> None:
        backoff = 1.0
        while not self.stop_event.is_set():
            try:
                frp = self.store.get_frp()
                config_text = self.store.get_frpc_toml()
                desired = bool(frp.get("enabled") and config_text.strip())
                config_hash = self._config_hash(config_text)
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

                self._write_config(config_text)
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
        probes: dict[str, bool | None] = {
            "dot_853": self._tcp_probe(853),
            "doq_853": None,
        }
        return {
            "enabled": bool(frp.get("enabled")),
            "configured": bool(self.store.get_frpc_toml().strip()),
            "running": running,
            "pid": pid,
            "started_at": started_at,
            "last_exit_code": exit_code,
            "last_error": last_error,
            "restart_count": restarts,
            "local_service_probes": probes,
            "logs": logs,
        }



class CertificateManager:
    def __init__(
        self,
        bridge_root: Path,
        technitium_config_dir: Path,
        lego_binary: str = "/usr/local/bin/lego",
        openssl_binary: str = "/usr/bin/openssl",
    ) -> None:
        self.bridge_root = bridge_root
        self.technitium_config_dir = technitium_config_dir
        self.lego_binary = lego_binary
        self.openssl_binary = openssl_binary
        self.config_path = bridge_root / "certificate.json"
        self.token_path = bridge_root / "cloudflare-dns-api-token"
        self.acme_dir = bridge_root / "acme-zerossl"
        self.legacy_cross_cert_path = Path(__file__).with_name("SectigoPublicServerAuthenticationRootR46_USERTrust.pem")
        self.cert_dir = technitium_config_dir / "certificates"
        self.cert_pem_path = self.cert_dir / "dns-tls.crt.pem"
        self.key_pem_path = self.cert_dir / "dns-tls.key.pem"
        self.pfx_path = self.cert_dir / "dns-tls.pfx"
        self.lock = threading.RLock()
        self.running = False
        self.last_error: str | None = None
        self.last_output = ""
        self.last_attempt: str | None = None
        self.last_success: str | None = None
        self.last_dns_sync: str | None = None
        self.last_dns_error: str | None = None
        self.last_dns_action: str | None = None
        self.stop_event = threading.Event()
        self.auto_thread: threading.Thread | None = None
        self._ensure_dirs()
        if not self.config_path.exists():
            self._write_config(DEFAULT_CERT_CONFIG)

    def _ensure_dirs(self) -> None:
        for path in (self.bridge_root, self.acme_dir, self.cert_dir):
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.bridge_root, 0o700)
        os.chmod(self.acme_dir, 0o700)
        os.chmod(self.cert_dir, 0o700)

    def _read_config(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        cfg = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        raw_ca = ""
        if isinstance(raw, Mapping):
            raw_ca = str(raw.get("acme_ca") or "").strip().lower()
            cfg.update({k: raw.get(k, cfg[k]) for k in cfg})
        cfg["format"] = CERT_CONFIG_FORMAT
        cfg["acme_ca"] = ACME_CA
        cfg["mode"] = "cloudflare" if cfg.get("mode") == "cloudflare" else "manual"
        cfg["domain"] = str(cfg.get("domain") or "").strip().lower().rstrip(".")
        cfg["email"] = str(cfg.get("email") or "").strip()
        cfg["auto_renew"] = bool(cfg.get("auto_renew"))
        cfg["accept_tos"] = bool(cfg.get("accept_tos"))
        if cfg["mode"] == "cloudflare" and raw_ca != ACME_CA:
            # Consent to another CA's terms cannot be carried over automatically.
            cfg["accept_tos"] = False
        cfg["manage_dns_record"] = bool(cfg.get("manage_dns_record", True))
        cfg["dns_target"] = str(cfg.get("dns_target") or "").strip()
        return cfg

    def _write_config(self, cfg: Mapping[str, Any]) -> None:
        document = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        document.update({k: cfg.get(k, document[k]) for k in document})
        document["format"] = CERT_CONFIG_FORMAT
        document["updated_at"] = now_iso()
        _safe_write(self.config_path, json.dumps(document, indent=2, sort_keys=True) + "\n")

    @staticmethod
    def _validate_domain(value: Any) -> str:
        domain = str(value or "").strip().lower().rstrip(".")
        if not domain or len(domain) > 253 or not HOST_RE.fullmatch(domain) or ".." in domain:
            raise ValueError("Certificate domain must be a valid hostname.")
        try:
            socket.inet_pton(socket.AF_INET, domain)
            raise ValueError("Certificate domain must be a hostname, not an IP address.")
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, domain)
            raise ValueError("Certificate domain must be a hostname, not an IP address.")
        except OSError:
            pass
        if "." not in domain:
            raise ValueError("Certificate domain must be a fully qualified hostname.")
        return domain

    @staticmethod
    def _validate_email(value: Any) -> str:
        email = str(value or "").strip()
        if not EMAIL_RE.fullmatch(email) or len(email) > 254:
            raise ValueError("A valid ACME email address is required.")
        return email

    def export_config(self) -> dict[str, Any]:
        with self.lock:
            cfg = self._read_config()
        cfg.pop("updated_at", None)
        return cfg

    def import_config(self, cfg: Any) -> None:
        if not isinstance(cfg, Mapping):
            return
        mode = "cloudflare" if cfg.get("mode") == "cloudflare" else "manual"
        document = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        document["mode"] = mode
        document["acme_ca"] = ACME_CA
        if mode == "cloudflare":
            domain = str(cfg.get("domain") or "").strip()
            email = str(cfg.get("email") or "").strip()
            if domain:
                document["domain"] = self._validate_domain(domain)
            if email:
                document["email"] = self._validate_email(email)
            document["auto_renew"] = bool(cfg.get("auto_renew"))
            document["accept_tos"] = bool(cfg.get("accept_tos")) and str(cfg.get("acme_ca") or "").strip().lower() == ACME_CA
            document["manage_dns_record"] = bool(cfg.get("manage_dns_record", True))
            document["dns_target"] = str(cfg.get("dns_target") or "").strip()
        self._write_config(document)

    @staticmethod
    def _frp_ipv4(frpc_toml: str) -> str:
        match = re.search(r'(?mi)^\s*serverAddr\s*=\s*"([^"]+)"\s*$', frpc_toml)
        if not match:
            raise ValueError("Could not find serverAddr in the saved frpc.toml.")
        host = match.group(1).strip()
        try:
            socket.inet_pton(socket.AF_INET, host)
            return host
        except OSError:
            pass
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"FRPS hostname {host!r} could not be resolved to IPv4.") from exc
        addresses = sorted({info[4][0] for info in infos if info and info[4]})
        if not addresses:
            raise ValueError(f"FRPS hostname {host!r} has no IPv4 address for an A record.")
        return addresses[0]

    @staticmethod
    def _cloudflare_error_message(payload: Any) -> str:
        if not isinstance(payload, Mapping):
            return "unknown Cloudflare API error"
        errors = payload.get("errors")
        if isinstance(errors, list):
            messages = []
            for item in errors:
                if isinstance(item, Mapping):
                    message = str(item.get("message") or "").strip()
                    code = item.get("code")
                    if message:
                        messages.append(f"{code}: {message}" if code is not None else message)
            if messages:
                return "; ".join(messages)
        return str(payload.get("message") or "unknown Cloudflare API error")

    def _cloudflare_api(
        self,
        token: str,
        method: str,
        path: str,
        query: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = "https://api.cloudflare.com/client/v4" + path
        if query:
            url += "?" + urlencode({key: value for key, value in query.items() if value is not None})
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "dns-bridge/1",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=payload, headers=headers, method=method)
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as exc:
            try:
                error_payload = json.loads(exc.read().decode("utf-8", "replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                error_payload = {}
            raise ValueError(
                f"Cloudflare API HTTP {exc.code}: {self._cloudflare_error_message(error_payload)}"
            ) from exc
        except URLError as exc:
            raise ValueError(f"Cloudflare API request failed: {exc.reason}") from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Cloudflare API returned invalid JSON.") from exc
        if not isinstance(parsed, dict) or not parsed.get("success"):
            raise ValueError("Cloudflare API error: " + self._cloudflare_error_message(parsed))
        return parsed

    def _find_cloudflare_zone(self, token: str, domain: str) -> tuple[str, str]:
        labels = domain.rstrip(".").split(".")
        # Try the FQDN and then progressively shorter suffixes. The first
        # active Cloudflare zone returned is the most-specific matching zone.
        for index in range(max(1, len(labels) - 1)):
            candidate = ".".join(labels[index:])
            if "." not in candidate:
                continue
            response = self._cloudflare_api(
                token,
                "GET",
                "/zones",
                {"name": candidate, "status": "active", "per_page": 1},
            )
            result = response.get("result")
            if isinstance(result, list) and result:
                zone = result[0]
                if isinstance(zone, Mapping) and zone.get("id") and str(zone.get("name", "")).lower() == candidate.lower():
                    return str(zone["id"]), str(zone["name"])
        raise ValueError(
            f"Cloudflare zone for {domain} was not found. The token needs Zone Read access to the zone."
        )

    def _sync_cloudflare_a_record(self, domain: str, target: str, token: str) -> dict[str, str]:
        try:
            socket.inet_pton(socket.AF_INET, target)
        except OSError as exc:
            raise ValueError(f"Cloudflare A-record target {target!r} is not a valid IPv4 address.") from exc

        zone_id, zone_name = self._find_cloudflare_zone(token, domain)
        records_response = self._cloudflare_api(
            token,
            "GET",
            f"/zones/{zone_id}/dns_records",
            {"name": domain, "per_page": 100},
        )
        records = records_response.get("result")
        if not isinstance(records, list):
            records = []

        a_record = None
        conflicting = []
        for record in records:
            if not isinstance(record, Mapping):
                continue
            record_type = str(record.get("type") or "").upper()
            if record_type == "A" and a_record is None:
                a_record = record
            elif record_type in {"CNAME", "NS"}:
                conflicting.append(record_type)

        body = {
            "type": "A",
            "name": domain,
            "content": target,
            "ttl": 1,
            "proxied": False,
        }
        if a_record is not None and a_record.get("id"):
            current_content = str(a_record.get("content") or "")
            current_proxied = bool(a_record.get("proxied"))
            if current_content == target and not current_proxied:
                action = "unchanged"
            else:
                self._cloudflare_api(
                    token,
                    "PATCH",
                    f"/zones/{zone_id}/dns_records/{a_record['id']}",
                    body=body,
                )
                action = "updated"
        else:
            if conflicting:
                kinds = ", ".join(sorted(set(conflicting)))
                raise ValueError(
                    f"Cannot create A record for {domain}: a conflicting {kinds} record already exists."
                )
            self._cloudflare_api(
                token,
                "POST",
                f"/zones/{zone_id}/dns_records",
                body=body,
            )
            action = "created"

        with self.lock:
            self.last_dns_sync = now_iso()
            self.last_dns_error = None
            self.last_dns_action = action
        return {"action": action, "zone": zone_name, "name": domain, "target": target}

    def save_cloudflare(self, payload: Mapping[str, Any], frpc_toml: str) -> dict[str, str] | None:
        domain = self._validate_domain(payload.get("domain"))
        email = self._validate_email(payload.get("email"))
        api_token = str(payload.get("api_token") or "")
        if len(api_token) > 4096:
            raise ValueError("Cloudflare API token is too long.")
        clear_token = _bool(payload.get("clear_token", False), "clear_token")
        manage_dns_record = _bool(payload.get("manage_dns_record", True), "manage_dns_record")
        dns_target = self._frp_ipv4(frpc_toml) if manage_dns_record else ""
        cfg = {
            "format": CERT_CONFIG_FORMAT,
            "acme_ca": ACME_CA,
            "mode": "cloudflare",
            "domain": domain,
            "email": email,
            "auto_renew": _bool(payload.get("auto_renew", True), "auto_renew"),
            "accept_tos": _bool(payload.get("accept_tos", False), "accept_tos"),
            "manage_dns_record": manage_dns_record,
            "dns_target": dns_target,
        }
        with self.lock:
            self._write_config(cfg)
            if api_token:
                _safe_write(self.token_path, api_token.strip() + "\n")
            elif clear_token:
                try:
                    self.token_path.unlink()
                except FileNotFoundError:
                    pass

        if not manage_dns_record:
            with self.lock:
                self.last_dns_error = None
                self.last_dns_action = None
            return None

        if not self.token_path.is_file():
            raise ValueError("Cloudflare API token is required to create or update the DNS A record.")
        token = self.token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("Cloudflare API token is empty.")
        try:
            return self._sync_cloudflare_a_record(domain, dns_target, token)
        except ValueError as exc:
            with self.lock:
                self.last_dns_error = str(exc)
            raise

    def _openssl(self, args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        try:
            completed = subprocess.run(
                [self.openssl_binary, *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"OpenSSL failed: {exc}") from exc
        if completed.returncode != 0:
            raise ValueError("OpenSSL failed: " + (completed.stdout or "unknown error")[-4000:])
        return completed

    def _install_pem(self, certificate_pem: str, private_key_pem: str) -> None:
        if "-----BEGIN CERTIFICATE-----" not in certificate_pem:
            raise ValueError("Certificate file is not PEM encoded.")
        if "-----BEGIN " not in private_key_pem or "PRIVATE KEY-----" not in private_key_pem:
            raise ValueError("Private key file is not PEM encoded.")
        temp_cert = self.cert_dir / ".dns-tls.crt.tmp"
        temp_key = self.cert_dir / ".dns-tls.key.tmp"
        temp_pfx = self.cert_dir / ".dns-tls.pfx.tmp"
        _safe_write(temp_cert, certificate_pem.rstrip() + "\n")
        _safe_write(temp_key, private_key_pem.rstrip() + "\n")
        try:
            cert_pub = self._openssl(["x509", "-in", str(temp_cert), "-pubkey", "-noout"]).stdout
            key_pub = self._openssl(["pkey", "-in", str(temp_key), "-pubout"]).stdout
            if hashlib.sha256(cert_pub.encode()).digest() != hashlib.sha256(key_pub.encode()).digest():
                raise ValueError("Certificate and private key do not match.")
            self._openssl([
                "pkcs12", "-export",
                "-out", str(temp_pfx),
                "-inkey", str(temp_key),
                "-in", str(temp_cert),
                "-passout", "pass:",
            ])
            os.chmod(temp_pfx, 0o600)
            os.replace(temp_cert, self.cert_pem_path)
            os.replace(temp_key, self.key_pem_path)
            os.replace(temp_pfx, self.pfx_path)
            os.chmod(self.cert_pem_path, 0o600)
            os.chmod(self.key_pem_path, 0o600)
            os.chmod(self.pfx_path, 0o600)
        finally:
            for path in (temp_cert, temp_key, temp_pfx):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

    def import_manual(self, certificate_pem: str, private_key_pem: str) -> None:
        with self.lock:
            self._install_pem(certificate_pem, private_key_pem)
            cfg = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
            cfg["mode"] = "manual"
            cfg["auto_renew"] = False
            self._write_config(cfg)
            self.last_error = None
            self.last_success = now_iso()
            self.last_output = "Manual certificate imported and converted to PKCS#12."

    def _expiry(self) -> str | None:
        if not self.cert_pem_path.is_file():
            return None
        try:
            output = self._openssl(["x509", "-in", str(self.cert_pem_path), "-noout", "-enddate"]).stdout.strip()
            return output.split("=", 1)[1] if "=" in output else output
        except ValueError:
            return None

    def _expires_within(self, days: int) -> bool:
        if not self.cert_pem_path.is_file():
            return True
        try:
            completed = subprocess.run(
                [self.openssl_binary, "x509", "-in", str(self.cert_pem_path), "-noout", "-checkend", str(days * 86400)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            return completed.returncode != 0
        except (OSError, subprocess.TimeoutExpired):
            return True

    def _legacy_cross_certificate_pem(self) -> str:
        if not self.legacy_cross_cert_path.is_file():
            raise ValueError(
                "Bundled Sectigo R46 USERTrust cross certificate is missing; "
                "cannot build the Android-compatible ZeroSSL chain."
            )
        pem = self.legacy_cross_cert_path.read_text(encoding="utf-8").strip() + "\n"
        try:
            info = self._openssl([
                "x509", "-in", str(self.legacy_cross_cert_path), "-noout",
                "-subject", "-issuer", "-fingerprint", "-sha256"
            ]).stdout
        except ValueError as exc:
            raise ValueError(f"Bundled ZeroSSL compatibility certificate is invalid: {exc}") from exc
        lowered = info.lower()
        if "sectigo public server authentication root r46" not in lowered:
            raise ValueError("Bundled ZeroSSL compatibility certificate has the wrong subject.")
        if "usertrust rsa certification authority" not in lowered:
            raise ValueError("Bundled ZeroSSL compatibility certificate is not USERTrust cross-signed.")
        fingerprint = re.sub(r"[^0-9A-F]", "", info.upper().split("SHA256 FINGERPRINT=", 1)[-1])
        if fingerprint != LEGACY_CROSS_CERT_SHA256:
            raise ValueError("Bundled ZeroSSL compatibility certificate fingerprint does not match the pinned Sectigo R46 cross-certificate.")
        return pem

    def _installed_chain_has_legacy_cross_certificate(self) -> bool:
        if not self.cert_pem_path.is_file():
            return False
        try:
            installed = self.cert_pem_path.read_text(encoding="utf-8")
            cross = self._legacy_cross_certificate_pem().strip()
        except (OSError, ValueError):
            return False
        return cross in installed

    def _install_lego_certificate(self, domain: str) -> None:
        cert, key, issuer = self._find_lego_certificates(domain)
        certificate_pem = cert.read_text(encoding="utf-8").strip() + "\n"
        if issuer is not None:
            certificate_pem = certificate_pem.rstrip() + "\n" + issuer.read_text(encoding="utf-8").strip() + "\n"
        # ZeroSSL's current RSA intermediate chains to Sectigo R46. Android 13
        # predates R46's addition to AOSP's CA store, so append Sectigo's official
        # R46 cross-certificate to the long-standing USERTrust RSA root.
        certificate_pem = certificate_pem.rstrip() + "\n" + self._legacy_cross_certificate_pem()
        private_key_pem = key.read_text(encoding="utf-8")
        self._install_pem(certificate_pem, private_key_pem)

    def _find_lego_certificates(self, domain: str) -> tuple[Path, Path, Path | None]:
        base = self.acme_dir / "certificates"
        cert = base / f"{domain}.crt"
        key = base / f"{domain}.key"
        issuer = base / f"{domain}.issuer.crt"
        if not cert.is_file() or not key.is_file():
            raise ValueError("ACME client completed but certificate files were not found.")
        return cert, key, issuer if issuer.is_file() else None

    def _certificate_key_algorithm(self, path: Path | None = None) -> str | None:
        certificate = path if path is not None else self.cert_pem_path
        if not certificate.is_file():
            return None
        try:
            output = self._openssl(["x509", "-in", str(certificate), "-noout", "-text"]).stdout
        except ValueError:
            return None
        if "Public Key Algorithm: rsaEncryption" in output:
            return "RSA"
        if "Public Key Algorithm: id-ecPublicKey" in output:
            return "EC"
        return "OTHER"

    def _build_lego_command(
        self,
        domain: str,
        email: str,
        first_issue: bool,
        force_compat_reissue: bool = False,
    ) -> list[str]:
        # Use ZeroSSL RSA2048 intentionally for the Android 13 compatibility A/B test.
        # Keep this ACME state in its own directory so the previous Let's Encrypt
        # account/certificate material remains intact for rollback.
        command = [
            self.lego_binary,
            "run",
            "--server", ACME_CA,
            "--email", email,
            "--dns", "cloudflare",
            "--domains", domain,
            "--path", str(self.acme_dir),
            "--key-type", "RSA2048",
        ]
        if first_issue:
            command.append("--accept-tos")
        elif force_compat_reissue:
            command.extend(["--renew-force", "--no-random-sleep"])
        else:
            command.extend(["--renew-days", "30", "--no-random-sleep"])
        return command

    def _run_cloudflare(self) -> None:
        with self.lock:
            cfg = self._read_config()
        if cfg.get("mode") != "cloudflare":
            raise ValueError("Cloudflare ACME mode is not configured.")
        domain = self._validate_domain(cfg.get("domain"))
        email = self._validate_email(cfg.get("email"))
        if not self.token_path.is_file():
            raise ValueError("Cloudflare API token is not configured.")
        token = self.token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("Cloudflare API token is empty.")
        lego_cert_path = self.acme_dir / "certificates" / f"{domain}.crt"
        first_issue = not lego_cert_path.is_file()
        current_key_algorithm = self._certificate_key_algorithm(lego_cert_path)
        force_compat_reissue = bool(not first_issue and current_key_algorithm != "RSA")
        if first_issue and not cfg.get("accept_tos"):
            raise ValueError("Accept the ACME / ZeroSSL terms before requesting the first certificate.")
        if cfg.get("manage_dns_record"):
            target = str(cfg.get("dns_target") or "").strip()
            if not target:
                raise ValueError("Automatic Cloudflare A-record target is missing. Save the Cloudflare settings again.")
            self._sync_cloudflare_a_record(domain, target, token)

        if not first_issue and not force_compat_reissue and not self._expires_within(30):
            if not self._installed_chain_has_legacy_cross_certificate():
                self._install_lego_certificate(domain)
                self.last_output = (
                    "Reinstalled the existing ZeroSSL certificate with the Sectigo R46 "
                    "USERTrust cross-signed compatibility chain for Android 13."
                )
            else:
                self.last_output = "Certificate is already RSA, Android-compatible, and valid for more than 30 days; renewal is not due."
            return

        command = self._build_lego_command(
            domain,
            email,
            first_issue,
            force_compat_reissue=force_compat_reissue,
        )

        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.bridge_root),
            "TMPDIR": "/tmp",
            "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
            "CLOUDFLARE_DNS_API_TOKEN": token,
        }
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=600,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"ACME client failed: {exc}") from exc
        output = (completed.stdout or "").strip()
        self.last_output = output[-12000:]
        if completed.returncode != 0:
            raise ValueError("ACME client failed: " + (output[-4000:] or "unknown error"))

        self._install_lego_certificate(domain)

    def _worker(self) -> None:
        try:
            with self.lock:
                self.last_attempt = now_iso()
                self.last_error = None
            self._run_cloudflare()
            with self.lock:
                self.last_success = now_iso()
        except ValueError as exc:
            with self.lock:
                self.last_error = str(exc)
        finally:
            with self.lock:
                self.running = False

    def request_renew(self) -> bool:
        with self.lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._worker, name="certificate-renew", daemon=True).start()
        return True

    def _auto_loop(self) -> None:
        # Run the first certificate check shortly after container startup. A missing
        # ZeroSSL certificate state means this deployment still needs the CA migration.
        if self.stop_event.wait(10):
            return
        while not self.stop_event.is_set():
            try:
                with self.lock:
                    cfg = self._read_config()
                    should_check = cfg.get("mode") == "cloudflare" and bool(cfg.get("auto_renew")) and self.token_path.is_file()
                lego_cert_path = self.acme_dir / "certificates" / f"{cfg.get('domain', '')}.crt"
                needs_ca_migration = bool(should_check and not lego_cert_path.is_file())
                needs_android_compat = bool(
                    should_check
                    and lego_cert_path.is_file()
                    and self._certificate_key_algorithm(lego_cert_path) != "RSA"
                )
                needs_legacy_chain = bool(
                    should_check
                    and lego_cert_path.is_file()
                    and not self._installed_chain_has_legacy_cross_certificate()
                )
                if should_check and (needs_ca_migration or needs_android_compat or needs_legacy_chain or self._expires_within(30)):
                    self.request_renew()
            except Exception as exc:
                with self.lock:
                    self.last_error = f"Auto-renew check failed: {exc}"
            if self.stop_event.wait(6 * 3600):
                break

    def start(self) -> None:
        self.auto_thread = threading.Thread(target=self._auto_loop, name="certificate-auto-renew", daemon=True)
        self.auto_thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.auto_thread and self.auto_thread.is_alive():
            self.auto_thread.join(timeout=5)

    def status(self) -> dict[str, Any]:
        with self.lock:
            cfg = self._read_config()
            return {
                "mode": cfg.get("mode"),
                "domain": cfg.get("domain"),
                "email": cfg.get("email"),
                "auto_renew": bool(cfg.get("auto_renew")),
                "accept_tos": bool(cfg.get("accept_tos")),
                "manage_dns_record": bool(cfg.get("manage_dns_record", True)),
                "dns_target": str(cfg.get("dns_target") or ""),
                "dns_record_last_sync": self.last_dns_sync,
                "dns_record_last_action": self.last_dns_action,
                "dns_record_last_error": self.last_dns_error,
                "cloudflare_token_configured": self.token_path.is_file() and self.token_path.stat().st_size > 0,
                "pfx_path": str(self.pfx_path),
                "pfx_password": "",
                "certificate_exists": self.pfx_path.is_file(),
                "acme_ca": ACME_CA_LABEL if cfg.get("mode") == "cloudflare" else None,
                "key_algorithm": self._certificate_key_algorithm(),
                "legacy_cross_chain_installed": self._installed_chain_has_legacy_cross_certificate() if cfg.get("mode") == "cloudflare" else None,
                "android_legacy_compatible": bool(
                    self._certificate_key_algorithm() == "RSA"
                    and (cfg.get("mode") != "cloudflare" or self._installed_chain_has_legacy_cross_certificate())
                ),
                "expires": self._expiry(),
                "running": self.running,
                "last_attempt": self.last_attempt,
                "last_success": self.last_success,
                "last_error": self.last_error,
                "last_output": self.last_output,
            }


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


class BridgeApp:
    def __init__(self, store: ConfigStore, supervisor: FrpcSupervisor, certificates: CertificateManager, index_file: Path) -> None:
        self.store = store
        self.supervisor = supervisor
        self.certificates = certificates
        self.index_file = index_file

    @staticmethod
    def technitium_ready() -> bool:
        targets = ["127.0.0.1"]
        try:
            resolved = socket.gethostbyname(socket.gethostname())
            if resolved not in targets:
                targets.append(resolved)
        except OSError:
            pass
        for host in targets:
            try:
                with socket.create_connection((host, 5380), timeout=0.5):
                    return True
            except OSError:
                continue
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
                    cert_status = app.certificates.status()
                    self._json({
                        "ok": True,
                        "config": app.store.public_config(),
                        "technitium_ready": app.technitium_ready(),
                        "public_health": {
                            "dot_local_ready": app.supervisor._tcp_probe(853),
                            "certificate_exists": bool(cert_status.get("certificate_exists")),
                            "certificate_key_algorithm": cert_status.get("key_algorithm"),
                            "certificate_acme_ca": cert_status.get("acme_ca"),
                            "certificate_legacy_cross_chain_installed": cert_status.get("legacy_cross_chain_installed"),
                            "android_legacy_compatible": bool(cert_status.get("android_legacy_compatible")),
                            "certificate_last_error": cert_status.get("last_error"),
                        },
                    })
                    return
                if not path.startswith("/_bridge/api/"):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                if not self._require_auth():
                    return
                if path == "/_bridge/api/status":
                    self._json({"ok": True, "config": app.store.public_config(), "frpc": app.supervisor.status(), "certificate": app.certificates.status(), "technitium_ready": app.technitium_ready()})
                elif path == "/_bridge/api/backup":
                    backup = app.store.export_backup()
                    backup["certificate"] = app.certificates.export_config()
                    payload = json.dumps(backup, indent=2).encode()
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
                        app.certificates.import_config(backup.get("certificate"))
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
                    if path == "/_bridge/api/frpc-toml":
                        enabled = _bool(data.get("enabled", False), "enabled")
                        text = sanitize_frpc_toml(data.get("toml", ""))
                        if enabled:
                            text = app.supervisor.verify_toml(text)
                        config = app.store.save_frpc_toml(text, enabled)
                        app.supervisor.reload()
                        self._json({"ok": True, "config": config})
                    elif path == "/_bridge/api/certificate/import":
                        certificate_pem = str(data.get("certificate_pem") or "")
                        private_key_pem = str(data.get("private_key_pem") or "")
                        app.certificates.import_manual(certificate_pem, private_key_pem)
                        self._json({"ok": True, "certificate": app.certificates.status()})
                    elif path == "/_bridge/api/certificate/cloudflare":
                        dns_record = app.certificates.save_cloudflare(data, app.store.get_frpc_toml())
                        self._json({"ok": True, "certificate": app.certificates.status(), "dns_record": dns_record})
                    elif path == "/_bridge/api/certificate/renew":
                        started = app.certificates.request_renew()
                        self._json({"ok": True, "started": started, "certificate": app.certificates.status()})
                    elif path == "/_bridge/api/settings":
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
                        app.certificates.import_config(backup.get("certificate"))
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
    parser.add_argument("--technitium-config-dir", default=os.environ.get("TECHNITIUM_CONFIG_DIR", "/data/technitium"))
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
    certificates = CertificateManager(root, Path(args.technitium_config_dir))
    supervisor.start()
    certificates.start()
    app = BridgeApp(store, supervisor, certificates, Path(args.index_file))
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
        certificates.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
, block)
        if not (name and ptype and local and remote):
            continue
        if (
            name.group(1) in {"dns-bridge-dot", "dot"}
            and ptype.group(1) == "tcp"
            and int(local.group(1)) == 853
            and int(remote.group(1)) == 853
        ):
            for i in range(start, end):
                if re.match(r"^\s*localPort\s*=\s*853\s*$", lines[i].rstrip("\r\n")):
                    newline = "\n" if lines[i].endswith("\n") else ""
                    indent = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
                    lines[i] = f"{indent}localPort = {DOT_TLS_PROXY_PORT}{newline}"
                    break
    return "".join(lines).rstrip() + "\n"


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
                "frpc_toml": render_frpc_toml(DEFAULT_CONFIG),
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
                "frpc_toml": render_frpc_toml(frp),
                "migration": {"source": str(path), "migrated_at": now_iso()},
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None

    def _read(self) -> dict[str, Any]:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("format") != CONFIG_FORMAT:
            raise ValueError("Unsupported bridge configuration format.")
        changed = False
        frp = raw.get("frp")
        if not isinstance(frp, dict):
            frp = json.loads(json.dumps(DEFAULT_CONFIG))
            raw["frp"] = frp
            changed = True
        if "auth_token" in frp:
            frp.pop("auth_token", None)
            changed = True
        proxies = frp.get("proxies")
        if isinstance(proxies, dict):
            for obsolete in ("dns_tcp", "dns_udp"):
                if obsolete in proxies:
                    proxies.pop(obsolete, None)
                    changed = True
        normalized_frp = validate_frp(frp, require_server_addr=False)
        if normalized_frp != frp:
            raw["frp"] = normalized_frp
            frp = normalized_frp
            changed = True
        raw_toml = raw.get("frpc_toml")
        if not isinstance(raw_toml, str):
            raw["frpc_toml"] = render_frpc_toml(frp)
            changed = True
        else:
            cleaned = sanitize_frpc_toml(raw_toml)
            if cleaned != raw_toml:
                raw["frpc_toml"] = cleaned
                changed = True
        if changed:
            raw["updated_at"] = now_iso()
            _safe_write(self.path, json.dumps(raw, indent=2, sort_keys=True) + "\n")
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

    def get_frpc_toml(self) -> str:
        with self.lock:
            doc = self._read()
            return sanitize_frpc_toml(doc.get("frpc_toml", render_frpc_toml(doc.get("frp", DEFAULT_CONFIG))))

    def save_frpc_toml(self, text: str, enabled: bool) -> dict[str, Any]:
        cleaned = sanitize_frpc_toml(text)
        with self.lock:
            doc = self._read()
            frp = validate_frp(doc.get("frp", DEFAULT_CONFIG), require_server_addr=False)
            frp["enabled"] = bool(enabled)
            doc["frp"] = frp
            doc["frpc_toml"] = cleaned
            doc["updated_at"] = now_iso()
            self._write(doc)
        return self.public_config()

    def public_config(self) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
        frp = validate_frp(doc.get("frp", DEFAULT_CONFIG), require_server_addr=False)
        return {
            "format": CONFIG_FORMAT,
            "setup_required": not bool(doc.get("admin", {}).get("username")),
            "username": str(doc.get("admin", {}).get("username", "")),
            "frp": frp,
            "frpc_toml": sanitize_frpc_toml(doc.get("frpc_toml", render_frpc_toml(frp))),
            "migration": doc.get("migration"),
            "updated_at": doc.get("updated_at"),
        }

    def save_frp(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self.lock:
            doc = self._read()
            frp = validate_frp(payload, doc.get("frp", DEFAULT_CONFIG))
            doc["frp"] = frp
            doc["frpc_toml"] = render_frpc_toml(frp)
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
            "warning": "This backup contains FRP connection settings and the bridge administrator password hash. Store it securely.",
        }

    def import_backup(self, backup: Mapping[str, Any]) -> None:
        fmt = backup.get("format")
        if fmt == BACKUP_FORMAT:
            candidate = backup.get("config")
            if not isinstance(candidate, Mapping) or candidate.get("format") != CONFIG_FORMAT:
                raise ValueError("Bridge backup is incomplete.")
            frp = validate_frp(candidate.get("frp", {}), require_server_addr=False)
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
                "frpc_toml": sanitize_frpc_toml(candidate.get("frpc_toml", render_frpc_toml(frp))),
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
            doc["frpc_toml"] = render_frpc_toml(frp)
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

    def _write_config(self, text: str) -> None:
        _safe_write(self.store.frpc_path, sanitize_frpc_toml(text))

    def _config_hash(self, text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    def verify_toml(self, text: str) -> str:
        cleaned = sanitize_frpc_toml(text)
        if not cleaned:
            raise ValueError("frpc.toml cannot be empty.")
        verify_path = self.store.root / "frpc.verify.toml"
        _safe_write(verify_path, cleaned)
        try:
            completed = subprocess.run(
                [self.frpc_binary, "verify", "-c", str(verify_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "HOME": "/tmp",
                    "TMPDIR": "/tmp",
                    "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"Unable to verify frpc.toml: {exc}") from exc
        finally:
            try:
                verify_path.unlink()
            except OSError:
                pass
        output = (completed.stdout or "").strip()
        if completed.returncode != 0:
            raise ValueError("frpc.toml validation failed: " + (output[-4000:] or "unknown error"))
        return cleaned

    def _run(self) -> None:
        backoff = 1.0
        while not self.stop_event.is_set():
            try:
                frp = self.store.get_frp()
                config_text = self.store.get_frpc_toml()
                desired = bool(frp.get("enabled") and config_text.strip())
                config_hash = self._config_hash(config_text)
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

                self._write_config(config_text)
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
        probes: dict[str, bool | None] = {
            "dot_853": self._tcp_probe(853),
            "doq_853": None,
        }
        return {
            "enabled": bool(frp.get("enabled")),
            "configured": bool(self.store.get_frpc_toml().strip()),
            "running": running,
            "pid": pid,
            "started_at": started_at,
            "last_exit_code": exit_code,
            "last_error": last_error,
            "restart_count": restarts,
            "local_service_probes": probes,
            "logs": logs,
        }



class CertificateManager:
    def __init__(
        self,
        bridge_root: Path,
        technitium_config_dir: Path,
        lego_binary: str = "/usr/local/bin/lego",
        openssl_binary: str = "/usr/bin/openssl",
    ) -> None:
        self.bridge_root = bridge_root
        self.technitium_config_dir = technitium_config_dir
        self.lego_binary = lego_binary
        self.openssl_binary = openssl_binary
        self.config_path = bridge_root / "certificate.json"
        self.token_path = bridge_root / "cloudflare-dns-api-token"
        self.acme_dir = bridge_root / "acme-zerossl"
        self.legacy_cross_cert_path = Path(__file__).with_name("SectigoPublicServerAuthenticationRootR46_USERTrust.pem")
        self.cert_dir = technitium_config_dir / "certificates"
        self.cert_pem_path = self.cert_dir / "dns-tls.crt.pem"
        self.key_pem_path = self.cert_dir / "dns-tls.key.pem"
        self.pfx_path = self.cert_dir / "dns-tls.pfx"
        self.lock = threading.RLock()
        self.running = False
        self.last_error: str | None = None
        self.last_output = ""
        self.last_attempt: str | None = None
        self.last_success: str | None = None
        self.last_dns_sync: str | None = None
        self.last_dns_error: str | None = None
        self.last_dns_action: str | None = None
        self.stop_event = threading.Event()
        self.auto_thread: threading.Thread | None = None
        self._ensure_dirs()
        if not self.config_path.exists():
            self._write_config(DEFAULT_CERT_CONFIG)

    def _ensure_dirs(self) -> None:
        for path in (self.bridge_root, self.acme_dir, self.cert_dir):
            path.mkdir(parents=True, exist_ok=True)
        os.chmod(self.bridge_root, 0o700)
        os.chmod(self.acme_dir, 0o700)
        os.chmod(self.cert_dir, 0o700)

    def _read_config(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        cfg = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        raw_ca = ""
        if isinstance(raw, Mapping):
            raw_ca = str(raw.get("acme_ca") or "").strip().lower()
            cfg.update({k: raw.get(k, cfg[k]) for k in cfg})
        cfg["format"] = CERT_CONFIG_FORMAT
        cfg["acme_ca"] = ACME_CA
        cfg["mode"] = "cloudflare" if cfg.get("mode") == "cloudflare" else "manual"
        cfg["domain"] = str(cfg.get("domain") or "").strip().lower().rstrip(".")
        cfg["email"] = str(cfg.get("email") or "").strip()
        cfg["auto_renew"] = bool(cfg.get("auto_renew"))
        cfg["accept_tos"] = bool(cfg.get("accept_tos"))
        if cfg["mode"] == "cloudflare" and raw_ca != ACME_CA:
            # Consent to another CA's terms cannot be carried over automatically.
            cfg["accept_tos"] = False
        cfg["manage_dns_record"] = bool(cfg.get("manage_dns_record", True))
        cfg["dns_target"] = str(cfg.get("dns_target") or "").strip()
        return cfg

    def _write_config(self, cfg: Mapping[str, Any]) -> None:
        document = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        document.update({k: cfg.get(k, document[k]) for k in document})
        document["format"] = CERT_CONFIG_FORMAT
        document["updated_at"] = now_iso()
        _safe_write(self.config_path, json.dumps(document, indent=2, sort_keys=True) + "\n")

    @staticmethod
    def _validate_domain(value: Any) -> str:
        domain = str(value or "").strip().lower().rstrip(".")
        if not domain or len(domain) > 253 or not HOST_RE.fullmatch(domain) or ".." in domain:
            raise ValueError("Certificate domain must be a valid hostname.")
        try:
            socket.inet_pton(socket.AF_INET, domain)
            raise ValueError("Certificate domain must be a hostname, not an IP address.")
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, domain)
            raise ValueError("Certificate domain must be a hostname, not an IP address.")
        except OSError:
            pass
        if "." not in domain:
            raise ValueError("Certificate domain must be a fully qualified hostname.")
        return domain

    @staticmethod
    def _validate_email(value: Any) -> str:
        email = str(value or "").strip()
        if not EMAIL_RE.fullmatch(email) or len(email) > 254:
            raise ValueError("A valid ACME email address is required.")
        return email

    def export_config(self) -> dict[str, Any]:
        with self.lock:
            cfg = self._read_config()
        cfg.pop("updated_at", None)
        return cfg

    def import_config(self, cfg: Any) -> None:
        if not isinstance(cfg, Mapping):
            return
        mode = "cloudflare" if cfg.get("mode") == "cloudflare" else "manual"
        document = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
        document["mode"] = mode
        document["acme_ca"] = ACME_CA
        if mode == "cloudflare":
            domain = str(cfg.get("domain") or "").strip()
            email = str(cfg.get("email") or "").strip()
            if domain:
                document["domain"] = self._validate_domain(domain)
            if email:
                document["email"] = self._validate_email(email)
            document["auto_renew"] = bool(cfg.get("auto_renew"))
            document["accept_tos"] = bool(cfg.get("accept_tos")) and str(cfg.get("acme_ca") or "").strip().lower() == ACME_CA
            document["manage_dns_record"] = bool(cfg.get("manage_dns_record", True))
            document["dns_target"] = str(cfg.get("dns_target") or "").strip()
        self._write_config(document)

    @staticmethod
    def _frp_ipv4(frpc_toml: str) -> str:
        match = re.search(r'(?mi)^\s*serverAddr\s*=\s*"([^"]+)"\s*$', frpc_toml)
        if not match:
            raise ValueError("Could not find serverAddr in the saved frpc.toml.")
        host = match.group(1).strip()
        try:
            socket.inet_pton(socket.AF_INET, host)
            return host
        except OSError:
            pass
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"FRPS hostname {host!r} could not be resolved to IPv4.") from exc
        addresses = sorted({info[4][0] for info in infos if info and info[4]})
        if not addresses:
            raise ValueError(f"FRPS hostname {host!r} has no IPv4 address for an A record.")
        return addresses[0]

    @staticmethod
    def _cloudflare_error_message(payload: Any) -> str:
        if not isinstance(payload, Mapping):
            return "unknown Cloudflare API error"
        errors = payload.get("errors")
        if isinstance(errors, list):
            messages = []
            for item in errors:
                if isinstance(item, Mapping):
                    message = str(item.get("message") or "").strip()
                    code = item.get("code")
                    if message:
                        messages.append(f"{code}: {message}" if code is not None else message)
            if messages:
                return "; ".join(messages)
        return str(payload.get("message") or "unknown Cloudflare API error")

    def _cloudflare_api(
        self,
        token: str,
        method: str,
        path: str,
        query: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = "https://api.cloudflare.com/client/v4" + path
        if query:
            url += "?" + urlencode({key: value for key, value in query.items() if value is not None})
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "dns-bridge/1",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=payload, headers=headers, method=method)
        try:
            with urlopen(request, timeout=30) as response:
                raw = response.read()
        except HTTPError as exc:
            try:
                error_payload = json.loads(exc.read().decode("utf-8", "replace"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                error_payload = {}
            raise ValueError(
                f"Cloudflare API HTTP {exc.code}: {self._cloudflare_error_message(error_payload)}"
            ) from exc
        except URLError as exc:
            raise ValueError(f"Cloudflare API request failed: {exc.reason}") from exc
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Cloudflare API returned invalid JSON.") from exc
        if not isinstance(parsed, dict) or not parsed.get("success"):
            raise ValueError("Cloudflare API error: " + self._cloudflare_error_message(parsed))
        return parsed

    def _find_cloudflare_zone(self, token: str, domain: str) -> tuple[str, str]:
        labels = domain.rstrip(".").split(".")
        # Try the FQDN and then progressively shorter suffixes. The first
        # active Cloudflare zone returned is the most-specific matching zone.
        for index in range(max(1, len(labels) - 1)):
            candidate = ".".join(labels[index:])
            if "." not in candidate:
                continue
            response = self._cloudflare_api(
                token,
                "GET",
                "/zones",
                {"name": candidate, "status": "active", "per_page": 1},
            )
            result = response.get("result")
            if isinstance(result, list) and result:
                zone = result[0]
                if isinstance(zone, Mapping) and zone.get("id") and str(zone.get("name", "")).lower() == candidate.lower():
                    return str(zone["id"]), str(zone["name"])
        raise ValueError(
            f"Cloudflare zone for {domain} was not found. The token needs Zone Read access to the zone."
        )

    def _sync_cloudflare_a_record(self, domain: str, target: str, token: str) -> dict[str, str]:
        try:
            socket.inet_pton(socket.AF_INET, target)
        except OSError as exc:
            raise ValueError(f"Cloudflare A-record target {target!r} is not a valid IPv4 address.") from exc

        zone_id, zone_name = self._find_cloudflare_zone(token, domain)
        records_response = self._cloudflare_api(
            token,
            "GET",
            f"/zones/{zone_id}/dns_records",
            {"name": domain, "per_page": 100},
        )
        records = records_response.get("result")
        if not isinstance(records, list):
            records = []

        a_record = None
        conflicting = []
        for record in records:
            if not isinstance(record, Mapping):
                continue
            record_type = str(record.get("type") or "").upper()
            if record_type == "A" and a_record is None:
                a_record = record
            elif record_type in {"CNAME", "NS"}:
                conflicting.append(record_type)

        body = {
            "type": "A",
            "name": domain,
            "content": target,
            "ttl": 1,
            "proxied": False,
        }
        if a_record is not None and a_record.get("id"):
            current_content = str(a_record.get("content") or "")
            current_proxied = bool(a_record.get("proxied"))
            if current_content == target and not current_proxied:
                action = "unchanged"
            else:
                self._cloudflare_api(
                    token,
                    "PATCH",
                    f"/zones/{zone_id}/dns_records/{a_record['id']}",
                    body=body,
                )
                action = "updated"
        else:
            if conflicting:
                kinds = ", ".join(sorted(set(conflicting)))
                raise ValueError(
                    f"Cannot create A record for {domain}: a conflicting {kinds} record already exists."
                )
            self._cloudflare_api(
                token,
                "POST",
                f"/zones/{zone_id}/dns_records",
                body=body,
            )
            action = "created"

        with self.lock:
            self.last_dns_sync = now_iso()
            self.last_dns_error = None
            self.last_dns_action = action
        return {"action": action, "zone": zone_name, "name": domain, "target": target}

    def save_cloudflare(self, payload: Mapping[str, Any], frpc_toml: str) -> dict[str, str] | None:
        domain = self._validate_domain(payload.get("domain"))
        email = self._validate_email(payload.get("email"))
        api_token = str(payload.get("api_token") or "")
        if len(api_token) > 4096:
            raise ValueError("Cloudflare API token is too long.")
        clear_token = _bool(payload.get("clear_token", False), "clear_token")
        manage_dns_record = _bool(payload.get("manage_dns_record", True), "manage_dns_record")
        dns_target = self._frp_ipv4(frpc_toml) if manage_dns_record else ""
        cfg = {
            "format": CERT_CONFIG_FORMAT,
            "acme_ca": ACME_CA,
            "mode": "cloudflare",
            "domain": domain,
            "email": email,
            "auto_renew": _bool(payload.get("auto_renew", True), "auto_renew"),
            "accept_tos": _bool(payload.get("accept_tos", False), "accept_tos"),
            "manage_dns_record": manage_dns_record,
            "dns_target": dns_target,
        }
        with self.lock:
            self._write_config(cfg)
            if api_token:
                _safe_write(self.token_path, api_token.strip() + "\n")
            elif clear_token:
                try:
                    self.token_path.unlink()
                except FileNotFoundError:
                    pass

        if not manage_dns_record:
            with self.lock:
                self.last_dns_error = None
                self.last_dns_action = None
            return None

        if not self.token_path.is_file():
            raise ValueError("Cloudflare API token is required to create or update the DNS A record.")
        token = self.token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("Cloudflare API token is empty.")
        try:
            return self._sync_cloudflare_a_record(domain, dns_target, token)
        except ValueError as exc:
            with self.lock:
                self.last_dns_error = str(exc)
            raise

    def _openssl(self, args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
        try:
            completed = subprocess.run(
                [self.openssl_binary, *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TMPDIR": "/tmp"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"OpenSSL failed: {exc}") from exc
        if completed.returncode != 0:
            raise ValueError("OpenSSL failed: " + (completed.stdout or "unknown error")[-4000:])
        return completed

    def _install_pem(self, certificate_pem: str, private_key_pem: str) -> None:
        if "-----BEGIN CERTIFICATE-----" not in certificate_pem:
            raise ValueError("Certificate file is not PEM encoded.")
        if "-----BEGIN " not in private_key_pem or "PRIVATE KEY-----" not in private_key_pem:
            raise ValueError("Private key file is not PEM encoded.")
        temp_cert = self.cert_dir / ".dns-tls.crt.tmp"
        temp_key = self.cert_dir / ".dns-tls.key.tmp"
        temp_pfx = self.cert_dir / ".dns-tls.pfx.tmp"
        _safe_write(temp_cert, certificate_pem.rstrip() + "\n")
        _safe_write(temp_key, private_key_pem.rstrip() + "\n")
        try:
            cert_pub = self._openssl(["x509", "-in", str(temp_cert), "-pubkey", "-noout"]).stdout
            key_pub = self._openssl(["pkey", "-in", str(temp_key), "-pubout"]).stdout
            if hashlib.sha256(cert_pub.encode()).digest() != hashlib.sha256(key_pub.encode()).digest():
                raise ValueError("Certificate and private key do not match.")
            self._openssl([
                "pkcs12", "-export",
                "-out", str(temp_pfx),
                "-inkey", str(temp_key),
                "-in", str(temp_cert),
                "-passout", "pass:",
            ])
            os.chmod(temp_pfx, 0o600)
            os.replace(temp_cert, self.cert_pem_path)
            os.replace(temp_key, self.key_pem_path)
            os.replace(temp_pfx, self.pfx_path)
            os.chmod(self.cert_pem_path, 0o600)
            os.chmod(self.key_pem_path, 0o600)
            os.chmod(self.pfx_path, 0o600)
        finally:
            for path in (temp_cert, temp_key, temp_pfx):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass

    def import_manual(self, certificate_pem: str, private_key_pem: str) -> None:
        with self.lock:
            self._install_pem(certificate_pem, private_key_pem)
            cfg = json.loads(json.dumps(DEFAULT_CERT_CONFIG))
            cfg["mode"] = "manual"
            cfg["auto_renew"] = False
            self._write_config(cfg)
            self.last_error = None
            self.last_success = now_iso()
            self.last_output = "Manual certificate imported and converted to PKCS#12."

    def _expiry(self) -> str | None:
        if not self.cert_pem_path.is_file():
            return None
        try:
            output = self._openssl(["x509", "-in", str(self.cert_pem_path), "-noout", "-enddate"]).stdout.strip()
            return output.split("=", 1)[1] if "=" in output else output
        except ValueError:
            return None

    def _expires_within(self, days: int) -> bool:
        if not self.cert_pem_path.is_file():
            return True
        try:
            completed = subprocess.run(
                [self.openssl_binary, "x509", "-in", str(self.cert_pem_path), "-noout", "-checkend", str(days * 86400)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            return completed.returncode != 0
        except (OSError, subprocess.TimeoutExpired):
            return True

    def _legacy_cross_certificate_pem(self) -> str:
        if not self.legacy_cross_cert_path.is_file():
            raise ValueError(
                "Bundled Sectigo R46 USERTrust cross certificate is missing; "
                "cannot build the Android-compatible ZeroSSL chain."
            )
        pem = self.legacy_cross_cert_path.read_text(encoding="utf-8").strip() + "\n"
        try:
            info = self._openssl([
                "x509", "-in", str(self.legacy_cross_cert_path), "-noout",
                "-subject", "-issuer", "-fingerprint", "-sha256"
            ]).stdout
        except ValueError as exc:
            raise ValueError(f"Bundled ZeroSSL compatibility certificate is invalid: {exc}") from exc
        lowered = info.lower()
        if "sectigo public server authentication root r46" not in lowered:
            raise ValueError("Bundled ZeroSSL compatibility certificate has the wrong subject.")
        if "usertrust rsa certification authority" not in lowered:
            raise ValueError("Bundled ZeroSSL compatibility certificate is not USERTrust cross-signed.")
        fingerprint = re.sub(r"[^0-9A-F]", "", info.upper().split("SHA256 FINGERPRINT=", 1)[-1])
        if fingerprint != LEGACY_CROSS_CERT_SHA256:
            raise ValueError("Bundled ZeroSSL compatibility certificate fingerprint does not match the pinned Sectigo R46 cross-certificate.")
        return pem

    def _installed_chain_has_legacy_cross_certificate(self) -> bool:
        if not self.cert_pem_path.is_file():
            return False
        try:
            installed = self.cert_pem_path.read_text(encoding="utf-8")
            cross = self._legacy_cross_certificate_pem().strip()
        except (OSError, ValueError):
            return False
        return cross in installed

    def _install_lego_certificate(self, domain: str) -> None:
        cert, key, issuer = self._find_lego_certificates(domain)
        certificate_pem = cert.read_text(encoding="utf-8").strip() + "\n"
        if issuer is not None:
            certificate_pem = certificate_pem.rstrip() + "\n" + issuer.read_text(encoding="utf-8").strip() + "\n"
        # ZeroSSL's current RSA intermediate chains to Sectigo R46. Android 13
        # predates R46's addition to AOSP's CA store, so append Sectigo's official
        # R46 cross-certificate to the long-standing USERTrust RSA root.
        certificate_pem = certificate_pem.rstrip() + "\n" + self._legacy_cross_certificate_pem()
        private_key_pem = key.read_text(encoding="utf-8")
        self._install_pem(certificate_pem, private_key_pem)

    def _find_lego_certificates(self, domain: str) -> tuple[Path, Path, Path | None]:
        base = self.acme_dir / "certificates"
        cert = base / f"{domain}.crt"
        key = base / f"{domain}.key"
        issuer = base / f"{domain}.issuer.crt"
        if not cert.is_file() or not key.is_file():
            raise ValueError("ACME client completed but certificate files were not found.")
        return cert, key, issuer if issuer.is_file() else None

    def _certificate_key_algorithm(self, path: Path | None = None) -> str | None:
        certificate = path if path is not None else self.cert_pem_path
        if not certificate.is_file():
            return None
        try:
            output = self._openssl(["x509", "-in", str(certificate), "-noout", "-text"]).stdout
        except ValueError:
            return None
        if "Public Key Algorithm: rsaEncryption" in output:
            return "RSA"
        if "Public Key Algorithm: id-ecPublicKey" in output:
            return "EC"
        return "OTHER"

    def _build_lego_command(
        self,
        domain: str,
        email: str,
        first_issue: bool,
        force_compat_reissue: bool = False,
    ) -> list[str]:
        # Use ZeroSSL RSA2048 intentionally for the Android 13 compatibility A/B test.
        # Keep this ACME state in its own directory so the previous Let's Encrypt
        # account/certificate material remains intact for rollback.
        command = [
            self.lego_binary,
            "run",
            "--server", ACME_CA,
            "--email", email,
            "--dns", "cloudflare",
            "--domains", domain,
            "--path", str(self.acme_dir),
            "--key-type", "RSA2048",
        ]
        if first_issue:
            command.append("--accept-tos")
        elif force_compat_reissue:
            command.extend(["--renew-force", "--no-random-sleep"])
        else:
            command.extend(["--renew-days", "30", "--no-random-sleep"])
        return command

    def _run_cloudflare(self) -> None:
        with self.lock:
            cfg = self._read_config()
        if cfg.get("mode") != "cloudflare":
            raise ValueError("Cloudflare ACME mode is not configured.")
        domain = self._validate_domain(cfg.get("domain"))
        email = self._validate_email(cfg.get("email"))
        if not self.token_path.is_file():
            raise ValueError("Cloudflare API token is not configured.")
        token = self.token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("Cloudflare API token is empty.")
        lego_cert_path = self.acme_dir / "certificates" / f"{domain}.crt"
        first_issue = not lego_cert_path.is_file()
        current_key_algorithm = self._certificate_key_algorithm(lego_cert_path)
        force_compat_reissue = bool(not first_issue and current_key_algorithm != "RSA")
        if first_issue and not cfg.get("accept_tos"):
            raise ValueError("Accept the ACME / ZeroSSL terms before requesting the first certificate.")
        if cfg.get("manage_dns_record"):
            target = str(cfg.get("dns_target") or "").strip()
            if not target:
                raise ValueError("Automatic Cloudflare A-record target is missing. Save the Cloudflare settings again.")
            self._sync_cloudflare_a_record(domain, target, token)

        if not first_issue and not force_compat_reissue and not self._expires_within(30):
            if not self._installed_chain_has_legacy_cross_certificate():
                self._install_lego_certificate(domain)
                self.last_output = (
                    "Reinstalled the existing ZeroSSL certificate with the Sectigo R46 "
                    "USERTrust cross-signed compatibility chain for Android 13."
                )
            else:
                self.last_output = "Certificate is already RSA, Android-compatible, and valid for more than 30 days; renewal is not due."
            return

        command = self._build_lego_command(
            domain,
            email,
            first_issue,
            force_compat_reissue=force_compat_reissue,
        )

        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.bridge_root),
            "TMPDIR": "/tmp",
            "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
            "CLOUDFLARE_DNS_API_TOKEN": token,
        }
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=600,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"ACME client failed: {exc}") from exc
        output = (completed.stdout or "").strip()
        self.last_output = output[-12000:]
        if completed.returncode != 0:
            raise ValueError("ACME client failed: " + (output[-4000:] or "unknown error"))

        self._install_lego_certificate(domain)

    def _worker(self) -> None:
        try:
            with self.lock:
                self.last_attempt = now_iso()
                self.last_error = None
            self._run_cloudflare()
            with self.lock:
                self.last_success = now_iso()
        except ValueError as exc:
            with self.lock:
                self.last_error = str(exc)
        finally:
            with self.lock:
                self.running = False

    def request_renew(self) -> bool:
        with self.lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._worker, name="certificate-renew", daemon=True).start()
        return True

    def _auto_loop(self) -> None:
        # Run the first certificate check shortly after container startup. A missing
        # ZeroSSL certificate state means this deployment still needs the CA migration.
        if self.stop_event.wait(10):
            return
        while not self.stop_event.is_set():
            try:
                with self.lock:
                    cfg = self._read_config()
                    should_check = cfg.get("mode") == "cloudflare" and bool(cfg.get("auto_renew")) and self.token_path.is_file()
                lego_cert_path = self.acme_dir / "certificates" / f"{cfg.get('domain', '')}.crt"
                needs_ca_migration = bool(should_check and not lego_cert_path.is_file())
                needs_android_compat = bool(
                    should_check
                    and lego_cert_path.is_file()
                    and self._certificate_key_algorithm(lego_cert_path) != "RSA"
                )
                needs_legacy_chain = bool(
                    should_check
                    and lego_cert_path.is_file()
                    and not self._installed_chain_has_legacy_cross_certificate()
                )
                if should_check and (needs_ca_migration or needs_android_compat or needs_legacy_chain or self._expires_within(30)):
                    self.request_renew()
            except Exception as exc:
                with self.lock:
                    self.last_error = f"Auto-renew check failed: {exc}"
            if self.stop_event.wait(6 * 3600):
                break

    def start(self) -> None:
        self.auto_thread = threading.Thread(target=self._auto_loop, name="certificate-auto-renew", daemon=True)
        self.auto_thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.auto_thread and self.auto_thread.is_alive():
            self.auto_thread.join(timeout=5)

    def status(self) -> dict[str, Any]:
        with self.lock:
            cfg = self._read_config()
            return {
                "mode": cfg.get("mode"),
                "domain": cfg.get("domain"),
                "email": cfg.get("email"),
                "auto_renew": bool(cfg.get("auto_renew")),
                "accept_tos": bool(cfg.get("accept_tos")),
                "manage_dns_record": bool(cfg.get("manage_dns_record", True)),
                "dns_target": str(cfg.get("dns_target") or ""),
                "dns_record_last_sync": self.last_dns_sync,
                "dns_record_last_action": self.last_dns_action,
                "dns_record_last_error": self.last_dns_error,
                "cloudflare_token_configured": self.token_path.is_file() and self.token_path.stat().st_size > 0,
                "pfx_path": str(self.pfx_path),
                "pfx_password": "",
                "certificate_exists": self.pfx_path.is_file(),
                "acme_ca": ACME_CA_LABEL if cfg.get("mode") == "cloudflare" else None,
                "key_algorithm": self._certificate_key_algorithm(),
                "legacy_cross_chain_installed": self._installed_chain_has_legacy_cross_certificate() if cfg.get("mode") == "cloudflare" else None,
                "android_legacy_compatible": bool(
                    self._certificate_key_algorithm() == "RSA"
                    and (cfg.get("mode") != "cloudflare" or self._installed_chain_has_legacy_cross_certificate())
                ),
                "expires": self._expiry(),
                "running": self.running,
                "last_attempt": self.last_attempt,
                "last_success": self.last_success,
                "last_error": self.last_error,
                "last_output": self.last_output,
            }


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


class BridgeApp:
    def __init__(self, store: ConfigStore, supervisor: FrpcSupervisor, certificates: CertificateManager, index_file: Path) -> None:
        self.store = store
        self.supervisor = supervisor
        self.certificates = certificates
        self.index_file = index_file

    @staticmethod
    def technitium_ready() -> bool:
        targets = ["127.0.0.1"]
        try:
            resolved = socket.gethostbyname(socket.gethostname())
            if resolved not in targets:
                targets.append(resolved)
        except OSError:
            pass
        for host in targets:
            try:
                with socket.create_connection((host, 5380), timeout=0.5):
                    return True
            except OSError:
                continue
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
                    cert_status = app.certificates.status()
                    self._json({
                        "ok": True,
                        "config": app.store.public_config(),
                        "technitium_ready": app.technitium_ready(),
                        "public_health": {
                            "dot_local_ready": app.supervisor._tcp_probe(853),
                            "certificate_exists": bool(cert_status.get("certificate_exists")),
                            "certificate_key_algorithm": cert_status.get("key_algorithm"),
                            "certificate_acme_ca": cert_status.get("acme_ca"),
                            "certificate_legacy_cross_chain_installed": cert_status.get("legacy_cross_chain_installed"),
                            "android_legacy_compatible": bool(cert_status.get("android_legacy_compatible")),
                            "certificate_last_error": cert_status.get("last_error"),
                        },
                    })
                    return
                if not path.startswith("/_bridge/api/"):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                if not self._require_auth():
                    return
                if path == "/_bridge/api/status":
                    self._json({"ok": True, "config": app.store.public_config(), "frpc": app.supervisor.status(), "certificate": app.certificates.status(), "technitium_ready": app.technitium_ready()})
                elif path == "/_bridge/api/backup":
                    backup = app.store.export_backup()
                    backup["certificate"] = app.certificates.export_config()
                    payload = json.dumps(backup, indent=2).encode()
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
                        app.certificates.import_config(backup.get("certificate"))
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
                    if path == "/_bridge/api/frpc-toml":
                        enabled = _bool(data.get("enabled", False), "enabled")
                        text = sanitize_frpc_toml(data.get("toml", ""))
                        if enabled:
                            text = app.supervisor.verify_toml(text)
                        config = app.store.save_frpc_toml(text, enabled)
                        app.supervisor.reload()
                        self._json({"ok": True, "config": config})
                    elif path == "/_bridge/api/certificate/import":
                        certificate_pem = str(data.get("certificate_pem") or "")
                        private_key_pem = str(data.get("private_key_pem") or "")
                        app.certificates.import_manual(certificate_pem, private_key_pem)
                        self._json({"ok": True, "certificate": app.certificates.status()})
                    elif path == "/_bridge/api/certificate/cloudflare":
                        dns_record = app.certificates.save_cloudflare(data, app.store.get_frpc_toml())
                        self._json({"ok": True, "certificate": app.certificates.status(), "dns_record": dns_record})
                    elif path == "/_bridge/api/certificate/renew":
                        started = app.certificates.request_renew()
                        self._json({"ok": True, "started": started, "certificate": app.certificates.status()})
                    elif path == "/_bridge/api/settings":
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
                        app.certificates.import_config(backup.get("certificate"))
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
    parser.add_argument("--technitium-config-dir", default=os.environ.get("TECHNITIUM_CONFIG_DIR", "/data/technitium"))
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
    certificates = CertificateManager(root, Path(args.technitium_config_dir))
    supervisor.start()
    certificates.start()
    app = BridgeApp(store, supervisor, certificates, Path(args.index_file))
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
        certificates.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
