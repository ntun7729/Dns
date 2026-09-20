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
MAX_TOML_BYTES = 128 * 1024
CERT_CONFIG_FORMAT = "dns-bridge-certificate-v1"
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

DEFAULT_CERT_CONFIG = {
    "format": CERT_CONFIG_FORMAT,
    "mode": "manual",
    "domain": "",
    "email": "",
    "auto_renew": False,
    "accept_tos": False,
    "updated_at": None,
}

DEFAULT_CONFIG = {
    "enabled": False,
    "server_addr": "",
    "server_port": 7000,
    "transport_tls": True,
    "proxies": {
        "dot": {"enabled": True, "type": "tcp", "local_port": 853, "remote_port": 853},
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
        frp = validate_frp(doc.get("frp", DEFAULT_CONFIG))
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
        self.acme_dir = bridge_root / "acme"
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
        if isinstance(raw, Mapping):
            cfg.update({k: raw.get(k, cfg[k]) for k in cfg})
        cfg["format"] = CERT_CONFIG_FORMAT
        cfg["mode"] = "cloudflare" if cfg.get("mode") == "cloudflare" else "manual"
        cfg["domain"] = str(cfg.get("domain") or "").strip().lower().rstrip(".")
        cfg["email"] = str(cfg.get("email") or "").strip()
        cfg["auto_renew"] = bool(cfg.get("auto_renew"))
        cfg["accept_tos"] = bool(cfg.get("accept_tos"))
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
        if mode == "cloudflare":
            domain = str(cfg.get("domain") or "").strip()
            email = str(cfg.get("email") or "").strip()
            if domain:
                document["domain"] = self._validate_domain(domain)
            if email:
                document["email"] = self._validate_email(email)
            document["auto_renew"] = bool(cfg.get("auto_renew"))
            document["accept_tos"] = bool(cfg.get("accept_tos"))
        self._write_config(document)

    def save_cloudflare(self, payload: Mapping[str, Any]) -> None:
        domain = self._validate_domain(payload.get("domain"))
        email = self._validate_email(payload.get("email"))
        api_token = str(payload.get("api_token") or "")
        if len(api_token) > 4096:
            raise ValueError("Cloudflare API token is too long.")
        clear_token = _bool(payload.get("clear_token", False), "clear_token")
        cfg = {
            "format": CERT_CONFIG_FORMAT,
            "mode": "cloudflare",
            "domain": domain,
            "email": email,
            "auto_renew": _bool(payload.get("auto_renew", True), "auto_renew"),
            "accept_tos": _bool(payload.get("accept_tos", False), "accept_tos"),
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

    def _find_lego_certificates(self, domain: str) -> tuple[Path, Path, Path | None]:
        base = self.acme_dir / "certificates"
        cert = base / f"{domain}.crt"
        key = base / f"{domain}.key"
        issuer = base / f"{domain}.issuer.crt"
        if not cert.is_file() or not key.is_file():
            raise ValueError("ACME client completed but certificate files were not found.")
        return cert, key, issuer if issuer.is_file() else None

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
        if first_issue and not cfg.get("accept_tos"):
            raise ValueError("Accept the ACME/Let's Encrypt terms before requesting the first certificate.")
        if not first_issue and not self._expires_within(30):
            self.last_output = "Certificate is valid for more than 30 days; renewal is not due."
            return

        # lego's account/provider/domain/path options are global CLI flags and
        # must precede the run/renew subcommand. Renewal-specific flags follow it.
        command = [
            self.lego_binary,
            "--email", email,
            "--dns", "cloudflare",
            "--domains", domain,
            "--path", str(self.acme_dir),
        ]
        if first_issue:
            command.extend(["--accept-tos", "run"])
        else:
            command.extend(["renew", "--days", "30", "--no-random-sleep"])

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

        cert, key, issuer = self._find_lego_certificates(domain)
        certificate_pem = cert.read_text(encoding="utf-8")
        if issuer is not None:
            certificate_pem = certificate_pem.rstrip() + "\n" + issuer.read_text(encoding="utf-8").lstrip()
        private_key_pem = key.read_text(encoding="utf-8")
        self._install_pem(certificate_pem, private_key_pem)

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
        if self.stop_event.wait(60):
            return
        while not self.stop_event.is_set():
            try:
                with self.lock:
                    cfg = self._read_config()
                    should_check = cfg.get("mode") == "cloudflare" and bool(cfg.get("auto_renew")) and self.token_path.is_file()
                if should_check and self._expires_within(30):
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
                "cloudflare_token_configured": self.token_path.is_file() and self.token_path.stat().st_size > 0,
                "pfx_path": str(self.pfx_path),
                "pfx_password": "",
                "certificate_exists": self.pfx_path.is_file(),
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
                        app.certificates.save_cloudflare(data)
                        self._json({"ok": True, "certificate": app.certificates.status()})
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
