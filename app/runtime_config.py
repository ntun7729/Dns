from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Mapping

from certificates import secure_write, valid_dns_hostname
from settings import Settings, now_iso

CONFIG_FORMAT = "dns-dashboard-config-v2"
DEFAULT_DATA_ROOT = Path("/data/dns-dashboard")
FALLBACK_DATA_ROOT = Path("/tmp/dns-dashboard")
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 256
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

_EDITABLE_FIELDS = (
    "service_name",
    "dot_enabled",
    "dot_bind_host",
    "dot_port",
    "dot_public_hostname",
    "upstream_timeout_seconds",
    "resolver_cooldown_seconds",
    "resolver_cooldown_max_seconds",
    "frpc_enabled",
    "frp_server_addr",
    "frp_server_port",
    "frp_auth_token",
    "frp_remote_port",
    "history_minutes",
    "filter_update_hours",
)


def _password_hash(password: str, *, enforce_policy: bool = True) -> str:
    if enforce_policy and not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
        raise ValueError(
            f"Dashboard password must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters."
        )
    if not password or len(password) > PASSWORD_MAX_LENGTH:
        raise ValueError("Dashboard password is invalid.")
    salt = os.urandom(16)
    n, r, p = 16384, 8, 1
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32
    )
    return "scrypt${}${}${}${}${}".format(
        n,
        r,
        p,
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(derived).decode("ascii").rstrip("="),
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
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected)
        )
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


def _int(value: Any, field: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer.") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}.")
    return parsed


def _float(value: Any, field: str, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a number.") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}.")
    return parsed


def _server_address(value: Any) -> str:
    candidate = str(value or "").strip().rstrip(".")
    if not candidate:
        return ""
    if len(candidate) > 253 or any(char.isspace() for char in candidate):
        raise ValueError("FRP server address is invalid.")
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    if not _HOST_RE.fullmatch(candidate) or ".." in candidate:
        raise ValueError("FRP server address must be an IP address or hostname.")
    return candidate.lower()


def _loopback_bind(value: Any) -> str:
    candidate = str(value or "").strip()
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError("Local DoT bind address must be a loopback IP address.") from exc
    if not address.is_loopback:
        raise ValueError(
            "Local DoT bind address must stay on loopback; expose DoT through FRPC instead."
        )
    return str(address)


class RuntimeConfigStore:
    """Persist dashboard-managed service settings and administrator credentials."""

    def __init__(self, root: Path | None = None) -> None:
        self.lock = threading.RLock()
        self.root = Path(root or DEFAULT_DATA_ROOT)
        self.fallback_used = False
        self._ensure_root()
        self.path = self.root / "config.json"

    def _ensure_root(self) -> None:
        try:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.root.chmod(0o700)
            probe = self.root / ".write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
        except OSError:
            self.root = FALLBACK_DATA_ROOT
            self.fallback_used = True
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                self.root.chmod(0o700)
            except OSError:
                pass

    def prepare_paths(self, settings: Settings) -> None:
        """Move all mutable/secrets files under the dashboard data directory."""
        object.__setattr__(settings, "dot_cert_file", str(self.root / "tls.crt"))
        object.__setattr__(settings, "dot_key_file", str(self.root / "tls.key"))
        object.__setattr__(settings, "frpc_config_file", str(self.root / "frpc.toml"))
        object.__setattr__(settings, "profiles_file", str(self.root / "profiles.json"))

    def _read(self) -> dict[str, Any]:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("format") != CONFIG_FORMAT:
            raise ValueError("Unsupported dashboard configuration format.")
        settings = raw.get("settings")
        auth = raw.get("auth")
        if not isinstance(settings, dict) or not isinstance(auth, dict):
            raise ValueError("Dashboard configuration is incomplete.")
        return raw

    def _write(self, document: Mapping[str, Any]) -> None:
        secure_write(
            self.path,
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )

    @staticmethod
    def _settings_from_object(settings: Settings) -> dict[str, Any]:
        return {field: getattr(settings, field) for field in _EDITABLE_FIELDS}

    def _migrated_document(self, settings: Settings) -> dict[str, Any]:
        username = settings.dashboard_username.strip()
        password = settings.dashboard_password
        auth: dict[str, Any] = {"username": "", "password_hash": ""}
        if username and password and _USERNAME_RE.fullmatch(username):
            # Preserve an existing deployment even when its legacy password does
            # not meet the stronger policy required for newly created passwords.
            auth = {
                "username": username,
                "password_hash": _password_hash(password, enforce_policy=False),
            }
        return {
            "format": CONFIG_FORMAT,
            "updated_at": now_iso(),
            "settings": self._settings_from_object(settings),
            "auth": auth,
        }

    def load_into(self, settings: Settings) -> None:
        """Load persistent settings, or migrate current environment values once."""
        self.prepare_paths(settings)
        with self.lock:
            if self.path.is_file():
                try:
                    document = self._read()
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    broken = self.path.with_suffix(".broken.json")
                    try:
                        os.replace(self.path, broken)
                    except OSError:
                        pass
                    raise RuntimeError(
                        f"Persistent dashboard configuration is invalid: {exc}"
                    ) from exc
            else:
                document = self._migrated_document(settings)
                self._write(document)
            self._apply_document(settings, document)

    def _apply_document(self, settings: Settings, document: Mapping[str, Any]) -> None:
        stored = document.get("settings", {})
        if isinstance(stored, Mapping):
            for field in _EDITABLE_FIELDS:
                if field in stored:
                    object.__setattr__(settings, field, stored[field])
        auth = document.get("auth", {})
        username = str(auth.get("username", "")) if isinstance(auth, Mapping) else ""
        password_hash = (
            str(auth.get("password_hash", "")) if isinstance(auth, Mapping) else ""
        )
        object.__setattr__(settings, "dashboard_username", username)
        object.__setattr__(
            settings,
            "dashboard_password",
            "[dashboard-managed]" if username and password_hash else "",
        )
        object.__setattr__(settings, "dot_cert_pem", "")
        object.__setattr__(settings, "dot_key_pem", "")

    def auth_enabled(self) -> bool:
        with self.lock:
            try:
                auth = self._read().get("auth", {})
            except (OSError, ValueError, json.JSONDecodeError):
                return False
            return bool(auth.get("username") and auth.get("password_hash"))

    def verify(self, username: str, password: str) -> bool:
        with self.lock:
            try:
                auth = self._read().get("auth", {})
            except (OSError, ValueError, json.JSONDecodeError):
                return False
        expected_user = str(auth.get("username", ""))
        encoded = str(auth.get("password_hash", ""))
        return bool(
            expected_user
            and encoded
            and hmac.compare_digest(username, expected_user)
            and verify_password(password, encoded)
        )

    def set_credentials(
        self,
        settings: Settings,
        username: str,
        password: str,
        *,
        require_unconfigured: bool = False,
    ) -> None:
        username = username.strip()
        if not _USERNAME_RE.fullmatch(username):
            raise ValueError(
                "Username must be 1-64 characters using letters, numbers, dot, dash, or underscore."
            )
        encoded = _password_hash(password)
        with self.lock:
            document = self._read()
            auth = document.get("auth", {})
            if require_unconfigured and auth.get("username") and auth.get("password_hash"):
                raise ValueError("Dashboard administrator is already configured.")
            document["auth"] = {"username": username, "password_hash": encoded}
            document["updated_at"] = now_iso()
            self._write(document)
            self._apply_document(settings, document)

    def validate_settings(
        self, payload: Mapping[str, Any], current: Mapping[str, Any]
    ) -> dict[str, Any]:
        result = dict(current)
        if "service_name" in payload:
            name = str(payload.get("service_name", "")).strip()
            if not 1 <= len(name) <= 80:
                raise ValueError("Service name must be 1-80 characters.")
            result["service_name"] = name
        if "dot_enabled" in payload:
            result["dot_enabled"] = _bool(payload["dot_enabled"], "dot_enabled")
        if "dot_bind_host" in payload:
            result["dot_bind_host"] = _loopback_bind(payload["dot_bind_host"])
        if "dot_port" in payload:
            result["dot_port"] = _int(payload["dot_port"], "dot_port", 1, 65535)
        if "dot_public_hostname" in payload:
            hostname = str(payload.get("dot_public_hostname", "")).strip().rstrip(".").lower()
            if hostname and not valid_dns_hostname(hostname):
                raise ValueError("Private DNS hostname is not a valid DNS hostname.")
            result["dot_public_hostname"] = hostname
        if "upstream_timeout_seconds" in payload:
            result["upstream_timeout_seconds"] = _float(
                payload["upstream_timeout_seconds"], "upstream_timeout_seconds", 0.2, 30.0
            )
        if "resolver_cooldown_seconds" in payload:
            result["resolver_cooldown_seconds"] = _float(
                payload["resolver_cooldown_seconds"], "resolver_cooldown_seconds", 0.0, 600.0
            )
        if "resolver_cooldown_max_seconds" in payload:
            result["resolver_cooldown_max_seconds"] = _float(
                payload["resolver_cooldown_max_seconds"],
                "resolver_cooldown_max_seconds",
                1.0,
                3600.0,
            )
        if result["resolver_cooldown_max_seconds"] < result["resolver_cooldown_seconds"]:
            raise ValueError("Maximum resolver cooldown cannot be shorter than the base cooldown.")
        if "frpc_enabled" in payload:
            result["frpc_enabled"] = _bool(payload["frpc_enabled"], "frpc_enabled")
        if "frp_server_addr" in payload:
            result["frp_server_addr"] = _server_address(payload["frp_server_addr"])
        if "frp_server_port" in payload:
            result["frp_server_port"] = _int(
                payload["frp_server_port"], "frp_server_port", 1, 65535
            )
        if "frp_remote_port" in payload:
            result["frp_remote_port"] = _int(
                payload["frp_remote_port"], "frp_remote_port", 1, 65535
            )
        if "history_minutes" in payload:
            result["history_minutes"] = _int(
                payload["history_minutes"], "history_minutes", 15, 1440
            )
        if "filter_update_hours" in payload:
            result["filter_update_hours"] = _int(
                payload["filter_update_hours"], "filter_update_hours", 1, 168
            )
        if "frp_auth_token" in payload:
            token = str(payload.get("frp_auth_token", ""))
            if len(token) > 2048:
                raise ValueError("FRP authentication token is too long.")
            if token:
                result["frp_auth_token"] = token
        if _bool(payload.get("clear_frp_auth_token", False), "clear_frp_auth_token"):
            result["frp_auth_token"] = ""
        return result

    def update_settings(self, settings: Settings, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self.lock:
            document = self._read()
            current = document.get("settings", {})
            if not isinstance(current, Mapping):
                raise ValueError("Stored dashboard settings are invalid.")
            validated = self.validate_settings(payload, current)
            document["settings"] = validated
            document["updated_at"] = now_iso()
            self._write(document)
            self._apply_document(settings, document)
        return self.public_payload(settings)

    def public_payload(self, settings: Settings) -> dict[str, Any]:
        with self.lock:
            document = self._read()
            stored = dict(document.get("settings", {}))
            auth = document.get("auth", {})
        stored.pop("frp_auth_token", None)
        return {
            "format": CONFIG_FORMAT,
            "setup_required": not bool(auth.get("username") and auth.get("password_hash")),
            "username": str(auth.get("username", "")),
            "settings": stored,
            "secrets": {
                "frp_auth_token_configured": bool(settings.frp_auth_token),
                "certificate_configured": Path(settings.dot_cert_file).is_file()
                and Path(settings.dot_key_file).is_file(),
            },
            "storage": {
                "root": str(self.root),
                "fallback_used": self.fallback_used,
                "note": (
                    "Configuration is stored on the local filesystem. Mount this path as a persistent volume to preserve dashboard changes across container replacement or redeploys."
                ),
            },
            "updated_at": document.get("updated_at"),
        }

    def export_backup(self, settings: Settings, profiles_export: Mapping[str, Any]) -> dict[str, Any]:
        with self.lock:
            document = self._read()
            stored = dict(document.get("settings", {}))
        cert_path = Path(settings.dot_cert_file)
        key_path = Path(settings.dot_key_file)
        certificate = cert_path.read_text(encoding="utf-8") if cert_path.is_file() else ""
        private_key = key_path.read_text(encoding="utf-8") if key_path.is_file() else ""
        return {
            "format": "dns-dashboard-backup-v1",
            "exported_at": now_iso(),
            "settings": stored,
            "tls": {"certificate_pem": certificate, "private_key_pem": private_key},
            "profiles": dict(profiles_export),
            "warning": "This backup can contain an FRP token and TLS private key. Store it securely.",
        }
