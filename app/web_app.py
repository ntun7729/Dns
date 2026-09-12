from __future__ import annotations

import base64
import hmac
import json
import socket
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping

from filtering import BlocklistManager
from settings import MAX_CONTROL_BODY_BYTES, STATIC_ROOT, Settings, now_iso
from telemetry import RuntimeState
from profiles import ProfileStore
from status_api import readiness_payload, status_payload
from tls_manager import install_tls_material


class DashboardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


def build_handler(
    settings: Settings,
    runtime: RuntimeState,
    profiles: ProfileStore,
    blocklists: BlocklistManager,
    *,
    config_store: Any | None = None,
    restart_callback: Callable[[], None] | None = None,
) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "DnsDashboard/4.2"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        static_routes = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/ui_fixes.js": ("ui_fixes.js", "text/javascript; charset=utf-8"),
            "/settings.js": ("settings.js", "text/javascript; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
            "/settings.css": ("settings.css", "text/css; charset=utf-8"),
        }

        def setup(self) -> None:
            super().setup()
            # Bound idle/slow clients so abandoned cloud/mobile connections do
            # not consume a dashboard worker indefinitely. Polling happens every
            # 15 seconds, so a 60-second keep-alive window is ample.
            self.connection.settimeout(60.0)

        def log_message(self, _format: str, *_args: Any) -> None:
            return None

        def _security_headers(self) -> None:
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header("Keep-Alive", "timeout=30, max=100")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'self'",
            )

        def _auth_enabled(self) -> bool:
            return config_store.auth_enabled() if config_store is not None else settings.auth_enabled

        def _authorized(self) -> bool:
            if not self._auth_enabled():
                return True
            header = self.headers.get("Authorization", "")
            if not header.startswith("Basic "):
                return False
            try:
                decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
                username, password = decoded.split(":", 1)
            except (ValueError, UnicodeDecodeError):
                return False
            if config_store is not None:
                return bool(config_store.verify(username, password))
            return hmac.compare_digest(
                username, settings.dashboard_username
            ) and hmac.compare_digest(password, settings.dashboard_password)

        def _safe_write(self, body: bytes) -> bool:
            try:
                self.wfile.write(body)
                self.wfile.flush()
                return True
            except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
                # Browser tabs and cloud proxies can disappear between header and
                # body writes. This is a client disconnect, not a server failure.
                self.close_connection = True
                return False

        def _send_unauthorized(self) -> None:
            body = b"Authentication required."
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("WWW-Authenticate", 'Basic realm="DNS Dashboard"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self._security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self._safe_write(body)

        def _same_origin(self) -> bool:
            origin = self.headers.get("Origin")
            if not origin:
                return True
            parsed = urllib.parse.urlsplit(origin)
            return parsed.scheme in {"http", "https"} and parsed.netloc == self.headers.get(
                "Host", ""
            )

        def _json(
            self, payload: Mapping[str, Any], status: HTTPStatus = HTTPStatus.OK
        ) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self._safe_write(body)

        def _serve_static(self, name: str, content_type: str) -> None:
            path = STATIC_ROOT / name
            try:
                body = path.read_bytes()
            except FileNotFoundError:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self._security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self._safe_write(body)

        def _read_json_body(self) -> dict[str, Any] | None:
            if not self._same_origin():
                self._json(
                    {"ok": False, "error": "Cross-origin control requests are rejected."},
                    HTTPStatus.FORBIDDEN,
                )
                return None
            if not self.headers.get("Content-Type", "").lower().startswith(
                "application/json"
            ):
                self._json(
                    {"ok": False, "error": "Content-Type must be application/json."},
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                )
                return None
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length <= 0 or length > MAX_CONTROL_BODY_BYTES:
                self._json(
                    {"ok": False, "error": "Control request size is invalid."},
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )
                return None
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._json(
                    {"ok": False, "error": f"Invalid JSON body: {exc}"},
                    HTTPStatus.BAD_REQUEST,
                )
                return None
            except (TimeoutError, OSError):
                self.close_connection = True
                return None
            if not isinstance(data, dict):
                self._json(
                    {"ok": False, "error": "JSON body must be an object."},
                    HTTPStatus.BAD_REQUEST,
                )
                return None
            return data

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                self._json({"ok": True, "time": now_iso()})
                return
            if path == "/readyz":
                payload = readiness_payload(settings, runtime)
                self._json(
                    payload,
                    HTTPStatus.OK if payload["ready"] else HTTPStatus.SERVICE_UNAVAILABLE,
                )
                return
            if not self._authorized():
                self._send_unauthorized()
                return
            if path in self.static_routes:
                self._serve_static(*self.static_routes[path])
            elif path == "/api/status":
                self._json(status_payload(settings, runtime, profiles, blocklists))
            elif path == "/api/control":
                if not self._auth_enabled():
                    self._json(
                        {
                            "ok": False,
                            "error": "Create the dashboard administrator in Settings to enable controls.",
                        },
                        HTTPStatus.FORBIDDEN,
                    )
                else:
                    self._json({"ok": True, "control": profiles.control_payload()})
            elif path == "/api/control/export":
                if not self._auth_enabled():
                    self._json(
                        {"ok": False, "error": "Dashboard controls are disabled."},
                        HTTPStatus.FORBIDDEN,
                    )
                else:
                    self._json(profiles.export())
            elif path == "/api/settings":
                if config_store is None:
                    self._json(
                        {"ok": False, "error": "Dashboard settings storage is unavailable."},
                        HTTPStatus.NOT_IMPLEMENTED,
                    )
                else:
                    self._json({"ok": True, "config": config_store.public_payload(settings)})
            elif path == "/api/settings/export":
                if config_store is None:
                    self._json(
                        {"ok": False, "error": "Dashboard settings storage is unavailable."},
                        HTTPStatus.NOT_IMPLEMENTED,
                    )
                elif not self._auth_enabled():
                    self._json(
                        {"ok": False, "error": "Configure an administrator first."},
                        HTTPStatus.FORBIDDEN,
                    )
                else:
                    self._json(config_store.export_backup(settings, profiles.export()))
            else:
                self.send_error(HTTPStatus.NOT_FOUND)

        def _post_setup(self) -> None:
            if config_store is None:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            if self._auth_enabled():
                self._json(
                    {"ok": False, "error": "Dashboard administrator is already configured."},
                    HTTPStatus.CONFLICT,
                )
                return
            data = self._read_json_body()
            if data is None:
                return
            try:
                config_store.set_credentials(
                    settings,
                    str(data.get("username", "")),
                    str(data.get("password", "")),
                    require_unconfigured=True,
                )
            except (OSError, ValueError, RuntimeError) as exc:
                self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            self._json(
                {
                    "ok": True,
                    "message": "Administrator created. Reload the page and sign in.",
                    "reload_required": True,
                }
            )

        def _post_control(self) -> None:
            data = self._read_json_body()
            if data is None:
                return
            try:
                action = str(data.get("action", "save_profile"))
                if action == "save_profile":
                    control = profiles.save(data)
                elif action == "activate_profile":
                    control = profiles.activate(str(data.get("id", "")))
                elif action == "duplicate_profile":
                    control = profiles.duplicate(str(data.get("id", "")))
                elif action == "delete_profile":
                    control = profiles.delete(str(data.get("id", "")))
                elif action == "import_profiles":
                    exported = data.get("export")
                    if not isinstance(exported, dict):
                        raise ValueError("Import data must be an export object.")
                    control = profiles.import_export(exported)
                elif action == "refresh_blocklist":
                    blocklists.refresh_profile(profiles.active(), force=True)
                    control = profiles.control_payload()
                else:
                    raise ValueError("Unsupported control action.")
                profile = profiles.active()
                runtime.ensure_upstreams(profile.upstreams)
                blocklists.refresh_profile(profile)
            except (OSError, RuntimeError, ValueError) as exc:
                self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            self._json(
                {
                    "ok": True,
                    "control": control,
                    "status": status_payload(settings, runtime, profiles, blocklists),
                }
            )

        def _post_settings(self) -> None:
            if config_store is None:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            data = self._read_json_body()
            if data is None:
                return
            action = str(data.get("action", "save_settings"))
            try:
                if action == "save_settings":
                    certificate_pem = str(data.get("certificate_pem", ""))
                    private_key_pem = str(data.get("private_key_pem", ""))
                    if bool(certificate_pem.strip()) != bool(private_key_pem.strip()):
                        raise ValueError(
                            "Certificate and private key must both be supplied when updating TLS."
                        )
                    config_store.update_settings(settings, data)
                    if certificate_pem.strip() and private_key_pem.strip():
                        certificate = install_tls_material(
                            settings, certificate_pem, private_key_pem
                        )
                        runtime.update(certificate=certificate.as_public())

                    requested_username = str(data.get("admin_username", "")).strip()
                    new_password = str(data.get("new_password", ""))
                    if new_password:
                        config_store.set_credentials(
                            settings,
                            requested_username or settings.dashboard_username,
                            new_password,
                        )
                    elif requested_username and requested_username != settings.dashboard_username:
                        raise ValueError("Enter a new password when changing the administrator username.")

                elif action == "import_backup":
                    backup = data.get("backup")
                    if not isinstance(backup, dict) or backup.get("format") != "dns-dashboard-backup-v1":
                        raise ValueError("Unsupported DNS Dashboard backup format.")
                    imported_settings = backup.get("settings")
                    if not isinstance(imported_settings, dict):
                        raise ValueError("Backup settings are missing.")
                    imported_payload = dict(imported_settings)
                    if not imported_payload.get("frp_auth_token"):
                        imported_payload["clear_frp_auth_token"] = True
                    config_store.update_settings(settings, imported_payload)

                    tls = backup.get("tls", {})
                    if isinstance(tls, dict):
                        certificate_pem = str(tls.get("certificate_pem", ""))
                        private_key_pem = str(tls.get("private_key_pem", ""))
                        if certificate_pem.strip() or private_key_pem.strip():
                            certificate = install_tls_material(
                                settings, certificate_pem, private_key_pem
                            )
                            runtime.update(certificate=certificate.as_public())

                    exported_profiles = backup.get("profiles")
                    if isinstance(exported_profiles, dict):
                        profiles.import_export(exported_profiles)
                else:
                    raise ValueError("Unsupported settings action.")
            except (OSError, RuntimeError, ValueError) as exc:
                self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return

            self._json(
                {
                    "ok": True,
                    "message": "Settings saved. The service is restarting to apply them.",
                    "restart_scheduled": restart_callback is not None,
                    "config": config_store.public_payload(settings),
                }
            )
            if restart_callback is not None:
                restart_callback()

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/api/setup":
                self._post_setup()
                return
            if path not in {"/api/control", "/api/settings"}:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            if not self._auth_enabled() or not self._authorized():
                self._send_unauthorized()
                return
            if path == "/api/control":
                self._post_control()
            else:
                self._post_settings()

    return DashboardHandler


def run_http(
    settings: Settings,
    runtime: RuntimeState,
    profiles: ProfileStore,
    blocklists: BlocklistManager,
    *,
    config_store: Any | None = None,
    restart_callback: Callable[[], None] | None = None,
) -> None:
    handler = build_handler(
        settings,
        runtime,
        profiles,
        blocklists,
        config_store=config_store,
        restart_callback=restart_callback,
    )
    server = DashboardHTTPServer((settings.bind_host, settings.port), handler)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
