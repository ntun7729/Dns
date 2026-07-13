from __future__ import annotations

import base64
import hmac
import json
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping

from filtering import BlocklistManager
from settings import MAX_CONTROL_BODY_BYTES, STATIC_ROOT, Settings, now_iso
from telemetry import RuntimeState
from profiles import ProfileStore
from status_api import readiness_payload, status_payload


class DashboardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def build_handler(
    settings: Settings,
    runtime: RuntimeState,
    profiles: ProfileStore,
    blocklists: BlocklistManager,
) -> type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "DnsDashboard/3.0"
        sys_version = ""
        static_routes = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/ui_fixes.js": ("ui_fixes.js", "text/javascript; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
        }

        def log_message(self, _format: str, *_args: Any) -> None:
            return None

        def _security_headers(self) -> None:
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'self'",
            )

        def _authorized(self) -> bool:
            if not settings.auth_enabled:
                return True
            header = self.headers.get("Authorization", "")
            if not header.startswith("Basic "):
                return False
            try:
                decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
                username, password = decoded.split(":", 1)
            except (ValueError, UnicodeDecodeError):
                return False
            return hmac.compare_digest(
                username, settings.dashboard_username
            ) and hmac.compare_digest(password, settings.dashboard_password)

        def _send_unauthorized(self) -> None:
            body = b"Authentication required."
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("WWW-Authenticate", 'Basic realm="DNS Dashboard"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self._security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

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
            self.wfile.write(body)

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
            self.wfile.write(body)

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
                if not settings.auth_enabled:
                    self._json(
                        {
                            "ok": False,
                            "error": "Configure dashboard credentials to enable controls.",
                        },
                        HTTPStatus.FORBIDDEN,
                    )
                else:
                    self._json({"ok": True, "control": profiles.control_payload()})
            elif path == "/api/control/export":
                if not settings.auth_enabled:
                    self._json(
                        {"ok": False, "error": "Dashboard controls are disabled."},
                        HTTPStatus.FORBIDDEN,
                    )
                else:
                    self._json(profiles.export())
            else:
                self.send_error(HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path != "/api/control":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            if not settings.auth_enabled or not self._authorized():
                self._send_unauthorized()
                return
            if not self._same_origin():
                self._json(
                    {"ok": False, "error": "Cross-origin control requests are rejected."},
                    HTTPStatus.FORBIDDEN,
                )
                return
            if not self.headers.get("Content-Type", "").lower().startswith(
                "application/json"
            ):
                self._json(
                    {"ok": False, "error": "Content-Type must be application/json."},
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                )
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length <= 0 or length > MAX_CONTROL_BODY_BYTES:
                self._json(
                    {"ok": False, "error": "Control request size is invalid."},
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )
                return
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("JSON body must be an object.")
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
            except (ValueError, json.JSONDecodeError) as exc:
                self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            self._json(
                {
                    "ok": True,
                    "control": control,
                    "status": status_payload(settings, runtime, profiles, blocklists),
                }
            )

    return DashboardHandler


def run_http(
    settings: Settings,
    runtime: RuntimeState,
    profiles: ProfileStore,
    blocklists: BlocklistManager,
) -> None:
    handler = build_handler(settings, runtime, profiles, blocklists)
    server = DashboardHTTPServer((settings.bind_host, settings.port), handler)
    server.serve_forever()
