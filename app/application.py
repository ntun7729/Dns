#!/usr/bin/env python3
"""Explicit production entrypoint for the DNS-over-TLS service."""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from certificates import normalize_pem, secure_write, validate_certificate_files
from dns_service import (
    build_formerr_response,
    build_nxdomain_response,
    build_servfail_response,
    parse_dns_question,
    send_udp_query,
    start_dot_thread,
)
from filtering import BlocklistManager
import frpc_service
from profiles import ProfileStore, parse_blocklist_text, validate_raw_github_url
from runtime_config import RuntimeConfigStore
from settings import Settings, UpstreamEndpoint, parse_upstream_servers
from telemetry import History, RuntimeState
from web_app import build_handler, run_http


def dashboard_data_root() -> Path | None:
    """Resolve persistent storage without coupling the image to one hosting provider.

    DNS_DASHBOARD_DATA_DIR is an optional infrastructure-only override for hosts
    whose persistent volume cannot be mounted at /data. Railway supplies its
    volume mount path automatically, so no user-defined variable is needed there.
    The RuntimeConfigStore default remains /data/dns-dashboard for plain Docker
    and other container platforms.
    """
    explicit = os.getenv("DNS_DASHBOARD_DATA_DIR", "").strip()
    if explicit:
        return Path(explicit)
    railway_volume = os.getenv("RAILWAY_VOLUME_MOUNT_PATH", "").strip()
    if railway_volume:
        return Path(railway_volume) / "dns-dashboard"
    return None


SETTINGS = Settings.from_env()
_LEGACY_CERT_PEM = SETTINGS.dot_cert_pem
_LEGACY_KEY_PEM = SETTINGS.dot_key_pem
CONFIG = RuntimeConfigStore(root=dashboard_data_root())
CONFIG.load_into(SETTINGS)

# One-time compatibility migration for deployments that previously supplied TLS
# material through environment variables. Future operational edits are made in
# the web dashboard and stored in the provider-neutral dashboard data directory.
if _LEGACY_CERT_PEM and _LEGACY_KEY_PEM:
    cert_path = Path(SETTINGS.dot_cert_file)
    key_path = Path(SETTINGS.dot_key_file)
    if not cert_path.is_file() or not key_path.is_file():
        secure_write(cert_path, normalize_pem(_LEGACY_CERT_PEM))
        secure_write(key_path, normalize_pem(_LEGACY_KEY_PEM))

HISTORY = History(SETTINGS.history_minutes)
RUNTIME = RuntimeState(HISTORY)
PROFILES = ProfileStore(SETTINGS)
BLOCKLISTS = BlocklistManager(SETTINGS, PROFILES, RUNTIME)
RUNTIME.ensure_upstreams(SETTINGS.upstreams)
FRPC_SUPERVISOR: frpc_service.FrpcSupervisor | None = None
FRPC_LOCK = threading.RLock()


def _stop_frpc() -> None:
    global FRPC_SUPERVISOR
    with FRPC_LOCK:
        supervisor = FRPC_SUPERVISOR
        FRPC_SUPERVISOR = None
    if supervisor is not None:
        supervisor.stop()


def schedule_restart() -> None:
    """Cleanly replace this process after the HTTP response has been flushed.

    FRPC is a child process. It must be stopped before exec() or the old tunnel
    survives the Python replacement and a second FRPC instance races it for the
    same remote port.
    """

    def restart() -> None:
        time.sleep(0.8)
        _stop_frpc()
        os.execv(sys.executable, [sys.executable, str(Path(__file__).resolve())])

    threading.Thread(target=restart, name="dashboard-restart", daemon=True).start()


DashboardHandler = build_handler(
    SETTINGS,
    RUNTIME,
    PROFILES,
    BLOCKLISTS,
    config_store=CONFIG,
    restart_callback=schedule_restart,
)


def start_frpc(settings: Settings):
    """Compatibility wrapper used by tests and local tooling."""
    return frpc_service.start_frpc(settings, RUNTIME)


def main() -> None:
    global FRPC_SUPERVISOR

    RUNTIME.reset()
    RUNTIME.ensure_upstreams(PROFILES.active().upstreams)
    BLOCKLISTS.start()
    dot_startup = start_dot_thread(SETTINGS, RUNTIME, PROFILES, BLOCKLISTS)
    dot_startup.wait(timeout=15)

    with FRPC_LOCK:
        FRPC_SUPERVISOR = frpc_service.start_frpc(SETTINGS, RUNTIME)

    shutting_down = threading.Event()

    def shutdown(_signum: int, _frame: Any) -> None:
        if shutting_down.is_set():
            raise SystemExit(0)
        shutting_down.set()
        BLOCKLISTS.stop_event.set()
        _stop_frpc()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        run_http(
            SETTINGS,
            RUNTIME,
            PROFILES,
            BLOCKLISTS,
            config_store=CONFIG,
            restart_callback=schedule_restart,
        )
    finally:
        BLOCKLISTS.stop_event.set()
        _stop_frpc()


if __name__ == "__main__":
    main()
