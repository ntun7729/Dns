#!/usr/bin/env python3
"""Explicit production entrypoint for the DNS-over-TLS service."""

from __future__ import annotations

import signal
import subprocess
import threading
from typing import Any

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
from runtime_config import (
    Settings,
    UpstreamEndpoint,
    parse_upstream_servers,
    validate_certificate_files,
)
from runtime_state import (
    History,
    ProfileStore,
    RuntimeState,
    parse_blocklist_text,
    validate_raw_github_url,
)
from web_app import build_handler, run_http

SETTINGS = Settings.from_env()
HISTORY = History(SETTINGS.history_minutes)
RUNTIME = RuntimeState(HISTORY)
PROFILES = ProfileStore(SETTINGS)
BLOCKLISTS = BlocklistManager(SETTINGS, PROFILES, RUNTIME)
RUNTIME.ensure_upstreams(SETTINGS.upstreams)
DashboardHandler = build_handler(SETTINGS, RUNTIME, PROFILES, BLOCKLISTS)


def start_frpc(settings: Settings):
    return frpc_service.start_frpc(settings, RUNTIME)


def main() -> None:
    RUNTIME.reset()
    RUNTIME.ensure_upstreams(PROFILES.active().upstreams)
    BLOCKLISTS.start()
    dot_startup = start_dot_thread(SETTINGS, RUNTIME, PROFILES, BLOCKLISTS)
    dot_startup.wait(timeout=15)
    frpc = frpc_service.start_frpc(SETTINGS, RUNTIME)

    def shutdown(_signum: int, _frame: Any) -> None:
        BLOCKLISTS.stop_event.set()
        if frpc and frpc.poll() is None:
            frpc.terminate()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    run_http(SETTINGS, RUNTIME, PROFILES, BLOCKLISTS)


if __name__ == "__main__":
    main()
