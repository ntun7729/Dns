#!/usr/bin/env python3
"""Serve the dashboard UI fix bundle and start the production runtime."""

from __future__ import annotations

import dashboard_v2  # noqa: F401 - imports and applies dashboard patches.
import main as core
import managed_main as managed


_original_do_get = core.DashboardHandler.do_GET


def do_get_with_ui_fixes(handler: core.DashboardHandler) -> None:
    path = handler.path.split("?", 1)[0]
    if path == "/ui_fixes.js":
        handler._serve_static("ui_fixes.js", "text/javascript; charset=utf-8")
        return
    _original_do_get(handler)


core.DashboardHandler.do_GET = do_get_with_ui_fixes


if __name__ == "__main__":
    managed.start_managed_services()
    core.main()
