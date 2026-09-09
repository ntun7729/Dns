from __future__ import annotations

import json
import subprocess
import threading
from pathlib import Path

from settings import Settings, now_iso
from certificates import redact_text, secure_write
from telemetry import RuntimeState


_FRPC_CHILD_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "TMPDIR": "/tmp",
    "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
    "SSL_CERT_DIR": "/etc/ssl/certs",
}


def frpc_child_environment() -> dict[str, str]:
    """Return the minimal non-secret environment inherited by FRPC."""
    return dict(_FRPC_CHILD_ENV)


def toml_string(value: str) -> str:
    return json.dumps(value)


def frpc_config(settings: Settings) -> str:
    lines = [
        f"serverAddr = {toml_string(settings.frp_server_addr)}",
        f"serverPort = {settings.frp_server_port}",
        "",
    ]
    if settings.frp_auth_token:
        lines.extend(
            [
                'auth.method = "token"',
                f"auth.token = {toml_string(settings.frp_auth_token)}",
                "",
            ]
        )
    lines.extend(
        [
            "[[proxies]]",
            'name = "dns-over-tls"',
            'type = "tcp"',
            f"localIP = {toml_string(settings.dot_bind_host)}",
            f"localPort = {settings.dot_port}",
            f"remotePort = {settings.frp_remote_port}",
            "",
        ]
    )
    return "\n".join(lines)


def write_frpc_config(settings: Settings) -> Path | None:
    if not settings.frpc_enabled or not settings.frpc_configured:
        return None
    path = Path(settings.frpc_config_file)
    secure_write(path, frpc_config(settings))
    return path


def _supervise_frpc(
    process: subprocess.Popen[bytes], settings: Settings, runtime: RuntimeState
) -> None:
    try:
        code = process.wait(timeout=settings.frpc_startup_grace_seconds)
    except subprocess.TimeoutExpired:
        runtime.update(frpc_state="running", frpc_running=True, frpc_last_error=None)
        code = process.wait()
        runtime.update(
            frpc_state="exited",
            frpc_running=False,
            frpc_exit_code=code,
            frpc_last_exit_at=now_iso(),
            frpc_last_error=f"FRPC exited unexpectedly with code {code}.",
        )
        return
    runtime.update(
        frpc_state="startup-failed",
        frpc_running=False,
        frpc_exit_code=code,
        frpc_last_exit_at=now_iso(),
        frpc_last_error=f"FRPC exited during startup with code {code}.",
    )


def start_frpc(
    settings: Settings, runtime: RuntimeState
) -> subprocess.Popen[bytes] | None:
    if not settings.frpc_enabled:
        runtime.update(frpc_state="disabled", frpc_running=False, frpc_last_error=None)
        return None
    if not settings.frpc_configured:
        runtime.update(
            frpc_state="needs-config",
            frpc_running=False,
            frpc_last_error="Configure the FRPS address in Dashboard > Settings.",
        )
        return None
    if settings.dot_enabled and runtime.snapshot()["dot_state"] != "running":
        runtime.update(
            frpc_state="blocked",
            frpc_running=False,
            frpc_last_error="FRPC was not started because the DoT listener is not ready.",
        )
        return None

    config = write_frpc_config(settings)
    assert config is not None
    child_env = frpc_child_environment()
    try:
        process = subprocess.Popen(
            [settings.frpc_binary, "-c", str(config)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            env=child_env,
        )
    except OSError as exc:
        runtime.update(
            frpc_state="startup-failed",
            frpc_running=False,
            frpc_last_error=redact_text(str(exc), settings),
        )
        return None

    runtime.update(
        frpc_state="starting",
        frpc_running=False,
        frpc_exit_code=None,
        frpc_started_at=now_iso(),
        frpc_last_exit_at=None,
        frpc_last_error=None,
    )
    threading.Thread(
        target=_supervise_frpc, args=(process, settings, runtime), daemon=True
    ).start()
    return process
