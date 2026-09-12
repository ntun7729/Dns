from __future__ import annotations

import json
import subprocess
import threading
import time
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

# Keep FRP's control/multiplexed connections active through NATs, cloud egress
# gateways, and intermediate TCP proxies. These are application defaults on
# purpose: the dashboard remains the operational control plane and deployments
# do not need environment variables just to stay connected.
FRPC_HEARTBEAT_INTERVAL_SECONDS = 10
FRPC_HEARTBEAT_TIMEOUT_SECONDS = 90
FRPC_TCP_MUX_KEEPALIVE_SECONDS = 15
FRPC_DIAL_KEEPALIVE_SECONDS = 30
FRPC_DIAL_TIMEOUT_SECONDS = 10
FRPC_RECONNECT_INITIAL_SECONDS = 1.0
FRPC_RECONNECT_MAX_SECONDS = 30.0
FRPC_STABLE_SESSION_SECONDS = 60.0
FRPC_STOP_TIMEOUT_SECONDS = 5.0


def frpc_child_environment() -> dict[str, str]:
    """Return the minimal non-secret environment inherited by FRPC."""
    return dict(_FRPC_CHILD_ENV)


def toml_string(value: str) -> str:
    return json.dumps(value)


def frpc_config(settings: Settings) -> str:
    lines = [
        f"serverAddr = {toml_string(settings.frp_server_addr)}",
        f"serverPort = {settings.frp_server_port}",
        # FRPC normally exits when its first login fails. Cloud networking can
        # be briefly unavailable during container startup, so keep retrying.
        "loginFailExit = false",
        'log.to = "console"',
        'log.level = "info"',
        "log.disablePrintColor = true",
        "transport.tcpMux = true",
        f"transport.tcpMuxKeepaliveInterval = {FRPC_TCP_MUX_KEEPALIVE_SECONDS}",
        f"transport.dialServerTimeout = {FRPC_DIAL_TIMEOUT_SECONDS}",
        f"transport.dialServerKeepalive = {FRPC_DIAL_KEEPALIVE_SECONDS}",
        f"transport.heartbeatInterval = {FRPC_HEARTBEAT_INTERVAL_SECONDS}",
        f"transport.heartbeatTimeout = {FRPC_HEARTBEAT_TIMEOUT_SECONDS}",
        "transport.tls.enable = true",
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


def _restart_delay(failure_streak: int) -> float:
    exponent = max(0, min(10, failure_streak - 1))
    return min(
        FRPC_RECONNECT_MAX_SECONDS,
        FRPC_RECONNECT_INITIAL_SECONDS * (2**exponent),
    )


class FrpcSupervisor:
    """Keep FRPC alive and surface its real tunnel state to the dashboard.

    FRPC has its own reconnect loop, but the process can still exit because of a
    crash, fatal startup error, or platform-level reset. This supervisor covers
    that outer failure mode with bounded exponential backoff. It also parses the
    stable FRPC info log messages so a live process is not mistaken for a live
    tunnel while it is reconnecting.
    """

    def __init__(
        self,
        settings: Settings,
        runtime: RuntimeState,
        config: Path,
    ) -> None:
        self.settings = settings
        self.runtime = runtime
        self.config = config
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self.process: subprocess.Popen[str] | None = None
        self.thread = threading.Thread(
            target=self._run,
            name="frpc-supervisor",
            daemon=True,
        )
        self.log_thread: threading.Thread | None = None
        self._ever_running = False
        self._reconnect_active = False
        self._reconnect_count = 0

    def start(self) -> "FrpcSupervisor":
        self.thread.start()
        return self

    def poll(self) -> int | None:
        with self.lock:
            process = self.process
        return process.poll() if process is not None else None

    def stop(self, timeout: float = FRPC_STOP_TIMEOUT_SECONDS) -> None:
        self.stop_event.set()
        with self.lock:
            process = self.process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=max(0.1, timeout))
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
            except OSError:
                pass
        if self.thread.is_alive() and threading.current_thread() is not self.thread:
            self.thread.join(timeout=max(0.1, timeout) + 1.0)

    def _increment_reconnect(self) -> None:
        with self.lock:
            self._reconnect_count += 1
            count = self._reconnect_count
        self.runtime.update(frpc_reconnect_count=count)

    def _mark_reconnecting(self, error: str | None = None) -> None:
        with self.lock:
            if self._ever_running and not self._reconnect_active:
                self._reconnect_active = True
                increment = True
            else:
                increment = False
        if increment:
            self._increment_reconnect()
        self.runtime.update(
            frpc_state="reconnecting",
            frpc_running=False,
            frpc_last_error=error,
        )

    def _drain_logs(self, process: subprocess.Popen[str]) -> None:
        stream = process.stdout
        if stream is None:
            return
        try:
            for line in stream:
                raw = line.rstrip("\r\n")
                if not raw:
                    continue
                safe = redact_text(raw, self.settings)
                print(f"[frpc] {safe}", flush=True)
                lower = raw.lower()

                if "try to connect to server" in lower:
                    self._mark_reconnecting()
                elif "login to server success" in lower:
                    self.runtime.update(
                        frpc_state="connected",
                        frpc_running=False,
                        frpc_last_error=None,
                    )
                elif "start proxy success" in lower and "dns-over-tls" in lower:
                    with self.lock:
                        self._ever_running = True
                        self._reconnect_active = False
                    self.runtime.update(
                        frpc_state="running",
                        frpc_running=True,
                        frpc_last_error=None,
                        frpc_connected_at=now_iso(),
                        frpc_next_retry_seconds=0.0,
                    )
                elif "start error:" in lower or "login to server failed" in lower:
                    self.runtime.update(
                        frpc_last_error=safe,
                        frpc_running=False,
                    )
        except (OSError, ValueError):
            return

    def _wait_for_dot(self) -> bool:
        while not self.stop_event.is_set():
            if not self.settings.dot_enabled:
                return True
            dot_state = self.runtime.snapshot().get("dot_state")
            if dot_state == "running":
                return True
            self.runtime.update(
                frpc_state="blocked",
                frpc_running=False,
                frpc_last_error="FRPC is waiting for the local DoT listener to become ready.",
            )
            self.stop_event.wait(0.5)
        return False

    def _spawn(self) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [self.settings.frpc_binary, "-c", str(self.config)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
            env=frpc_child_environment(),
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

    def _run(self) -> None:
        failure_streak = 0
        launches = 0

        while not self.stop_event.is_set():
            if not self._wait_for_dot():
                break

            state = "starting" if launches == 0 else "reconnecting"
            self.runtime.update(
                frpc_state=state,
                frpc_running=False,
                frpc_exit_code=None,
                frpc_started_at=now_iso(),
                frpc_next_retry_seconds=0.0,
                frpc_last_error=None,
            )

            try:
                process = self._spawn()
            except OSError as exc:
                failure_streak += 1
                delay = _restart_delay(failure_streak)
                self.runtime.update(
                    frpc_state="reconnecting",
                    frpc_running=False,
                    frpc_last_error=redact_text(str(exc), self.settings),
                    frpc_next_retry_seconds=delay,
                )
                if self.stop_event.wait(delay):
                    break
                continue

            launches += 1
            if launches > 1:
                self._increment_reconnect()
            started = time.monotonic()
            with self.lock:
                self.process = process

            if self.stop_event.is_set():
                try:
                    process.terminate()
                except OSError:
                    pass

            self.log_thread = threading.Thread(
                target=self._drain_logs,
                args=(process,),
                name="frpc-log-reader",
                daemon=True,
            )
            self.log_thread.start()

            code = process.wait()
            uptime = time.monotonic() - started
            with self.lock:
                if self.process is process:
                    self.process = None

            if self.stop_event.is_set():
                break

            if uptime >= FRPC_STABLE_SESSION_SECONDS:
                failure_streak = 0
            failure_streak += 1
            delay = _restart_delay(failure_streak)
            exit_message = (
                f"FRPC exited with code {code}; reconnecting in {delay:.1f} seconds."
            )
            self.runtime.update(
                frpc_state="reconnecting",
                frpc_running=False,
                frpc_exit_code=code,
                frpc_last_exit_at=now_iso(),
                frpc_last_error=exit_message,
                frpc_next_retry_seconds=delay,
            )
            if self.stop_event.wait(delay):
                break

        self.runtime.update(
            frpc_running=False,
            frpc_next_retry_seconds=0.0,
            frpc_state=(
                "disabled" if not self.settings.frpc_enabled else "stopped"
            ),
        )


def start_frpc(
    settings: Settings, runtime: RuntimeState
) -> FrpcSupervisor | None:
    if not settings.frpc_enabled:
        runtime.update(
            frpc_state="disabled",
            frpc_running=False,
            frpc_last_error=None,
            frpc_reconnect_count=0,
            frpc_next_retry_seconds=0.0,
        )
        return None
    if not settings.frpc_configured:
        runtime.update(
            frpc_state="needs-config",
            frpc_running=False,
            frpc_last_error="Configure the FRPS address in Dashboard > Settings.",
            frpc_reconnect_count=0,
            frpc_next_retry_seconds=0.0,
        )
        return None

    config = write_frpc_config(settings)
    assert config is not None
    runtime.update(
        frpc_state="starting",
        frpc_running=False,
        frpc_exit_code=None,
        frpc_started_at=now_iso(),
        frpc_last_exit_at=None,
        frpc_last_error=None,
        frpc_reconnect_count=0,
        frpc_next_retry_seconds=0.0,
        frpc_connected_at=None,
    )
    return FrpcSupervisor(settings, runtime, config).start()
