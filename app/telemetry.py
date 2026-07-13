from __future__ import annotations

import asyncio
import socket
import threading
import time
from collections import deque
from typing import Any, Sequence

from certificates import CertificateStatus
from settings import ERROR_TYPES, Settings, UpstreamEndpoint, now_iso


def classify_dns_error(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError, asyncio.TimeoutError)):
        return "upstream_timeout"
    if isinstance(exc, OSError):
        return "upstream_socket"
    if isinstance(exc, ValueError):
        return "malformed_message"
    return "internal_error"


class History:
    def __init__(self, minutes: int) -> None:
        self.minutes = minutes
        self._lock = threading.RLock()
        self._points: deque[dict[str, Any]] = deque(maxlen=minutes)

    @staticmethod
    def _minute_epoch(timestamp: float | None = None) -> int:
        return int((time.time() if timestamp is None else timestamp) // 60) * 60

    def reset(self) -> None:
        with self._lock:
            self._points.clear()

    def record(
        self,
        *,
        queries: int = 0,
        errors: int = 0,
        blocked: int = 0,
        failovers: int = 0,
        latency_ms: float | None = None,
        timestamp: float | None = None,
    ) -> None:
        epoch = self._minute_epoch(timestamp)
        with self._lock:
            if not self._points or self._points[-1]["epoch"] != epoch:
                self._points.append(
                    {
                        "epoch": epoch,
                        "queries": 0,
                        "errors": 0,
                        "blocked": 0,
                        "failovers": 0,
                        "latency_total_ms": 0.0,
                        "latency_samples": 0,
                    }
                )
            bucket = self._points[-1]
            bucket["queries"] += queries
            bucket["errors"] += errors
            bucket["blocked"] += blocked
            bucket["failovers"] += failovers
            if latency_ms is not None:
                bucket["latency_total_ms"] += latency_ms
                bucket["latency_samples"] += 1

    def snapshot(self, *, timestamp: float | None = None) -> list[dict[str, Any]]:
        now_epoch = self._minute_epoch(timestamp)
        first_epoch = now_epoch - (self.minutes - 1) * 60
        with self._lock:
            existing = {point["epoch"]: dict(point) for point in self._points}
        output: list[dict[str, Any]] = []
        for epoch in range(first_epoch, now_epoch + 1, 60):
            bucket = existing.get(
                epoch,
                {
                    "queries": 0,
                    "errors": 0,
                    "blocked": 0,
                    "failovers": 0,
                    "latency_total_ms": 0.0,
                    "latency_samples": 0,
                },
            )
            samples = int(bucket["latency_samples"])
            total = float(bucket["latency_total_ms"])
            output.append(
                {
                    "time": now_iso(epoch),
                    "queries": int(bucket["queries"]),
                    "errors": int(bucket["errors"]),
                    "blocked": int(bucket["blocked"]),
                    "failovers": int(bucket["failovers"]),
                    "latency_ms": round(total / samples, 2) if samples else None,
                }
            )
        return output


class RuntimeState:
    def __init__(self, history: History) -> None:
        self.history = history
        self.lock = threading.RLock()
        self.data: dict[str, Any] = {}
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.data = {
                "dot_state": "not-started",
                "dot_last_error": None,
                "dns_queries": 0,
                "dns_errors": 0,
                "dns_blocked": 0,
                "last_query_at": None,
                "dns_error_types": {name: 0 for name in ERROR_TYPES},
                "unexpected_disconnects": 0,
                "active_connections": 0,
                "peak_connections": 0,
                "upstream_cursor": 0,
                "upstream_failovers": 0,
                "upstream_last_used": None,
                "upstream_last_latency_ms": None,
                "upstream_latency_total_ms": 0.0,
                "upstream_latency_samples": 0,
                "upstream_last_success_at": None,
                "upstream_last_failure_at": None,
                "upstream_stats": {},
                "frpc_state": "not-started",
                "frpc_running": False,
                "frpc_exit_code": None,
                "frpc_started_at": None,
                "frpc_last_exit_at": None,
                "frpc_last_error": None,
                "certificate": CertificateStatus(
                    error="Certificate has not been loaded."
                ).as_public(),
            }
        self.history.reset()

    def update(self, **values: Any) -> None:
        with self.lock:
            self.data.update(values)

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            result = dict(self.data)
            result["certificate"] = dict(self.data["certificate"])
            result["dns_error_types"] = dict(self.data["dns_error_types"])
            result["upstream_stats"] = {
                key: dict(value)
                for key, value in self.data.get("upstream_stats", {}).items()
            }
            return result

    def ensure_upstreams(self, endpoints: Sequence[UpstreamEndpoint]) -> None:
        with self.lock:
            stats = self.data.setdefault("upstream_stats", {})
            for endpoint in endpoints:
                stats.setdefault(
                    endpoint.key,
                    {
                        "endpoint": endpoint.key,
                        "attempts": 0,
                        "successes": 0,
                        "failures": 0,
                        "timeouts": 0,
                        "last_latency_ms": None,
                        "latency_total_ms": 0.0,
                        "latency_samples": 0,
                        "last_success_at": None,
                        "last_failure_at": None,
                        "last_error_type": None,
                        "consecutive_failures": 0,
                        "cooldown_until": 0.0,
                    },
                )

    def connection_delta(self, delta: int) -> None:
        with self.lock:
            active = max(0, int(self.data.get("active_connections", 0)) + delta)
            self.data["active_connections"] = active
            self.data["peak_connections"] = max(
                int(self.data.get("peak_connections", 0)), active
            )

    def record_unexpected_disconnect(self) -> None:
        with self.lock:
            self.data["unexpected_disconnects"] += 1

    def record_query(self, *, blocked: bool = False) -> None:
        with self.lock:
            self.data["dns_queries"] += 1
            if blocked:
                self.data["dns_blocked"] += 1
            self.data["last_query_at"] = now_iso()
        self.history.record(queries=1, blocked=1 if blocked else 0)

    def record_dns_error(self, kind: str, message: str) -> None:
        if kind not in ERROR_TYPES:
            kind = "internal_error"
        with self.lock:
            self.data["dns_errors"] += 1
            self.data["dns_error_types"][kind] += 1
            self.data["dot_last_error"] = message
        self.history.record(errors=1)

    def ordered_upstreams(
        self,
        endpoints: tuple[UpstreamEndpoint, ...],
        strategy: str,
    ) -> tuple[UpstreamEndpoint, ...]:
        self.ensure_upstreams(endpoints)
        if strategy == "round_robin" and len(endpoints) > 1:
            with self.lock:
                cursor = int(self.data.get("upstream_cursor", 0)) % len(endpoints)
                self.data["upstream_cursor"] = cursor + 1
            ordered = endpoints[cursor:] + endpoints[:cursor]
        else:
            ordered = endpoints

        now_mono = time.monotonic()
        with self.lock:
            available = [
                endpoint
                for endpoint in ordered
                if float(
                    self.data["upstream_stats"][endpoint.key].get(
                        "cooldown_until", 0.0
                    )
                )
                <= now_mono
            ]
            if available:
                return tuple(available)
            return tuple(
                sorted(
                    ordered,
                    key=lambda endpoint: float(
                        self.data["upstream_stats"][endpoint.key].get(
                            "cooldown_until", 0.0
                        )
                    ),
                )
            )

    def record_upstream_success(
        self,
        endpoint: UpstreamEndpoint,
        latency_ms: float,
        *,
        failover: bool,
    ) -> None:
        self.ensure_upstreams((endpoint,))
        timestamp = now_iso()
        with self.lock:
            stats = self.data["upstream_stats"][endpoint.key]
            stats["attempts"] += 1
            stats["successes"] += 1
            stats["last_latency_ms"] = round(latency_ms, 2)
            stats["latency_total_ms"] += latency_ms
            stats["latency_samples"] += 1
            stats["last_success_at"] = timestamp
            stats["last_error_type"] = None
            stats["consecutive_failures"] = 0
            stats["cooldown_until"] = 0.0
            self.data["upstream_last_used"] = endpoint.key
            self.data["upstream_last_latency_ms"] = round(latency_ms, 2)
            self.data["upstream_latency_total_ms"] += latency_ms
            self.data["upstream_latency_samples"] += 1
            self.data["upstream_last_success_at"] = timestamp
            if failover:
                self.data["upstream_failovers"] += 1
        self.history.record(latency_ms=latency_ms, failovers=1 if failover else 0)

    def record_upstream_failure(
        self,
        endpoint: UpstreamEndpoint,
        exc: BaseException,
        settings: Settings,
    ) -> None:
        self.ensure_upstreams((endpoint,))
        kind = classify_dns_error(exc)
        timestamp = now_iso()
        with self.lock:
            stats = self.data["upstream_stats"][endpoint.key]
            stats["attempts"] += 1
            stats["failures"] += 1
            stats["last_failure_at"] = timestamp
            stats["last_error_type"] = kind
            if kind == "upstream_timeout":
                stats["timeouts"] += 1
            stats["consecutive_failures"] += 1
            exponent = max(0, min(6, stats["consecutive_failures"] - 1))
            cooldown = min(
                settings.resolver_cooldown_seconds * (2**exponent),
                settings.resolver_cooldown_max_seconds,
            )
            stats["cooldown_until"] = time.monotonic() + cooldown
            self.data["upstream_last_failure_at"] = timestamp

    def public_upstream_stats(
        self, endpoints: Sequence[UpstreamEndpoint]
    ) -> list[dict[str, Any]]:
        self.ensure_upstreams(endpoints)
        now_mono = time.monotonic()
        with self.lock:
            raw = self.data["upstream_stats"]
            output: list[dict[str, Any]] = []
            for endpoint in endpoints:
                stats = raw[endpoint.key]
                samples = int(stats["latency_samples"])
                total = float(stats["latency_total_ms"])
                last_success = stats["last_success_at"]
                last_failure = stats["last_failure_at"]
                cooldown_seconds = max(
                    0, int(float(stats.get("cooldown_until", 0.0)) - now_mono)
                )
                if cooldown_seconds:
                    state = "degraded"
                elif not stats["attempts"]:
                    state = "unknown"
                elif last_failure and (not last_success or last_failure > last_success):
                    state = "degraded"
                else:
                    state = "healthy"
                output.append(
                    {
                        "endpoint": endpoint.key,
                        "state": state,
                        "attempts": int(stats["attempts"]),
                        "successes": int(stats["successes"]),
                        "failures": int(stats["failures"]),
                        "timeouts": int(stats["timeouts"]),
                        "last_latency_ms": stats["last_latency_ms"],
                        "average_latency_ms": (
                            round(total / samples, 2) if samples else None
                        ),
                        "last_success_at": last_success,
                        "last_failure_at": last_failure,
                        "last_error_type": stats["last_error_type"],
                        "cooldown_seconds": cooldown_seconds,
                    }
                )
            return output
