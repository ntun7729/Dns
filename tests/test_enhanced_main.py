import importlib
import os
import socket
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_ROOT))

core = importlib.import_module("main")
enhanced = importlib.import_module("enhanced_main")


class EnhancedTelemetryTests(unittest.TestCase):
    def setUp(self):
        enhanced.reset_runtime()

    def test_reset_runtime_adds_telemetry_defaults(self):
        snapshot = core.RUNTIME
        self.assertEqual(snapshot["dns_error_types"]["upstream_timeout"], 0)
        self.assertEqual(snapshot["active_connections"], 0)
        self.assertEqual(snapshot["upstream_latency_samples"], 0)
        self.assertEqual(snapshot["upstream_failovers"], 0)
        self.assertIn("upstream_stats", snapshot)

    def test_error_classification(self):
        self.assertEqual(
            enhanced.classify_dns_error(socket.timeout("timeout")),
            "upstream_timeout",
        )
        self.assertEqual(
            enhanced.classify_dns_error(OSError("network")),
            "upstream_socket",
        )
        self.assertEqual(
            enhanced.classify_dns_error(ValueError("bad length")),
            "malformed_message",
        )
        self.assertEqual(
            enhanced.classify_dns_error(RuntimeError("unexpected")),
            "internal_error",
        )

    def test_parse_upstream_servers_supports_ports_ipv6_and_deduplication(self):
        endpoints = enhanced.parse_upstream_servers(
            "1.1.1.1:53, 9.9.9.9, [2606:4700:4700::1111]:53, 1.1.1.1:53",
            fallback_host="8.8.8.8",
            fallback_port=53,
        )
        self.assertEqual(
            [endpoint.key for endpoint in endpoints],
            ["1.1.1.1:53", "9.9.9.9:53", "[2606:4700:4700::1111]:53"],
        )

    def test_primary_failover_uses_second_resolver_after_failure(self):
        upstreams = (
            enhanced.UpstreamEndpoint("1.1.1.1", 53),
            enhanced.UpstreamEndpoint("9.9.9.9", 53),
        )
        calls = []

        def fake_send(endpoint, payload, timeout):
            calls.append(endpoint.key)
            if endpoint == upstreams[0]:
                raise socket.timeout("primary timeout")
            return b"\x12\x34" + b"\x00" * 10

        with patch.object(enhanced, "_send_udp_query", side_effect=fake_send):
            response = enhanced.query_upstreams_sync(
                b"\x12\x34" + b"\x00" * 10,
                upstreams=upstreams,
                strategy="primary_failover",
                timeout=0.1,
            )

        self.assertEqual(response[:2], b"\x12\x34")
        self.assertEqual(calls, ["1.1.1.1:53", "9.9.9.9:53"])
        self.assertEqual(core.RUNTIME["upstream_failovers"], 1)
        self.assertEqual(core.RUNTIME["upstream_last_used"], "9.9.9.9:53")

    def test_certificate_warning_levels(self):
        self.assertEqual(
            enhanced.certificate_warning({"valid": True, "days_remaining": 89})["level"],
            "green",
        )
        self.assertEqual(
            enhanced.certificate_warning({"valid": True, "days_remaining": 20})["level"],
            "yellow",
        )
        self.assertEqual(
            enhanced.certificate_warning({"valid": True, "days_remaining": 7})["level"],
            "red",
        )
        self.assertEqual(
            enhanced.certificate_warning({"valid": False, "error": "invalid"})["level"],
            "critical",
        )

    def test_status_payload_has_no_log_and_reports_upstream_pool(self):
        endpoint = enhanced.UPSTREAMS[0]
        upstream_stats = enhanced._blank_upstream_stats()
        upstream_stats[endpoint.key].update(
            {
                "attempts": 2,
                "successes": 2,
                "last_latency_ms": 12.5,
                "latency_total_ms": 25.0,
                "latency_samples": 2,
                "last_success_at": core.now_iso(),
            }
        )
        core.set_runtime(
            dot_state="running",
            frpc_state="running",
            frpc_started_at=core.now_iso(),
            frpc_last_log="must not be exposed",
            certificate={
                "source": "environment",
                "configured": True,
                "valid": True,
                "hostname_match": True,
                "key_match": True,
                "expired": False,
                "not_yet_valid": False,
                "not_before": core.now_iso(),
                "expires_at": core.now_iso(time.time() + 86400 * 89),
                "days_remaining": 89,
                "error": None,
            },
            upstream_last_used=endpoint.key,
            upstream_last_latency_ms=12.5,
            upstream_latency_total_ms=25.0,
            upstream_latency_samples=2,
            upstream_last_success_at=core.now_iso(),
            upstream_stats=upstream_stats,
        )
        settings = core.Settings(
            app_env="production",
            dot_public_hostname="dns.nyan.college",
            frpc_enabled=True,
            frp_server_addr="203.0.113.10",
        )
        old_cert = os.environ.get("DOT_CERT_B64")
        old_key = os.environ.get("DOT_KEY_B64")
        os.environ["DOT_CERT_B64"] = "test"
        os.environ["DOT_KEY_B64"] = "test"
        try:
            payload = enhanced.status_payload(settings)
        finally:
            if old_cert is None:
                os.environ.pop("DOT_CERT_B64", None)
            else:
                os.environ["DOT_CERT_B64"] = old_cert
            if old_key is None:
                os.environ.pop("DOT_KEY_B64", None)
            else:
                os.environ["DOT_KEY_B64"] = old_key

        self.assertEqual(payload["certificate"]["warning"]["level"], "green")
        self.assertEqual(payload["metrics"]["upstream_average_latency_ms"], 12.5)
        self.assertNotIn("last_log", payload["frpc"])
        self.assertEqual(payload["configuration"]["runtime_logging"], "disabled")
        self.assertGreaterEqual(len(payload["metrics"]["upstreams"]), 1)
        self.assertEqual(payload["diagnostics"][0]["severity"], "ok")


if __name__ == "__main__":
    unittest.main()
