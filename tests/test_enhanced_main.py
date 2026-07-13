import importlib
import os
import socket
import sys
import time
import unittest
from pathlib import Path

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

    def test_strip_ansi_removes_terminal_codes(self):
        text = "\x1b[0m\x1b[1;34mproxy success"
        self.assertEqual(enhanced.strip_ansi(text), "proxy success")

    def test_status_payload_adds_safe_operational_fields(self):
        core.set_runtime(
            dot_state="running",
            frpc_state="running",
            frpc_started_at=core.now_iso(),
            frpc_last_log="\x1b[32mstart proxy success\x1b[0m",
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
            upstream_last_latency_ms=12.5,
            upstream_latency_total_ms=25.0,
            upstream_latency_samples=2,
            upstream_last_success_at=core.now_iso(),
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
        self.assertEqual(payload["frpc"]["last_log"], "start proxy success")
        self.assertEqual(payload["configuration"]["tls_secret_format"], "base64")
        self.assertEqual(payload["diagnostics"][0]["severity"], "ok")


if __name__ == "__main__":
    unittest.main()
