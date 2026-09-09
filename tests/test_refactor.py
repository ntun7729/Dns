from __future__ import annotations

import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

APP = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP))
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("DOT_ENABLED", "false")
os.environ.setdefault("FRPC_ENABLED", "false")

from certificates import validate_certificate_files
from dns_service import (
    build_formerr_response,
    build_nxdomain_response,
    build_servfail_response,
    cache_dns_response,
    get_cached_dns_response,
    parse_dns_question,
)
from filtering import BlocklistManager
from frpc_service import frpc_child_environment
from profiles import ProfileStore, parse_blocklist_text, validate_raw_github_url
from runtime_config import RuntimeConfigStore
from settings import Settings, UpstreamEndpoint, parse_upstream_servers
from status_api import readiness_payload, status_payload
from telemetry import History, RuntimeState
from web_app import build_handler


def dns_query(name: str = "example.com", transaction_id: bytes = b"\x12\x34") -> bytes:
    labels = b"" if name == "." else b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    )
    return (
        transaction_id
        + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + labels
        + b"\x00\x00\x01\x00\x01"
    )


class RefactorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = Settings(
            dot_enabled=False,
            frpc_enabled=False,
            upstreams=(UpstreamEndpoint("1.1.1.1", 53),),
        )
        self.history = History(60)
        self.runtime = RuntimeState(self.history)
        self.profiles = ProfileStore(self.settings)
        self.blocklists = BlocklistManager(self.settings, self.profiles, self.runtime)

    def test_upstream_parser_supports_ipv6_and_deduplication(self) -> None:
        endpoints = parse_upstream_servers(
            "1.1.1.1:53,1.1.1.1:53,[2606:4700:4700::1111]:53"
        )
        self.assertEqual([item.key for item in endpoints], [
            "1.1.1.1:53", "[2606:4700:4700::1111]:53"
        ])

    def test_single_label_and_service_discovery_questions_are_valid(self) -> None:
        self.assertEqual(parse_dns_question(dns_query("printer"))[0], "printer")
        self.assertEqual(
            parse_dns_question(dns_query("_dns._udp.example.com"))[0],
            "_dns._udp.example.com",
        )

    def test_manual_rules_accept_service_discovery_domains(self) -> None:
        active = self.profiles.active()
        self.profiles.save({
            "id": active.id,
            "name": active.name,
            "upstream_servers": "1.1.1.1:53",
            "upstream_strategy": "primary_failover",
            "filter_enabled": True,
            "filter_preset": "off",
            "manual_block_domains": "_dns._udp.example.com",
            "allow_domains": "_sip._tcp.example.com",
            "custom_blocklist_urls": "",
            "activate": False,
        })
        updated = self.profiles.active()
        self.assertIn("_dns._udp.example.com", updated.manual_block)
        self.assertIn("_sip._tcp.example.com", updated.allow)

    def test_frpc_child_environment_excludes_application_secrets(self) -> None:
        secret_values = {
            "DOT_CERT_PEM": "certificate-secret",
            "DOT_KEY_PEM": "private-key-secret",
            "DOT_CERT_B64": "certificate-base64-secret",
            "DOT_KEY_B64": "private-key-base64-secret",
            "DASHBOARD_USERNAME": "dashboard-user",
            "DASHBOARD_PASSWORD": "dashboard-password-secret",
            "FRP_AUTH_TOKEN": "frp-token-secret",
        }
        parent_env = {
            **secret_values,
            "PATH": "/tmp/untrusted-path",
            "SSL_CERT_FILE": "/tmp/untrusted-ca-file",
        }
        with mock.patch.dict(os.environ, parent_env, clear=True):
            child_env = frpc_child_environment()
        self.assertEqual(
            child_env,
            {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": "/tmp",
                "TMPDIR": "/tmp",
                "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
                "SSL_CERT_DIR": "/etc/ssl/certs",
            },
        )
        for variable, value in secret_values.items():
            self.assertNotIn(variable, child_env)
            self.assertNotIn(value, child_env.values())
        self.assertNotEqual(child_env["PATH"], parent_env["PATH"])
        self.assertNotEqual(child_env["SSL_CERT_FILE"], parent_env["SSL_CERT_FILE"])

    def test_protocol_error_responses_preserve_transaction(self) -> None:
        query = dns_query()
        _, question_end = parse_dns_question(query)
        for response, rcode in (
            (build_formerr_response(query, question_end), 1),
            (build_servfail_response(query, question_end), 2),
        ):
            self.assertEqual(response[:2], query[:2])
            self.assertTrue(int.from_bytes(response[2:4], "big") & 0x8000)
            self.assertEqual(int.from_bytes(response[2:4], "big") & 0xF, rcode)

    def test_dns_cache_is_scoped_to_profile_revision(self) -> None:
        query = dns_query("cache-revision.example")
        domain, question_end = parse_dns_question(query)
        qtype_class = query[question_end - 4 : question_end]
        original_profile = self.profiles.active()
        response = build_nxdomain_response(query, question_end)
        cache_dns_response(
            original_profile, domain, qtype_class, response, question_end
        )
        cached = get_cached_dns_response(
            original_profile, domain, qtype_class, b"\xaa\xbb"
        )
        self.assertIsNotNone(cached)
        self.assertEqual(cached[:2], b"\xaa\xbb")

        self.profiles.save({
            "id": original_profile.id,
            "name": "Changed revision",
            "upstream_servers": "1.1.1.1:53",
            "upstream_strategy": "primary_failover",
            "filter_enabled": False,
            "filter_preset": "off",
            "manual_block_domains": "",
            "allow_domains": "",
            "custom_blocklist_urls": "",
            "activate": True,
        })
        self.assertIsNone(
            get_cached_dns_response(
                self.profiles.active(), domain, qtype_class, b"\xcc\xdd"
            )
        )

    def test_blocklist_parser_handles_hosts_and_inline_comments(self) -> None:
        parsed = parse_blocklist_text(
            "0.0.0.0 ads.example.com # comment\n||tracker.example.org^\nplain.example.net\n"
        )
        self.assertEqual(
            parsed,
            frozenset({"ads.example.com", "tracker.example.org", "plain.example.net"}),
        )

    def test_custom_blocklists_are_restricted_to_raw_github(self) -> None:
        valid = "https://raw.githubusercontent.com/owner/repo/main/list.txt"
        self.assertEqual(validate_raw_github_url(valid), valid)
        for invalid in (
            "http://raw.githubusercontent.com/owner/repo/main/list.txt",
            "https://example.com/list.txt",
            valid + "?download=1",
        ):
            with self.assertRaises(ValueError):
                validate_raw_github_url(invalid)

    def test_active_profile_snapshot_updates_without_reactivation(self) -> None:
        active = self.profiles.active()
        self.profiles.save({
            "id": active.id,
            "name": "Edited",
            "upstream_servers": "1.1.1.1:53",
            "upstream_strategy": "primary_failover",
            "filter_enabled": False,
            "filter_preset": "off",
            "manual_block_domains": "",
            "allow_domains": "",
            "custom_blocklist_urls": "",
            "activate": False,
        })
        self.assertEqual(self.profiles.active().name, "Edited")

    def test_dashboard_config_persists_and_hides_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "dashboard-data"
            settings = Settings(
                dot_enabled=False,
                frpc_enabled=False,
                upstreams=(UpstreamEndpoint("1.1.1.1", 53),),
            )
            store = RuntimeConfigStore(root)
            store.load_into(settings)
            self.assertTrue(store.public_payload(settings)["setup_required"])
            self.assertEqual(Path(settings.profiles_file).parent, root)

            store.set_credentials(settings, "admin", "strong-pass-123")
            self.assertTrue(store.verify("admin", "strong-pass-123"))
            self.assertFalse(store.verify("admin", "wrong-password"))
            store.update_settings(settings, {
                "frpc_enabled": True,
                "frp_server_addr": "203.0.113.10",
                "frp_server_port": 7000,
                "frp_remote_port": 853,
                "frp_auth_token": "secret-token",
                "dot_public_hostname": "dns.example.com",
                "history_minutes": 180,
            })
            public = store.public_payload(settings)
            self.assertEqual(public["settings"]["frp_server_addr"], "203.0.113.10")
            self.assertEqual(public["settings"]["history_minutes"], 180)
            self.assertTrue(public["secrets"]["frp_auth_token_configured"])
            self.assertNotIn("frp_auth_token", public["settings"])
            self.assertNotIn("secret-token", str(public))

            reloaded = Settings(
                dot_enabled=False,
                frpc_enabled=False,
                upstreams=(UpstreamEndpoint("1.1.1.1", 53),),
            )
            RuntimeConfigStore(root).load_into(reloaded)
            self.assertEqual(reloaded.frp_server_addr, "203.0.113.10")
            self.assertEqual(reloaded.frp_auth_token, "secret-token")
            self.assertEqual(reloaded.dot_public_hostname, "dns.example.com")

    def test_short_legacy_dashboard_password_migrates_without_lockout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(
                dashboard_username="legacy",
                dashboard_password="short",
                dot_enabled=False,
                frpc_enabled=False,
            )
            store = RuntimeConfigStore(Path(directory) / "data")
            store.load_into(settings)
            self.assertTrue(store.verify("legacy", "short"))

    def test_health_status_and_static_routes_are_safe(self) -> None:
        self.runtime.update(dot_state="disabled", frpc_state="disabled")
        self.assertTrue(readiness_payload(self.settings, self.runtime)["ready"])
        payload = status_payload(
            self.settings, self.runtime, self.profiles, self.blocklists
        )
        self.assertEqual(payload["checks"]["http"], "healthy")
        handler = build_handler(
            self.settings, self.runtime, self.profiles, self.blocklists
        )
        self.assertIn("/app.js", handler.static_routes)
        self.assertIn("/settings.js", handler.static_routes)
        self.assertNotIn("/api/status", handler.static_routes)

    def test_matching_certificate_and_key_validate(self) -> None:
        if not Path("/usr/bin/openssl").exists() and not Path("/bin/openssl").exists():
            self.skipTest("OpenSSL is unavailable")
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            cert = Path(directory) / "cert.pem"
            key = Path(directory) / "key.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=dns.example.com",
                "-addext", "subjectAltName=DNS:dns.example.com",
                "-keyout", str(key), "-out", str(cert),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            result = validate_certificate_files(
                cert, key, "dns.example.com", source="test"
            )
            self.assertTrue(result.valid, result.error)


if __name__ == "__main__":
    unittest.main()
