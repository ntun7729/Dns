import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "main.py"
SPEC = importlib.util.spec_from_file_location("dns_dashboard_main", MODULE_PATH)
main = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = main
SPEC.loader.exec_module(main)


class CertificateFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp_directory.name)
        cls.cert_one, cls.key_one = cls._generate_certificate("dns.nyan.college", "one")
        cls.cert_two, cls.key_two = cls._generate_certificate("other.nyan.college", "two")

    @classmethod
    def tearDownClass(cls):
        cls.temp_directory.cleanup()

    @classmethod
    def _generate_certificate(cls, hostname: str, name: str):
        cert = cls.root / f"{name}.crt"
        key = cls.root / f"{name}.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                f"/CN={hostname}",
                "-addext",
                f"subjectAltName=DNS:{hostname}",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return cert, key


class FrpcConfigurationTests(unittest.TestCase):
    def test_tokenless_frpc_configuration_omits_all_authentication_lines(self):
        settings = main.Settings(frp_server_addr="203.0.113.10", frp_auth_token="")
        config = main.frpc_config(settings)

        self.assertTrue(settings.frpc_configured)
        self.assertEqual(settings.frp_auth_mode, "none")
        self.assertNotIn("auth.method", config)
        self.assertNotIn("auth.token", config)
        self.assertIn('serverAddr = "203.0.113.10"', config)
        self.assertIn("serverPort = 7000", config)
        self.assertIn("remotePort = 853", config)

    def test_token_authenticated_frpc_configuration_includes_authentication(self):
        settings = main.Settings(
            frp_server_addr="203.0.113.10",
            frp_auth_token="secret-token",
        )
        config = main.frpc_config(settings)

        self.assertEqual(settings.frp_auth_mode, "token")
        self.assertIn('auth.method = "token"', config)
        self.assertIn('auth.token = "secret-token"', config)

    def test_frpc_defaults_match_required_architecture(self):
        settings = main.Settings()
        self.assertEqual(settings.frp_server_port, 7000)
        self.assertEqual(settings.frp_remote_port, 853)
        self.assertEqual(settings.dot_bind_host, "127.0.0.1")
        self.assertEqual(settings.dot_port, 8853)

    def test_frpc_config_file_is_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "frpc.toml"
            settings = main.Settings(
                frp_server_addr="203.0.113.10",
                frpc_config_file=str(path),
            )
            main.write_frpc_config(settings)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_frpc_startup_failure_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-frpc"
            binary.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
            binary.chmod(0o700)
            main.reset_runtime()
            main.set_runtime(dot_state="disabled")
            settings = main.Settings(
                dot_enabled=False,
                frp_server_addr="203.0.113.10",
                frpc_binary=str(binary),
                frpc_config_file=str(Path(directory) / "frpc.toml"),
                frpc_startup_grace_seconds=0.05,
            )

            process = main.start_frpc(settings)
            self.assertIsNotNone(process)
            process.wait(timeout=2)
            time.sleep(0.1)
            snapshot = main.runtime_snapshot()
            self.assertEqual(snapshot["frpc_state"], "startup-failed")
            self.assertEqual(snapshot["frpc_exit_code"], 7)


class CertificateTests(CertificateFixture):
    def test_certificate_environment_variables_are_written_and_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            cert_path = Path(directory) / "runtime.crt"
            key_path = Path(directory) / "runtime.key"
            cert_text = self.cert_one.read_text(encoding="utf-8")
            key_text = self.key_one.read_text(encoding="utf-8")
            settings = main.Settings(
                app_env="production",
                dot_public_hostname="dns.nyan.college",
                dot_cert_pem=cert_text.replace("\n", "\\n"),
                dot_key_pem=key_text,
                dot_cert_file=str(cert_path),
                dot_key_file=str(key_path),
                frpc_enabled=False,
            )

            status = main.prepare_tls_material(settings)

            self.assertTrue(status.valid, status.error)
            self.assertEqual(status.source, "environment")
            self.assertTrue(cert_path.read_text(encoding="utf-8").endswith("\n"))
            self.assertTrue(key_path.read_text(encoding="utf-8").endswith("\n"))
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            self.assertNotEqual(status.expires_at, None)

    def test_certificate_and_private_key_must_match(self):
        status = main.validate_certificate_files(
            self.cert_one,
            self.key_two,
            "dns.nyan.college",
            source="test",
        )
        self.assertFalse(status.valid)
        self.assertFalse(status.key_match)

    def test_certificate_hostname_must_match_public_hostname(self):
        matching = main.validate_certificate_files(
            self.cert_one,
            self.key_one,
            "dns.nyan.college",
            source="test",
        )
        mismatching = main.validate_certificate_files(
            self.cert_one,
            self.key_one,
            "wrong.nyan.college",
            source="test",
        )
        self.assertTrue(matching.hostname_match)
        self.assertTrue(matching.valid, matching.error)
        self.assertFalse(mismatching.hostname_match)
        self.assertFalse(mismatching.valid)

    def test_expired_certificate_is_rejected(self):
        decoded = main.ssl._ssl._test_decode_cert(str(self.cert_one))
        future = main.ssl.cert_time_to_seconds(decoded["notAfter"]) + 1
        status = main.validate_certificate_files(
            self.cert_one,
            self.key_one,
            "dns.nyan.college",
            source="test",
            now=future,
        )
        self.assertTrue(status.expired)
        self.assertFalse(status.valid)

    def test_production_missing_manual_certificate_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = main.Settings(
                app_env="production",
                dot_public_hostname="dns.nyan.college",
                dot_cert_file=str(Path(directory) / "missing.crt"),
                dot_key_file=str(Path(directory) / "missing.key"),
            )
            status = main.prepare_tls_material(settings)
            self.assertFalse(status.valid)
            self.assertEqual(status.source, "missing")
            self.assertIn("DOT_CERT_PEM", status.error)
            self.assertFalse(Path(settings.dot_cert_file).exists())
            self.assertFalse(Path(settings.dot_key_file).exists())

    def test_development_can_generate_a_self_signed_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = main.Settings(
                app_env="development",
                dot_public_hostname="dns-dashboard.local",
                dot_cert_file=str(Path(directory) / "dev.crt"),
                dot_key_file=str(Path(directory) / "dev.key"),
                frpc_enabled=False,
            )
            status = main.prepare_tls_material(settings)
            self.assertTrue(status.valid, status.error)
            self.assertEqual(status.source, "self-signed")


class ReadinessAndRedactionTests(CertificateFixture):
    def setUp(self):
        main.reset_runtime()

    def test_production_readiness_requires_certificate_dot_and_frpc(self):
        settings = main.Settings(
            app_env="production",
            dot_public_hostname="dns.nyan.college",
            frpc_enabled=True,
            frp_server_addr="203.0.113.10",
        )
        certificate = main.validate_certificate_files(
            self.cert_one,
            self.key_one,
            "dns.nyan.college",
            source="environment",
        )
        main.set_runtime(
            certificate=certificate.as_public(),
            dot_state="running",
            frpc_state="running",
        )
        self.assertTrue(main.readiness_payload(settings)["ready"])

        main.set_runtime(frpc_state="exited")
        self.assertFalse(main.readiness_payload(settings)["ready"])

        main.set_runtime(frpc_state="running", dot_state="certificate-error")
        self.assertFalse(main.readiness_payload(settings)["ready"])

    def test_missing_certificate_fails_production_readiness(self):
        settings = main.Settings(
            app_env="production",
            dot_public_hostname="dns.nyan.college",
            frpc_enabled=False,
        )
        main.set_runtime(dot_state="certificate-error")
        self.assertFalse(main.readiness_payload(settings)["ready"])

    def test_secret_redaction_removes_token_key_and_certificate(self):
        token = "super-secret-frp-token"
        key = self.key_one.read_text(encoding="utf-8")
        cert = self.cert_one.read_text(encoding="utf-8")
        settings = main.Settings(
            frp_auth_token=token,
            dot_key_pem=key,
            dot_cert_pem=cert,
        )
        text = f"token={token}\n{key}\n{cert}\nauth.token = \"{token}\""
        redacted = main.redact_text(text, settings)
        self.assertNotIn(token, redacted)
        self.assertNotIn("BEGIN PRIVATE KEY", redacted)
        self.assertNotIn("BEGIN CERTIFICATE", redacted)

    def test_status_api_never_contains_secret_values(self):
        token = "super-secret-frp-token"
        key = self.key_one.read_text(encoding="utf-8")
        cert = self.cert_one.read_text(encoding="utf-8")
        settings = main.Settings(
            app_env="production",
            dot_public_hostname="dns.nyan.college",
            dot_key_pem=key,
            dot_cert_pem=cert,
            frp_auth_token=token,
            frp_server_addr="203.0.113.10",
        )
        payload = json.dumps(main.status_payload(settings))
        self.assertNotIn(token, payload)
        self.assertNotIn("BEGIN PRIVATE KEY", payload)
        self.assertNotIn("BEGIN CERTIFICATE", payload)
        self.assertIn('"frp_auth_mode": "token"', payload)
        self.assertIn('"public_dns_hostname": "dns.nyan.college"', payload)


if __name__ == "__main__":
    unittest.main()
