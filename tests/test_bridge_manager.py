import json
import subprocess
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge"))
from manager import (  # noqa: E402
    BACKUP_FORMAT,
    CertificateManager,
    ConfigStore,
    DEFAULT_CONFIG,
    render_frpc_toml,
    sanitize_frpc_toml,
    validate_frp,
)


class BridgeTests(unittest.TestCase):
    def test_default_frp_has_no_plain_dns_53(self):
        self.assertEqual(set(DEFAULT_CONFIG["proxies"]), {"dot", "doq"})
        text = render_frpc_toml(DEFAULT_CONFIG)
        self.assertNotIn("localPort = 53", text)
        self.assertNotIn("remotePort = 53", text)

    def test_validation_and_toml(self):
        cfg = validate_frp(
            {
                "enabled": True,
                "server_addr": "frp.example.com",
                "server_port": 7000,
                "transport_tls": True,
                "proxies": {
                    "dot": {"enabled": True, "local_port": 853, "remote_port": 853},
                    "doq": {"enabled": True, "local_port": 853, "remote_port": 853},
                },
            }
        )
        text = render_frpc_toml(cfg)
        self.assertIn('serverAddr = "frp.example.com"', text)
        self.assertNotIn("auth.token", text)
        self.assertIn('name = "dns-bridge-dot"', text)
        self.assertIn('name = "dns-bridge-doq"', text)
        self.assertIn('type = "udp"', text)

    def test_token_fields_are_ignored_and_raw_token_auth_is_rejected(self):
        cfg = validate_frp({"auth_token": "must-not-be-used", "clear_auth_token": True})
        self.assertNotIn("auth_token", cfg)
        self.assertNotIn("auth.token", render_frpc_toml(cfg))
        with self.assertRaises(ValueError):
            sanitize_frpc_toml('serverAddr = "x.example"\nauth.token = "secret"\n')
        with self.assertRaises(ValueError):
            sanitize_frpc_toml('serverAddr = "x.example"\nauth.method = "token"\n')

    def test_raw_toml_round_trip(self):
        raw = (
            'serverAddr = "frp.example.com"\n'
            'serverPort = 7000\n'
            'transport.tls.enable = true\n\n'
            '[[proxies]]\n'
            'name = "dot"\n'
            'type = "tcp"\n'
            'localIP = "127.0.0.1"\n'
            'localPort = 853\n'
            'remotePort = 8853\n'
        )
        with tempfile.TemporaryDirectory() as root:
            store = ConfigStore(Path(root))
            store.save_frpc_toml(raw, True)
            self.assertEqual(store.get_frpc_toml(), raw)
            self.assertTrue(store.get_frp()["enabled"])
            self.assertNotIn("localPort = 53", store.get_frpc_toml())

    def test_backup_round_trip_preserves_raw_toml(self):
        with tempfile.TemporaryDirectory() as root:
            store = ConfigStore(Path(root))
            store.set_admin("admin", "very-secure-password")
            raw = 'serverAddr = "1.2.3.4"\nserverPort = 7000\n'
            store.save_frpc_toml(raw, True)
            backup = store.export_backup()
            self.assertEqual(backup["format"], BACKUP_FORMAT)
            clone_root = Path(root) / "clone"
            clone = ConfigStore(clone_root)
            clone.import_backup(json.loads(json.dumps(backup)))
            self.assertEqual(clone.get_frpc_toml(), raw)
            self.assertTrue(clone.verify("admin", "very-secure-password"))

    def test_legacy_config_migration(self):
        with tempfile.TemporaryDirectory() as root:
            legacy = Path(root) / "legacy"
            legacy.mkdir()
            legacy_doc = {
                "format": "dns-dashboard-config-v2",
                "settings": {
                    "frpc_enabled": True,
                    "frp_server_addr": "frp.old.example",
                    "frp_server_port": 7000,
                    "frp_auth_token": "old-token",
                    "frp_remote_port": 8853,
                    "dot_enabled": True,
                    "dot_port": 853,
                },
                "auth": {"username": "", "password_hash": ""},
            }
            (legacy / "config.json").write_text(json.dumps(legacy_doc))
            store = ConfigStore(Path(root) / "new", legacy)
            frp = store.get_frp()
            self.assertTrue(frp["enabled"])
            self.assertEqual(frp["server_addr"], "frp.old.example")
            self.assertNotIn("auth_token", frp)
            self.assertEqual(frp["proxies"]["dot"]["remote_port"], 8853)
            self.assertNotIn("localPort = 53", store.get_frpc_toml())

    def test_manual_pem_import_creates_valid_blank_password_pfx(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            cert_file = root_path / "test.crt"
            key_file = root_path / "test.key"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key_file), "-out", str(cert_file),
                    "-subj", "/CN=dns.example.com", "-days", "1",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            certs = CertificateManager(root_path / "bridge", root_path / "technitium")
            certs.import_manual(
                cert_file.read_text(encoding="utf-8"),
                key_file.read_text(encoding="utf-8"),
            )
            status = certs.status()
            self.assertTrue(status["certificate_exists"])
            self.assertEqual(status["pfx_password"], "")
            subprocess.run(
                [
                    "openssl", "pkcs12", "-in", status["pfx_path"],
                    "-passin", "pass:", "-noout",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

    def test_lego_v5_run_command_places_flags_after_subcommand(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            certs = CertificateManager(root_path / "bridge", root_path / "technitium", lego_binary="/usr/local/bin/lego")
            first = certs._build_lego_command("dns.example.com", "admin@example.com", True)
            renew = certs._build_lego_command("dns.example.com", "admin@example.com", False)

            self.assertEqual(first[:2], ["/usr/local/bin/lego", "run"])
            self.assertGreater(first.index("--email"), first.index("run"))
            self.assertGreater(first.index("--dns"), first.index("run"))
            self.assertGreater(first.index("--domains"), first.index("run"))
            self.assertIn("--accept-tos", first)
            self.assertNotIn("renew", first)

            self.assertEqual(renew[:2], ["/usr/local/bin/lego", "run"])
            self.assertIn("--renew-days", renew)
            self.assertIn("30", renew)
            self.assertIn("--no-random-sleep", renew)
            self.assertNotIn("renew", renew)

    def test_bridge_ui_preserves_dirty_form_values_during_polling(self):
        index = (Path(__file__).resolve().parents[1] / "bridge" / "index.html").read_text(encoding="utf-8")
        self.assertIn("frpDirty=false,certDirty=false,adminDirty=false", index)
        self.assertIn("if(hydrateForm||!frpDirty)", index)
        self.assertIn("if(hydrateForm||!certDirty)", index)
        self.assertIn("refresh(false)", index)

    def test_cloudflare_token_is_not_exported(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            certs = CertificateManager(root_path / "bridge", root_path / "technitium")
            certs.save_cloudflare(
                {
                    "domain": "dns.example.com",
                    "email": "admin@example.com",
                    "api_token": "super-secret-cloudflare-token",
                    "auto_renew": True,
                    "accept_tos": True,
                }
            )
            status = certs.status()
            exported = certs.export_config()
            self.assertTrue(status["cloudflare_token_configured"])
            self.assertNotIn("api_token", exported)
            self.assertNotIn("super-secret-cloudflare-token", json.dumps(exported))
            self.assertEqual(exported["domain"], "dns.example.com")

    def test_invalid_enabled_without_server(self):
        with self.assertRaises(ValueError):
            validate_frp({"enabled": True, "server_addr": ""})


if __name__ == "__main__":
    unittest.main()
