import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge"))
from manager import (  # noqa: E402
    BACKUP_FORMAT,
    ConfigStore,
    render_frpc_toml,
    validate_frp,
)


class BridgeTests(unittest.TestCase):
    def test_validation_and_toml(self):
        cfg = validate_frp(
            {
                "enabled": True,
                "server_addr": "frp.example.com",
                "server_port": 7000,
                "transport_tls": True,
                "proxies": {
                    "dot": {"enabled": True, "local_port": 853, "remote_port": 853},
                    "dns_udp": {"enabled": True, "local_port": 53, "remote_port": 53},
                },
            }
        )
        text = render_frpc_toml(cfg)
        self.assertIn('serverAddr = "frp.example.com"', text)
        self.assertNotIn("auth.token", text)
        self.assertIn('name = "dns-bridge-dot"', text)
        self.assertIn('type = "udp"', text)

    def test_token_fields_are_ignored(self):
        cfg = validate_frp({"auth_token": "must-not-be-used", "clear_auth_token": True})
        self.assertNotIn("auth_token", cfg)
        self.assertNotIn("auth.token", render_frpc_toml(cfg))

    def test_backup_round_trip(self):
        with tempfile.TemporaryDirectory() as root:
            store = ConfigStore(Path(root))
            store.set_admin("admin", "very-secure-password")
            store.save_frp({"server_addr": "1.2.3.4", "enabled": True})
            backup = store.export_backup()
            self.assertEqual(backup["format"], BACKUP_FORMAT)
            clone_root = Path(root) / "clone"
            clone = ConfigStore(clone_root)
            clone.import_backup(json.loads(json.dumps(backup)))
            self.assertEqual(clone.get_frp()["server_addr"], "1.2.3.4")
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

    def test_invalid_enabled_without_server(self):
        with self.assertRaises(ValueError):
            validate_frp({"enabled": True, "server_addr": ""})


if __name__ == "__main__":
    unittest.main()
