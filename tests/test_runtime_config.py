import importlib.util
import os
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "app" / "main.py"
SPEC = importlib.util.spec_from_file_location("dashboard_main", MODULE_PATH)
dashboard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = dashboard
SPEC.loader.exec_module(dashboard)


class RuntimeConfigTests(unittest.TestCase):
    def test_frpc_config_uses_dot_and_remote_853(self):
        settings = dashboard.Settings(
            dot_bind_host="127.0.0.1",
            dot_port=8853,
            frp_server_addr="frps.example.com",
            frp_auth_token="secret",
            frp_remote_port=853,
        )

        config = dashboard.frpc_config(settings)

        self.assertIn('serverAddr = "frps.example.com"', config)
        self.assertIn('localIP = "127.0.0.1"', config)
        self.assertIn("localPort = 8853", config)
        self.assertIn("remotePort = 853", config)
        self.assertIn('auth.token = "secret"', config)

    def test_public_config_masks_frp_token(self):
        settings = dashboard.Settings(frp_auth_token="secret")

        self.assertEqual(settings.public_config()["frp_auth_token"], "***configured***")

    def test_render_defaults_match_docker_runtime(self):
        settings = dashboard.Settings()

        self.assertEqual(settings.port, int(os.getenv("PORT", "10000")))
        self.assertEqual(settings.dot_port, 8853)
        self.assertEqual(settings.frp_remote_port, 853)
