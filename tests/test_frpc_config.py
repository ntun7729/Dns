import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "app" / "main.py"
spec = importlib.util.spec_from_file_location("dns_dashboard_main", MODULE_PATH)
main = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = main
spec.loader.exec_module(main)


class FrpcConfigTests(unittest.TestCase):
    def test_tokenless_config_omits_authentication_lines(self):
        settings = main.Settings(frp_server_addr="203.0.113.10", frp_auth_token="")
        config = main.frpc_config(settings)

        self.assertTrue(settings.frpc_configured)
        self.assertEqual(settings.frp_auth_mode, "none")
        self.assertNotIn("auth.method", config)
        self.assertNotIn("auth.token", config)
        self.assertIn('serverAddr = "203.0.113.10"', config)
        self.assertIn("serverPort = 7000", config)
        self.assertIn("remotePort = 853", config)

    def test_token_config_includes_authentication_lines(self):
        settings = main.Settings(frp_server_addr="203.0.113.10", frp_auth_token="secret-token")
        config = main.frpc_config(settings)

        self.assertEqual(settings.frp_auth_mode, "token")
        self.assertIn('auth.method = "token"', config)
        self.assertIn('auth.token = "secret-token"', config)

    def test_public_config_never_exposes_token(self):
        settings = main.Settings(frp_server_addr="203.0.113.10", frp_auth_token="secret-token")
        public = settings.public_config()

        self.assertNotIn("frp_auth_token", public)
        self.assertEqual(public["frp_auth_mode"], "token")
        self.assertNotIn("secret-token", str(public))

    def test_server_address_is_the_only_required_frpc_setting(self):
        self.assertFalse(main.Settings(frp_server_addr="", frp_auth_token="").frpc_configured)
        self.assertTrue(main.Settings(frp_server_addr="203.0.113.10", frp_auth_token="").frpc_configured)


if __name__ == "__main__":
    unittest.main()
