import asyncio
import importlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_ROOT))


class DashboardV24Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = importlib.import_module("main")
        cls.enhanced = importlib.import_module("enhanced_main")
        cls.managed = importlib.import_module("managed_main")
        cls.v2 = importlib.import_module("dashboard_v2")

    def setUp(self):
        self.enhanced.reset_runtime()
        with self.managed.PROFILE_LOCK:
            self.managed.PROFILES.clear()
            profile = self.v2.new_profile(
                name="Default",
                upstreams=(self.enhanced.UpstreamEndpoint("1.1.1.1", 53),),
                strategy="primary_failover",
                filter_enabled=True,
                filter_preset="off",
                manual_block=set(),
                allow=set(),
                custom_blocklist_urls=(),
                profile_id="default",
            )
            self.managed.PROFILES[profile["id"]] = profile
            self.managed.ACTIVE_PROFILE_ID = profile["id"]

    def test_accepts_only_raw_github_https_urls(self):
        good = "https://raw.githubusercontent.com/example/repo/main/list.txt"
        self.assertEqual(self.v2.validate_raw_github_url(good), good)
        for bad in [
            "http://raw.githubusercontent.com/example/repo/main/list.txt",
            "https://github.com/example/repo/raw/main/list.txt",
            "https://raw.githubusercontent.com.evil.test/example/repo/main/list.txt",
            "https://raw.githubusercontent.com/example/repo/list.txt",
            "https://raw.githubusercontent.com/example/repo/main/list.txt?x=1",
        ]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.v2.validate_raw_github_url(bad)

    def test_profile_export_keeps_custom_sources(self):
        url = "https://raw.githubusercontent.com/example/repo/main/list.txt"
        with patch.object(self.v2, "refresh_custom_source_async"):
            control = self.managed.save_profile(
                {
                    "id": "default",
                    "name": "Protected",
                    "upstream_servers": "1.1.1.1:53",
                    "upstream_strategy": "primary_failover",
                    "filter_enabled": True,
                    "filter_preset": "off",
                    "custom_blocklist_urls": url,
                    "manual_block_domains": "",
                    "allow_domains": "",
                    "activate": True,
                }
            )
        profile = control["profiles"][0]
        self.assertEqual(profile["custom_blocklist_urls"], url)
        exported = self.managed.export_profiles()
        self.assertEqual(exported["profiles"][0]["custom_blocklist_urls"], url)

    def test_custom_source_domains_are_used_for_blocking(self):
        url = "https://raw.githubusercontent.com/example/repo/main/list.txt"
        with self.managed.PROFILE_LOCK:
            profile = self.managed.PROFILES["default"]
            profile["custom_blocklist_urls"] = (url,)
        with self.v2.CUSTOM_SOURCE_LOCK:
            self.v2.CUSTOM_SOURCE_CACHE[url] = {
                "domains": {"ads.example.com"},
                "loading": False,
                "last_updated_at": self.core.now_iso(),
                "last_error": None,
            }
        self.assertTrue(self.v2.domain_is_blocked("ads.example.com"))
        self.assertTrue(self.v2.domain_is_blocked("sub.ads.example.com"))
        self.assertFalse(self.v2.domain_is_blocked("example.org"))

    def test_clean_eof_is_not_counted_as_disconnect(self):
        clean = asyncio.IncompleteReadError(partial=b"", expected=2)
        partial = asyncio.IncompleteReadError(partial=b"\x00", expected=2)
        self.assertFalse(self.v2.should_count_incomplete_read(clean))
        self.assertTrue(self.v2.should_count_incomplete_read(partial))


if __name__ == "__main__":
    unittest.main()
