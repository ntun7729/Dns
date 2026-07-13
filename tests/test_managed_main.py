import importlib
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

APP_ROOT = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP_ROOT))

core = importlib.import_module("main")
enhanced = importlib.import_module("enhanced_main")
managed = importlib.import_module("managed_main")


def dns_query(domain: str, qtype: int = 1) -> bytes:
    transaction_id = b"\x12\x34"
    flags = b"\x01\x00"
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in domain.split("."))
    question = labels + b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    return transaction_id + flags + counts + question


class ManagedDashboardTests(unittest.TestCase):
    def setUp(self):
        enhanced.reset_runtime()
        with managed.PROFILE_LOCK:
            managed.PROFILES.clear()
            profile = managed._new_profile(
                name="Default",
                upstreams=(enhanced.UpstreamEndpoint("1.1.1.1", 53),),
                strategy="primary_failover",
                filter_enabled=False,
                filter_preset="off",
                manual_block=set(),
                allow=set(),
                profile_id="default",
            )
            managed.PROFILES[profile["id"]] = profile
            managed.ACTIVE_PROFILE_ID = profile["id"]
        with managed.FILTER_LOCK:
            managed.BLOCKED_QUERIES = 0
            for cache in managed.BLOCKLIST_CACHE.values():
                cache["domains"] = set()
                cache["loading"] = False
                cache["last_error"] = None
        with managed.HISTORY_LOCK:
            managed.HISTORY.clear()
        managed._sync_active_profile()

    def test_parse_dns_question_and_nxdomain_response(self):
        query = dns_query("ads.example.com")
        domain, question_end = managed.parse_dns_question(query)
        self.assertEqual(domain, "ads.example.com")
        response = managed.build_nxdomain_response(query, question_end)
        self.assertEqual(response[:2], query[:2])
        self.assertTrue(int.from_bytes(response[2:4], "big") & 0x8000)
        self.assertEqual(int.from_bytes(response[2:4], "big") & 0x000F, 3)
        self.assertEqual(response[12:], query[12:question_end])

    def test_manual_block_and_allowlist_precedence(self):
        with managed.PROFILE_LOCK:
            profile = managed.PROFILES[managed.ACTIVE_PROFILE_ID]
            profile["filter_enabled"] = True
            profile["manual_block"] = {"example.com"}
            profile["allow"] = {"allowed.example.com"}
        self.assertTrue(managed.domain_is_blocked("ads.example.com"))
        self.assertFalse(managed.domain_is_blocked("allowed.example.com"))

    def test_profile_lifecycle_and_export_import(self):
        with patch.object(managed, "refresh_blocklist_async"):
            control = managed.save_profile(
                {
                    "name": "Family",
                    "upstream_servers": "1.1.1.1:53,9.9.9.9:53",
                    "upstream_strategy": "primary_failover",
                    "filter_enabled": True,
                    "filter_preset": "hagezi_light",
                    "manual_block_domains": "example-ads.test",
                    "allow_domains": "allowed.test",
                    "activate": True,
                }
            )
            self.assertEqual(len(control["profiles"]), 2)
            active = control["active_profile_id"]
            self.assertEqual(managed.PROFILES[active]["name"], "Family")

            control = managed.duplicate_profile(active)
            self.assertEqual(len(control["profiles"]), 3)
            self.assertTrue(managed.PROFILES[control["active_profile_id"]]["name"].endswith("Copy"))

            exported = managed.export_profiles()
            self.assertEqual(exported["format"], "dns-dashboard-profiles-v1")
            managed.import_profiles(exported)
            self.assertEqual(len(managed.PROFILES), 3)

            duplicate_id = managed.ACTIVE_PROFILE_ID
            control = managed.delete_profile(duplicate_id)
            self.assertEqual(len(control["profiles"]), 2)

    def test_history_is_bounded_and_aggregate_only(self):
        managed._record_history(queries=2, blocked=1, errors=1, failovers=1, latency_ms=12.5)
        points = managed.history_snapshot()
        self.assertEqual(len(points), managed.HISTORY_MINUTES)
        last = points[-1]
        self.assertEqual(last["queries"], 2)
        self.assertEqual(last["blocked"], 1)
        self.assertEqual(last["errors"], 1)
        self.assertEqual(last["failovers"], 1)
        self.assertEqual(last["latency_ms"], 12.5)
        self.assertNotIn("domain", last)
        self.assertNotIn("client", last)

    def test_status_payload_exposes_profiles_without_domain_names(self):
        core.set_runtime(
            dot_state="running",
            frpc_state="running",
            frpc_started_at=core.now_iso(),
            certificate={
                "source": "environment",
                "configured": True,
                "valid": True,
                "hostname_match": True,
                "key_match": True,
                "expired": False,
                "not_yet_valid": False,
                "not_before": core.now_iso(),
                "expires_at": core.now_iso(core.time.time() + 86400 * 89),
                "days_remaining": 89,
                "error": None,
            },
        )
        settings = core.Settings(
            app_env="production",
            dot_public_hostname="dns.nyan.college",
            frpc_enabled=True,
            frp_server_addr="203.0.113.10",
        )
        payload = managed.status_payload(settings)
        self.assertEqual(payload["profile"]["name"], "Default")
        self.assertIn("history", payload)
        encoded = str(payload)
        self.assertNotIn("manual_block_domains", encoded)
        self.assertNotIn("allow_domains", encoded)


if __name__ == "__main__":
    unittest.main()
