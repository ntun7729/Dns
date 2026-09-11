from __future__ import annotations

import os
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

APP = Path(__file__).resolve().parents[1] / "app"
sys.path.insert(0, str(APP))
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("DOT_ENABLED", "false")
os.environ.setdefault("FRPC_ENABLED", "false")

import dns_service
from dns_service import (
    _decode_dns_name,
    parse_dns_question,
    send_doh_query,
    send_udp_query,
    send_upstream_query,
)
from settings import UpstreamEndpoint, parse_upstream_servers


def dns_query(name: str = "example.com", transaction_id: bytes = b"\x12\x34") -> bytes:
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    )
    return (
        transaction_id
        + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + labels
        + b"\x00\x00\x01\x00\x01"
    )


class DnsTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        with dns_service._TRANSPORT_PREFERENCE_LOCK:
            dns_service._TRANSPORT_PREFERENCE.clear()

    def test_udp_timeout_falls_back_to_tcp_and_remembers_tcp(self) -> None:
        endpoint = UpstreamEndpoint("1.1.1.1", 53)
        query = dns_query()
        response = query[:2] + b"\x81\x80" + query[4:]

        with mock.patch(
            "dns_service._send_udp_only", side_effect=socket.timeout("udp blocked")
        ) as udp, mock.patch(
            "dns_service.send_tcp_query", return_value=response
        ) as tcp:
            self.assertEqual(send_udp_query(endpoint, query, 2.0), response)
            self.assertEqual(udp.call_count, 1)
            self.assertEqual(tcp.call_count, 1)

            # TCP remains preferred until it actually fails. There is no forced
            # five-minute UDP re-probe that can invalidate Android Private DNS.
            self.assertEqual(send_udp_query(endpoint, query, 2.0), response)
            self.assertEqual(udp.call_count, 1)
            self.assertEqual(tcp.call_count, 2)
            self.assertEqual(dns_service._transport_preference(endpoint), "tcp")

    def test_udp_success_does_not_use_tcp(self) -> None:
        endpoint = UpstreamEndpoint("9.9.9.9", 53)
        query = dns_query()
        response = query[:2] + b"\x81\x80" + query[4:]

        with mock.patch("dns_service._send_udp_only", return_value=response) as udp, mock.patch(
            "dns_service.send_tcp_query"
        ) as tcp:
            self.assertEqual(send_udp_query(endpoint, query, 2.0), response)
            self.assertEqual(udp.call_count, 1)
            tcp.assert_not_called()

    def test_truncated_udp_response_retries_over_tcp(self) -> None:
        endpoint = UpstreamEndpoint("8.8.8.8", 53)
        query = dns_query()
        truncated = query[:2] + b"\x83\x80" + query[4:]
        full = query[:2] + b"\x81\x80" + query[4:]

        with mock.patch("dns_service._send_udp_only", return_value=truncated), mock.patch(
            "dns_service.send_tcp_query", return_value=full
        ) as tcp:
            self.assertEqual(send_udp_query(endpoint, query, 2.0), full)
            tcp.assert_called_once()

    def test_doh_url_parses_and_round_trips(self) -> None:
        endpoints = parse_upstream_servers(
            "https://dns.google/dns-query,https://cloudflare-dns.com/dns-query"
        )
        self.assertEqual(len(endpoints), 2)
        self.assertTrue(endpoints[0].is_doh)
        self.assertEqual(endpoints[0].host, "dns.google")
        self.assertEqual(endpoints[0].port, 443)
        self.assertEqual(endpoints[0].request_target, "/dns-query")
        self.assertEqual(endpoints[0].key, "https://dns.google/dns-query")
        self.assertEqual(
            endpoints[1].key, "https://cloudflare-dns.com/dns-query"
        )

    def test_doh_rejects_insecure_or_credentialed_urls(self) -> None:
        for value in (
            "http://dns.google/dns-query",
            "https://user:pass@dns.google/dns-query",
            "https://dns.google/dns-query#fragment",
        ):
            with self.assertRaises(ValueError):
                parse_upstream_servers(value)

    def test_doh_uses_binary_dns_https_post(self) -> None:
        endpoint = parse_upstream_servers("https://dns.google/dns-query")[0]
        query = dns_query()
        body = query[:2] + b"\x81\x80" + query[4:]
        http_response = mock.Mock()
        http_response.status = 200
        http_response.getheader.return_value = "application/dns-message"
        http_response.read.return_value = body
        connection = mock.Mock()
        connection.getresponse.return_value = http_response

        with mock.patch(
            "dns_service.http.client.HTTPSConnection", return_value=connection
        ), mock.patch("dns_service.ssl.create_default_context", return_value=mock.Mock()):
            self.assertEqual(send_doh_query(endpoint, query, 2.0), body)

        connection.request.assert_called_once()
        args, kwargs = connection.request.call_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(args[1], "/dns-query")
        self.assertEqual(kwargs["body"], query)
        self.assertEqual(kwargs["headers"]["Accept"], "application/dns-message")
        self.assertEqual(
            kwargs["headers"]["Content-Type"], "application/dns-message"
        )
        connection.close.assert_called_once()

    def test_doh_endpoint_bypasses_classic_udp_transport(self) -> None:
        endpoint = parse_upstream_servers("https://dns.google/dns-query")[0]
        query = dns_query()
        response = query[:2] + b"\x81\x80" + query[4:]
        with mock.patch("dns_service.send_doh_query", return_value=response) as doh, mock.patch(
            "dns_service.send_udp_query"
        ) as classic:
            self.assertEqual(send_upstream_query(endpoint, query, 2.0), response)
            doh.assert_called_once_with(endpoint, query, 2.0)
            classic.assert_not_called()

    def test_dns_name_decoder_accepts_safe_compression_pointer(self) -> None:
        encoded = b"\x07example\x03com\x00"
        payload = encoded + b"\xc0\x00"
        domain, end = _decode_dns_name(payload, len(encoded))
        self.assertEqual(domain, "example.com")
        self.assertEqual(end, len(encoded) + 2)

    def test_dns_name_decoder_rejects_pointer_loop(self) -> None:
        with self.assertRaisesRegex(ValueError, "pointer loop"):
            _decode_dns_name(b"\xc0\x00", 0)

    def test_normal_android_style_query_still_parses(self) -> None:
        query = dns_query("1234abcd-dnsotls-ds.metric.gstatic.com")
        domain, question_end = parse_dns_question(query)
        self.assertEqual(domain, "1234abcd-dnsotls-ds.metric.gstatic.com")
        self.assertEqual(query[question_end - 4 : question_end], b"\x00\x01\x00\x01")


if __name__ == "__main__":
    unittest.main()
