import unittest

from dpi_engine import (
    BlockingRules,
    PacketInfo,
    classify_domain,
    extract_http_host,
    extract_tls_sni,
    parse_packet,
)
from generate_test_pcap import tls_client_hello, tcp_packet


class DPIEngineTests(unittest.TestCase):
    def test_classifies_known_domains(self):
        self.assertEqual(classify_domain("www.youtube.com"), "YouTube")
        self.assertEqual(classify_domain("www.facebook.com"), "Facebook")
        self.assertEqual(classify_domain("example.org"), "HTTPS")
        self.assertEqual(classify_domain(""), "Unknown")

    def test_extracts_tls_sni(self):
        self.assertEqual(extract_tls_sni(tls_client_hello("www.youtube.com")), "www.youtube.com")

    def test_extracts_http_host(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: test\r\n\r\n"
        self.assertEqual(extract_http_host(payload), "example.com")

    def test_parses_ethernet_ipv4_tcp(self):
        packet = tcp_packet(
            "192.168.1.50", "142.250.72.14", 51001, 443,
            tls_client_hello("www.youtube.com"), 1
        )
        info = parse_packet(packet)
        self.assertIsNotNone(info)
        self.assertEqual(info.src_ip, "192.168.1.50")
        self.assertEqual(info.dst_port, 443)
        self.assertEqual(info.transport, "TCP")
        self.assertGreater(info.payload_offset, 14)

    def test_blocking_rules(self):
        rules = BlockingRules(
            blocked_ips=["192.168.1.50"],
            blocked_apps=["YouTube"],
            blocked_domains=["facebook"],
        )
        info = PacketInfo("192.168.1.50", "142.250.72.14", 51001, 443, 6, "TCP", 54)
        self.assertTrue(rules.is_blocked(info, type("Flow", (), {"app": "Unknown", "domain": ""})()))

    def test_rejects_unknown_app_name(self):
        with self.assertRaises(ValueError):
            BlockingRules(blocked_apps=["not-an-app"])


if __name__ == "__main__":
    unittest.main()
