import tempfile
import unittest
from pathlib import Path

from dpi_engine import (
    BlockingRules,
    PacketInfo,
    classify_domain,
    extract_http_host,
    extract_tls_sni,
    parse_packet,
)
from generate_test_pcap import create_capture, tls_client_hello, tcp_packet


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

    def test_processes_generated_capture(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_file = str(Path(temp_dir) / "input.pcap")
            output_file = str(Path(temp_dir) / "output.pcap")
            create_capture(input_file)
            from dpi_engine import DPIEngine
            engine = DPIEngine(BlockingRules(blocked_apps=["YouTube"]), num_lbs=1, fps_per_lb=1)
            self.assertTrue(engine.process_file(input_file, output_file))
            self.assertGreater(engine.stats.total_packets, 0)
            self.assertGreater(engine.stats.dropped, 0)
            self.assertTrue(Path(output_file).exists())

    def test_blocks_destination_port(self):
        rules = BlockingRules(blocked_ports=[8080])
        info = PacketInfo("10.0.0.2", "10.0.0.3", 50000, 8080, 6, "TCP", 54)
        flow = type("Flow", (), {"app": "Unknown", "domain": ""})()
        self.assertTrue(rules.is_blocked(info, flow))

    def test_matches_wildcard_domain_rule(self):
        rules = BlockingRules(blocked_domains=["*.tiktok.com"])
        info = PacketInfo("10.0.0.2", "10.0.0.3", 50000, 443, 6, "TCP", 54)
        flow = type("Flow", (), {"app": "HTTPS", "domain": "api.tiktok.com"})()
        self.assertTrue(rules.is_blocked(info, flow))

    def test_rejects_invalid_destination_port(self):
        with self.assertRaises(ValueError):
            BlockingRules(blocked_ports=[70000])

    def test_rejects_unknown_app_name(self):
        with self.assertRaises(ValueError):
            BlockingRules(blocked_apps=["not-an-app"])


if __name__ == "__main__":
    unittest.main()
