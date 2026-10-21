#!/usr/bin/env python3
"""Pure-Python PCAP-based Deep Packet Inspection engine.

This is an offline analysis tool: it reads an existing PCAP file and writes
packets that are allowed by the configured rules to another PCAP file.
"""
from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import queue
import struct
import sys
import threading
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Optional

APP_PATTERNS = {
    "Google": ("google", "gstatic", "googleapis", "ggpht", "gvt1"),
    "YouTube": ("youtube", "ytimg", "youtu.be", "yt3.ggpht"),
    "Facebook": ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"),
    "Instagram": ("instagram", "cdninstagram"),
    "WhatsApp": ("whatsapp", "wa.me"),
    "Twitter/X": ("twitter", "twimg", "x.com", "t.co"),
    "Netflix": ("netflix", "nflxvideo", "nflximg"),
    "Amazon": ("amazon", "amazonaws", "cloudfront", "aws"),
    "Microsoft": ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"),
    "Apple": ("apple", "icloud", "mzstatic", "itunes"),
    "Telegram": ("telegram", "t.me"),
    "TikTok": ("tiktok", "tiktokcdn", "musical.ly", "bytedance"),
    "Spotify": ("spotify", "scdn.co"),
    "Zoom": ("zoom",),
    "Discord": ("discord", "discordapp"),
    "GitHub": ("github", "githubusercontent"),
    "Cloudflare": ("cloudflare", "cf-"),
}
VALID_APPS = {"Unknown", "HTTP", "HTTPS", "DNS", "TLS", "QUIC", *APP_PATTERNS.keys()}


@dataclass(frozen=True)
class PacketInfo:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    transport: str
    payload_offset: int
    tcp_flags: int = 0

    @property
    def flow_key(self) -> tuple[str, str, int, int, int]:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)


@dataclass
class FlowState:
    app: str = "Unknown"
    domain: str = ""
    packets: int = 0
    byte_count: int = 0
    blocked: bool = False


@dataclass
class Statistics:
    total_packets: int = 0
    total_bytes: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    forwarded: int = 0
    dropped: int = 0
    app_counts: Counter = field(default_factory=Counter)
    detected_domains: dict[str, str] = field(default_factory=dict)
    lb_counts: Counter = field(default_factory=Counter)
    fp_counts: Counter = field(default_factory=Counter)
    active_flows: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


class PcapReader:
    """Read classic PCAP files without requiring third-party packages."""

    MAGIC_FORMATS = {
        b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
        b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
        b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
        b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
    }

    def __init__(self, filename: str):
        self.filename = filename
        self.file: Optional[BinaryIO] = None
        self.global_header = b""
        self.endian = "<"
        self.timestamp_precision = "microseconds"

    def open(self) -> None:
        self.file = open(self.filename, "rb")
        self.global_header = self.file.read(24)
        if len(self.global_header) != 24:
            self.file.close()
            raise ValueError("Input is too small to contain a PCAP global header.")
        magic = self.global_header[:4]
        if magic not in self.MAGIC_FORMATS:
            self.file.close()
            raise ValueError("Unsupported capture format. Please provide a classic PCAP file.")
        self.endian, self.timestamp_precision = self.MAGIC_FORMATS[magic]

    def packets(self):
        if self.file is None:
            raise RuntimeError("PCAP reader is not open.")
        packet_header_struct = struct.Struct(self.endian + "IIII")
        while True:
            packet_header = self.file.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise ValueError("Capture ended in the middle of a packet header.")
            _ts_sec, _ts_frac, captured_length, _original_length = packet_header_struct.unpack(packet_header)
            if captured_length > 64 * 1024 * 1024:
                raise ValueError(f"Unreasonable packet size in capture: {captured_length} bytes.")
            data = self.file.read(captured_length)
            if len(data) != captured_length:
                raise ValueError("Capture ended in the middle of packet data.")
            yield packet_header, data

    def close(self) -> None:
        if self.file is not None:
            self.file.close()
            self.file = None


def parse_packet(data: bytes) -> Optional[PacketInfo]:
    """Parse Ethernet + IPv4 + TCP/UDP headers and return transport payload offset."""
    if len(data) < 14:
        return None
    offset = 14
    ether_type = struct.unpack_from("!H", data, 12)[0]

    # Support common VLAN tags.
    while ether_type in (0x8100, 0x88A8, 0x9100):
        if len(data) < offset + 4:
            return None
        ether_type = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4

    if ether_type != 0x0800 or len(data) < offset + 20:
        return None  # This implementation currently inspects IPv4 Ethernet frames only.

    version_ihl = data[offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(data) < offset + ip_header_length:
        return None

    total_length = struct.unpack_from("!H", data, offset + 2)[0]
    if total_length < ip_header_length:
        return None
    fragment = struct.unpack_from("!H", data, offset + 6)[0]
    if fragment & 0x1FFF:
        return None  # Non-initial fragments do not contain transport headers.
    protocol = data[offset + 9]
    src_ip = str(ipaddress.IPv4Address(data[offset + 12:offset + 16]))
    dst_ip = str(ipaddress.IPv4Address(data[offset + 16:offset + 20]))
    transport_offset = offset + ip_header_length
    packet_end = min(len(data), offset + total_length)
    tcp_flags = 0

    if protocol == 6:
        if packet_end < transport_offset + 20:
            return None
        src_port, dst_port = struct.unpack_from("!HH", data, transport_offset)
        tcp_header_length = (data[transport_offset + 12] >> 4) * 4
        if tcp_header_length < 20 or packet_end < transport_offset + tcp_header_length:
            return None
        tcp_flags = data[transport_offset + 13]
        payload_offset = transport_offset + tcp_header_length
        transport = "TCP"
    elif protocol == 17:
        if packet_end < transport_offset + 8:
            return None
        src_port, dst_port = struct.unpack_from("!HH", data, transport_offset)
        payload_offset = transport_offset + 8
        transport = "UDP"
    else:
        return None

    return PacketInfo(src_ip, dst_ip, src_port, dst_port, protocol, transport, payload_offset, tcp_flags)


def extract_tls_sni(payload: bytes) -> Optional[str]:
    """Extract the hostname extension from a TLS ClientHello when visible."""
    if len(payload) < 9 or payload[0] != 0x16:
        return None
    version = int.from_bytes(payload[1:3], "big")
    record_length = int.from_bytes(payload[3:5], "big")
    if not 0x0300 <= version <= 0x0304 or record_length > len(payload) - 5:
        return None
    if payload[5] != 0x01:  # ClientHello handshake
        return None

    handshake_length = int.from_bytes(payload[6:9], "big")
    end = min(len(payload), 9 + handshake_length)
    offset = 9
    # Client version + random
    if offset + 34 > end:
        return None
    offset += 34
    if offset >= end:
        return None
    session_length = payload[offset]
    offset += 1 + session_length
    if offset + 2 > end:
        return None
    cipher_length = int.from_bytes(payload[offset:offset + 2], "big")
    offset += 2 + cipher_length
    if offset >= end:
        return None
    compression_length = payload[offset]
    offset += 1 + compression_length
    if offset + 2 > end:
        return None
    extensions_length = int.from_bytes(payload[offset:offset + 2], "big")
    offset += 2
    extensions_end = min(end, offset + extensions_length)

    while offset + 4 <= extensions_end:
        extension_type = int.from_bytes(payload[offset:offset + 2], "big")
        extension_length = int.from_bytes(payload[offset + 2:offset + 4], "big")
        offset += 4
        extension_end = offset + extension_length
        if extension_end > extensions_end:
            return None
        if extension_type == 0:
            extension = payload[offset:extension_end]
            if len(extension) < 5:
                return None
            list_length = int.from_bytes(extension[:2], "big")
            if list_length < 3 or len(extension) < 2 + list_length:
                return None
            name_type = extension[2]
            name_length = int.from_bytes(extension[3:5], "big")
            if name_type != 0 or name_length > len(extension) - 5:
                return None
            try:
                return extension[5:5 + name_length].decode("ascii").lower()
            except UnicodeDecodeError:
                return None
        offset = extension_end
    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    """Return the HTTP Host header from an unencrypted HTTP request."""
    if not payload:
        return None
    first_line = payload[:16].upper()
    if not any(first_line.startswith(method) for method in (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS ")):
        return None
    header_end = payload.find(b"\r\n\r\n")
    headers = payload[:header_end if header_end >= 0 else min(len(payload), 8192)]
    for line in headers.split(b"\n")[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        if name.strip().lower() == b"host":
            host = value.strip().decode("latin-1", errors="replace").lower()
            if host.startswith("[") and "]" in host:
                host = host[1:host.index("]")]
            elif host.count(":") == 1:
                host = host.rsplit(":", 1)[0]
            return host or None
    return None


def classify_domain(domain: str) -> str:
    if not domain:
        return "Unknown"
    value = domain.lower()
    for app, patterns in APP_PATTERNS.items():
        if any(pattern in value for pattern in patterns):
            return app
    return "HTTPS"


class BlockingRules:
    def __init__(self, blocked_ips=(), blocked_apps=(), blocked_domains=(), blocked_ports=()):
        self.blocked_ips = set()
        for value in blocked_ips:
            self.add_ip(value)
        self.blocked_apps = set()
        for value in blocked_apps:
            self.add_app(value)
        self.blocked_domains = {value.strip().lower().rstrip('.') for value in blocked_domains}
        self.blocked_ports = set()
        for value in blocked_ports:
            port = int(value)
            if not 1 <= port <= 65535:
                raise ValueError(f"Invalid destination port: {port}")
            self.blocked_ports.add(port)

    def add_ip(self, value: str) -> None:
        self.blocked_ips.add(str(ipaddress.IPv4Address(value)))

    def add_app(self, value: str) -> None:
        normalized = value.strip().casefold()
        for app in VALID_APPS:
            if app.casefold() == normalized:
                self.blocked_apps.add(app)
                return
        raise ValueError(f"Unknown application '{value}'. Valid values include: {', '.join(sorted(VALID_APPS))}")

    def is_blocked(self, info: PacketInfo, flow: FlowState) -> bool:
        if info.src_ip in self.blocked_ips:
            return True
        if info.dst_port in self.blocked_ports:
            return True
        if flow.app in self.blocked_apps:
            return True
        domain = flow.domain.lower().rstrip('.')
        return any(fnmatch.fnmatchcase(domain, rule) or (not rule.startswith('*.') and rule in domain) for rule in self.blocked_domains)


class DPIEngine:
    def __init__(self, rules: BlockingRules, num_lbs: int = 2, fps_per_lb: int = 2, queue_size: int = 10000):
        if num_lbs < 1 or fps_per_lb < 1:
            raise ValueError("--lbs and --fps must both be at least 1.")
        self.rules = rules
        self.num_lbs = num_lbs
        self.fps_per_lb = fps_per_lb
        self.queue_size = max(1, queue_size)
        self.stats = Statistics()
        self.output_queue: queue.Queue = queue.Queue(self.queue_size)
        self.lb_queues = [queue.Queue(self.queue_size) for _ in range(num_lbs)]
        self.fp_queues = [queue.Queue(self.queue_size) for _ in range(num_lbs * fps_per_lb)]
        self.fp_flows = [{} for _ in self.fp_queues]
        self.writer_file: Optional[BinaryIO] = None

    def _writer(self):
        while True:
            item = self.output_queue.get()
            if item is None:
                return
            packet_header, data = item
            self.writer_file.write(packet_header)
            self.writer_file.write(data)

    def _load_balancer(self, lb_index: int):
        while True:
            item = self.lb_queues[lb_index].get()
            if item is None:
                base = lb_index * self.fps_per_lb
                for fp_index in range(base, base + self.fps_per_lb):
                    self.fp_queues[fp_index].put(None)
                return
            packet_header, data, info = item
            fp_index = lb_index * self.fps_per_lb + (hash(info.flow_key) % self.fps_per_lb)
            with self.stats.lock:
                self.stats.lb_counts[lb_index] += 1
            self.fp_queues[fp_index].put((packet_header, data, info))

    def _fast_path(self, fp_index: int):
        flows = self.fp_flows[fp_index]
        while True:
            item = self.fp_queues[fp_index].get()
            if item is None:
                return
            packet_header, data, info = item
            flow = flows.setdefault(info.flow_key, FlowState())
            flow.packets += 1
            flow.byte_count += len(data)
            payload = data[info.payload_offset:] if info.payload_offset < len(data) else b""

            if not flow.domain and info.transport == "TCP":
                if info.dst_port == 443 or info.src_port == 443:
                    domain = extract_tls_sni(payload)
                    if domain:
                        flow.domain = domain
                        flow.app = classify_domain(domain)
                elif info.dst_port == 80 or info.src_port == 80:
                    domain = extract_http_host(payload)
                    if domain:
                        flow.domain = domain
                        flow.app = classify_domain(domain)

            if flow.app == "Unknown" and (info.src_port == 53 or info.dst_port == 53):
                flow.app = "DNS"
            if flow.app == "Unknown":
                if info.transport == "UDP" and (info.src_port == 443 or info.dst_port == 443):
                    flow.app = "QUIC"
                elif info.src_port == 443 or info.dst_port == 443:
                    flow.app = "HTTPS"
                elif info.src_port == 80 or info.dst_port == 80:
                    flow.app = "HTTP"

            if not flow.blocked:
                flow.blocked = self.rules.is_blocked(info, flow)
                if flow.blocked:
                    detail = f" ({flow.app}"
                    if flow.domain:
                        detail += f": {flow.domain}"
                    print(f"[BLOCKED] {info.src_ip} -> {info.dst_ip}{detail})")

            with self.stats.lock:
                self.stats.fp_counts[fp_index] += 1
                self.stats.app_counts[flow.app] += 1
                if flow.domain:
                    self.stats.detected_domains[flow.domain] = flow.app
                if flow.blocked:
                    self.stats.dropped += 1
                else:
                    self.stats.forwarded += 1
                    self.output_queue.put((packet_header, data))

    def process_file(self, input_file: str, output_file: str) -> bool:
        reader = PcapReader(input_file)
        try:
            reader.open()
            with open(output_file, "wb") as output:
                output.write(reader.global_header)
                self.writer_file = output
                writer_thread = threading.Thread(target=self._writer, name="PCAP-writer")
                lb_threads = [
                    threading.Thread(target=self._load_balancer, args=(i,), name=f"LB-{i}")
                    for i in range(self.num_lbs)
                ]
                fp_threads = [
                    threading.Thread(target=self._fast_path, args=(i,), name=f"FP-{i}")
                    for i in range(self.num_lbs * self.fps_per_lb)
                ]
                writer_thread.start()
                for thread in fp_threads:
                    thread.start()
                for thread in lb_threads:
                    thread.start()

                print(f"[Reader] Processing packets with {self.num_lbs} load balancer(s) and "
                      f"{self.num_lbs * self.fps_per_lb} fast path worker(s)...")
                read_error = None
                try:
                    for packet_header, data in reader.packets():
                        info = parse_packet(data)
                        if info is None:
                            continue
                        with self.stats.lock:
                            self.stats.total_packets += 1
                            self.stats.total_bytes += len(data)
                            if info.transport == "TCP":
                                self.stats.tcp_packets += 1
                            else:
                                self.stats.udp_packets += 1
                        lb_index = hash(info.flow_key) % self.num_lbs
                        self.lb_queues[lb_index].put((packet_header, data, info))
                except (OSError, ValueError) as exc:
                    read_error = exc
                finally:
                    reader.close()

                # Always stop workers, even when the input capture is truncated.
                for work_queue in self.lb_queues:
                    work_queue.put(None)
                for thread in lb_threads:
                    thread.join()
                for thread in fp_threads:
                    thread.join()
                self.output_queue.put(None)
                writer_thread.join()
                if read_error is not None:
                    print(f"Error: {read_error}", file=sys.stderr)
                    return False
                self.stats.active_flows = sum(len(flows) for flows in self.fp_flows)
                self._print_report(output_file)
            return True
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            reader.close()
            return False

    def _print_report(self, output_file: str) -> None:
        stats = self.stats
        print("\n" + "=" * 62)
        print("                 DPI ENGINE - PROCESSING REPORT")
        print("=" * 62)
        print(f"Total Packets:       {stats.total_packets:>10}")
        print(f"Total Bytes:         {stats.total_bytes:>10}")
        print(f"TCP Packets:         {stats.tcp_packets:>10}")
        print(f"UDP Packets:         {stats.udp_packets:>10}")
        print(f"Forwarded:           {stats.forwarded:>10}")
        print(f"Dropped:             {stats.dropped:>10}")
        print(f"Active Flows:        {stats.active_flows:>10}")
        print("-" * 62)
        print("THREAD STATISTICS")
        for index in range(self.num_lbs):
            print(f"  LB{index} dispatched: {stats.lb_counts[index]}")
        for index in range(self.num_lbs * self.fps_per_lb):
            print(f"  FP{index} processed:  {stats.fp_counts[index]}")
        print("-" * 62)
        print("APPLICATION BREAKDOWN")
        for app, count in stats.app_counts.most_common():
            pct = 100.0 * count / stats.total_packets if stats.total_packets else 0.0
            print(f"  {app:<15} {count:>8}  {pct:5.1f}%  {'#' * int(pct / 5)}")
        if stats.detected_domains:
            print("\n[Detected Domains/SNIs]")
            for domain, app in sorted(stats.detected_domains.items()):
                print(f"  - {domain} -> {app}")
        print(f"\nOutput written to: {output_file}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DPI Engine - Deep Packet Inspection of classic PCAP captures",
        usage="%(prog)s <input.pcap> <output.pcap> [options]",
    )
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", help="Output PCAP file containing allowed packets")
    parser.add_argument("--block-ip", action="append", default=[], metavar="IP",
                        help="Block traffic from this source IPv4 address (repeatable)")
    parser.add_argument("--block-app", action="append", default=[], metavar="APP",
                        help="Block an application, for example YouTube (repeatable)")
    parser.add_argument("--block-domain", action="append", default=[], metavar="DOMAIN",
                        help="Block domains by exact name, wildcard, or substring (repeatable)")
    parser.add_argument("--block-port", action="append", default=[], type=int, metavar="PORT",
                        help="Block traffic with this destination port (repeatable)")
    parser.add_argument("--rules", metavar="FILE", help="Load rules from the original section-based format")
    parser.add_argument("--verbose", action="store_true", help="Print extra processing details")
    parser.add_argument("--lbs", type=int, default=2, help="Number of load balancer threads (default: 2)")
    parser.add_argument("--fps", type=int, default=2, help="Fast path workers per load balancer (default: 2)")
    parser.add_argument("--queue-size", type=int, default=10000, help="Maximum queued items per worker (default: 10000)")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if Path(args.input).resolve() == Path(args.output).resolve():
        parser.error("Input and output files must be different.")
    try:
        rule_ips, rule_apps, rule_domains, rule_ports = [], [], [], []
        if args.rules:
            section = ""
            with open(args.rules, encoding="utf-8") as rule_file:
                for raw_line in rule_file:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    if line.startswith("[") and line.endswith("]"):
                        section = line.upper()
                    elif section == "[BLOCKED_IPS]":
                        rule_ips.append(line)
                    elif section == "[BLOCKED_APPS]":
                        rule_apps.append(line)
                    elif section == "[BLOCKED_DOMAINS]":
                        rule_domains.append(line)
                    elif section == "[BLOCKED_PORTS]":
                        rule_ports.append(line)
        rules = BlockingRules(rule_ips + args.block_ip, rule_apps + args.block_app, rule_domains + args.block_domain, rule_ports + args.block_port)
        engine = DPIEngine(rules, args.lbs, args.fps, args.queue_size)
    except (ValueError, ipaddress.AddressValueError) as exc:
        parser.error(str(exc))
    print("\nDPI ENGINE - DEEP PACKET INSPECTION SYSTEM")
    print("=" * 48)
    for ip in args.block_ip:
        print(f"[Rules] Blocked IP: {ip}")
    for app in args.block_app:
        print(f"[Rules] Blocked app: {app}")
    for domain in args.block_domain:
        print(f"[Rules] Blocked domain: {domain}")
    for port in args.block_port:
        print(f"[Rules] Blocked destination port: {port}")
    if args.rules:
        print(f"[Rules] Loaded rules file: {args.rules}")
    return 0 if engine.process_file(args.input, args.output) else 1


if __name__ == "__main__":
    raise SystemExit(main())
