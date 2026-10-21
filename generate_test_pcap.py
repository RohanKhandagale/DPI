#!/usr/bin/env python3
"""Create a small synthetic PCAP file for testing the DPI engine.

The packets are generated locally and do not contain real user traffic.
"""
from __future__ import annotations

import argparse
import ipaddress
import struct
from pathlib import Path


def ethernet_ipv4(src_ip: str, dst_ip: str, protocol: int, payload: bytes, ident: int) -> bytes:
    destination_mac = bytes.fromhex("001122334455")
    source_mac = bytes.fromhex("aabbccddeeff")
    eth = destination_mac + source_mac + struct.pack("!H", 0x0800)
    src = ipaddress.IPv4Address(src_ip).packed
    dst = ipaddress.IPv4Address(dst_ip).packed
    total_length = 20 + len(payload)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length, ident, 0x4000, 64, protocol, 0, src, dst)
    return eth + ip_header + payload


def tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, ident: int) -> bytes:
    flags = 0x18 if payload else 0x02
    tcp_header = struct.pack("!HHIIHHHH", src_port, dst_port, ident * 100, 0, (5 << 12) | flags, 65535, 0, 0)
    return ethernet_ipv4(src_ip, dst_ip, 6, tcp_header + payload, ident)


def udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, ident: int) -> bytes:
    udp_header = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return ethernet_ipv4(src_ip, dst_ip, 17, udp_header + payload, ident)


def tls_client_hello(hostname: str) -> bytes:
    name = hostname.encode("ascii")
    server_name = struct.pack("!H", 3 + len(name)) + b"\x00" + struct.pack("!H", len(name)) + name
    sni_extension = struct.pack("!HH", 0, len(server_name)) + server_name
    extensions = sni_extension
    body = (
        b"\x03\x03" + bytes(range(32)) +
        b"\x00" +
        b"\x00\x02\x13\x01" +
        b"\x01\x00" +
        struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def create_capture(filename: str) -> int:
    packets = [
        tcp_packet("192.168.1.50", "142.250.72.14", 51001, 443, tls_client_hello("www.youtube.com"), 1),
        tcp_packet("192.168.1.51", "157.240.20.35", 51002, 443, tls_client_hello("www.facebook.com"), 2),
        tcp_packet("192.168.1.52", "93.184.216.34", 51003, 80,
                   b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: DPI-Test\r\n\r\n", 3),
        udp_packet("192.168.1.53", "8.8.8.8", 53000, 53,
                   b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01", 4),
        tcp_packet("192.168.1.54", "23.45.67.89", 51004, 443, tls_client_hello("www.tiktok.com"), 5),
        udp_packet("192.168.1.55", "1.1.1.1", 55000, 443, b"\xc0\x00\x00\x00\x01", 6),
    ]
    output = Path(filename)
    # Classic PCAP, little-endian, microsecond timestamps, Ethernet link type.
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    with output.open("wb") as handle:
        handle.write(global_header)
        for index, packet in enumerate(packets, start=1):
            handle.write(struct.pack("<IIII", 1_700_000_000 + index, index * 1000, len(packet), len(packet)))
            handle.write(packet)
    return len(packets)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic PCAP capture for DPI testing.")
    parser.add_argument("-o", "--output", default="test_dpi.pcap", help="Output PCAP filename")
    args = parser.parse_args()
    count = create_capture(args.output)
    print(f"Created {args.output} with {count} synthetic packets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
