"""Shared data types for the Python DPI implementation."""
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter
from threading import Lock
from typing import Optional

class AppType(str, Enum):
    UNKNOWN="Unknown"; HTTP="HTTP"; HTTPS="HTTPS"; DNS="DNS"; TLS="TLS"; QUIC="QUIC"
    GOOGLE="Google"; FACEBOOK="Facebook"; YOUTUBE="YouTube"; TWITTER="Twitter/X"; INSTAGRAM="Instagram"
    NETFLIX="Netflix"; AMAZON="Amazon"; MICROSOFT="Microsoft"; APPLE="Apple"; WHATSAPP="WhatsApp"
    TELEGRAM="Telegram"; TIKTOK="TikTok"; SPOTIFY="Spotify"; ZOOM="Zoom"; DISCORD="Discord"; GITHUB="GitHub"; CLOUDFLARE="Cloudflare"

class ConnectionState(str, Enum):
    NEW="new"; ESTABLISHED="established"; CLASSIFIED="classified"; BLOCKED="blocked"; CLOSED="closed"
class PacketAction(str, Enum):
    FORWARD="forward"; DROP="drop"; INSPECT="inspect"; LOG_ONLY="log-only"

@dataclass(frozen=True)
class FiveTuple:
    src_ip: str; dst_ip: str; src_port: int; dst_port: int; protocol: int
    def reverse(self): return FiveTuple(self.dst_ip,self.src_ip,self.dst_port,self.src_port,self.protocol)
    def __str__(self): return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} (proto={self.protocol})"

@dataclass
class Connection:
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets_in: int = 0; packets_out: int = 0; bytes_in: int = 0; bytes_out: int = 0
    action: PacketAction = PacketAction.FORWARD
    syn_seen: bool = False; syn_ack_seen: bool = False; fin_seen: bool = False

@dataclass
class PacketJob:
    packet_id: int
    tuple: FiveTuple
    data: bytes
    eth_offset: int = 0; ip_offset: int = 14; transport_offset: int = 34; payload_offset: int = 54
    payload_length: int = 0; tcp_flags: int = 0; ts_sec: int = 0; ts_usec: int = 0

@dataclass
class DPIStats:
    total_packets: int=0; total_bytes: int=0; forwarded_packets: int=0; dropped_packets: int=0
    tcp_packets: int=0; udp_packets: int=0; other_packets: int=0; active_connections: int=0
    app_counts: Counter=field(default_factory=Counter)
    _lock: Lock=field(default_factory=Lock,repr=False)
    def increment(self, field_name, amount=1):
        with self._lock: setattr(self,field_name,getattr(self,field_name)+amount)
