"""Fast-path packet inspection and decision helpers."""
from .packet_parser import parse_packet
from .sni_extractor import extract_http_host, extract_tls_sni
from .rule_manager import RuleManager

class FastPathProcessor:
    def __init__(self,fp_id,rule_manager=None): self.fp_id=fp_id; self.rules=rule_manager or RuleManager(); self.packets_processed=0; self.packets_forwarded=0; self.packets_dropped=0
    def inspect(self,raw_packet):
        self.packets_processed+=1; info=parse_packet(raw_packet)
        if info is None: self.packets_forwarded+=1; return {'action':'forward','packet':None,'domain':'','app':'Unknown','reason':None}
        payload=raw_packet[info.payload_offset:info.payload_offset+info.payload_length]
        domain=extract_tls_sni(payload) or extract_http_host(payload)
        app='Unknown'
        if domain:
            d=domain.lower()
            for name,patterns in {'YouTube':('youtube','ytimg','youtu.be'),'Google':('google','gstatic'),'Facebook':('facebook','fbcdn'),'Instagram':('instagram','cdninstagram'),'WhatsApp':('whatsapp','wa.me'),'Netflix':('netflix','nflx'),'TikTok':('tiktok','bytedance'),'GitHub':('github',)}.items():
                if any(p in d for p in patterns): app=name; break
            if app=='Unknown': app='HTTPS' if payload[:1]==b'\x16' else 'HTTP'
        elif info.dst_port==53 or info.src_port==53: app='DNS'
        elif info.dst_port==443 and info.transport=='UDP': app='QUIC'
        elif info.dst_port==443: app='HTTPS'
        elif info.dst_port==80: app='HTTP'
        reason=self.rules.should_block(info.src_ip,info.dst_port,app,domain)
        action='drop' if reason else 'forward'
        if reason: self.packets_dropped+=1
        else: self.packets_forwarded+=1
        return {'action':action,'packet':info,'domain':domain,'app':app,'reason':reason}
