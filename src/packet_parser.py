"""Ethernet/VLAN/IPv4/TCP/UDP parser used by the DPI pipeline."""
import ipaddress, struct
from dataclasses import dataclass

@dataclass(frozen=True)
class ParsedPacket:
    src_ip:str; dst_ip:str; src_port:int; dst_port:int; protocol:int; transport:str
    ip_offset:int; transport_offset:int; payload_offset:int; payload_length:int; tcp_flags:int=0
    @property
    def five_tuple(self): return (self.src_ip,self.dst_ip,self.src_port,self.dst_port,self.protocol)

def parse_packet(data):
    if len(data)<14: return None
    off=14; et=struct.unpack_from("!H",data,12)[0]
    while et in (0x8100,0x88A8,0x9100):
        if len(data)<off+4: return None
        et=struct.unpack_from("!H",data,off+2)[0]; off+=4
    if et!=0x0800 or len(data)<off+20: return None
    ihl=(data[off]&15)*4
    if data[off]>>4!=4 or ihl<20 or len(data)<off+ihl: return None
    total=struct.unpack_from("!H",data,off+2)[0]
    if total<ihl: return None
    frag=struct.unpack_from("!H",data,off+6)[0]
    if frag&0x1fff: return None
    proto=data[off+9]; src=str(ipaddress.IPv4Address(data[off+12:off+16])); dst=str(ipaddress.IPv4Address(data[off+16:off+20]))
    tr=off+ihl; end=min(len(data),off+total); flags=0
    if proto==6:
        if end<tr+20: return None
        sp,dp=struct.unpack_from("!HH",data,tr); th=(data[tr+12]>>4)*4; flags=data[tr+13]
        if th<20 or end<tr+th: return None
        payload=tr+th; transport="TCP"
    elif proto==17:
        if end<tr+8: return None
        sp,dp,ulen,_=struct.unpack_from("!HHHH",data,tr)
        if ulen<8: return None
        payload=tr+8; transport="UDP"
    else: return None
    return ParsedPacket(src,dst,sp,dp,proto,transport,off,tr,payload,max(0,end-payload),flags)
