"""Classic PCAP reader/writer; supports both byte orders and timestamp precisions."""
import struct
from pathlib import Path

MAGIC={b"\xd4\xc3\xb2\xa1":("<",1_000_000),b"\xa1\xb2\xc3\xd4":(">",1_000_000),b"\x4d\x3c\xb2\xa1":("<",1_000_000_000),b"\xa1\xb2\x3c\x4d":(">",1_000_000_000)}
class PcapReader:
    def __init__(self,filename): self.filename=str(filename); self.file=None; self.endian="<"; self.precision=1_000_000; self.global_header=b""
    def open(self):
        self.file=open(self.filename,"rb"); self.global_header=self.file.read(24)
        if len(self.global_header)!=24 or self.global_header[:4] not in MAGIC:
            self.close(); raise ValueError("Not a supported classic PCAP file")
        self.endian,self.precision=MAGIC[self.global_header[:4]]; return self
    def packets(self):
        if self.file is None: raise RuntimeError("Call open() before packets()")
        unpack=struct.Struct(self.endian+"IIII").unpack
        while True:
            h=self.file.read(16)
            if not h: return
            if len(h)!=16: raise ValueError("Truncated PCAP packet header")
            sec,frac,inc,orig=unpack(h)
            if inc>64*1024*1024: raise ValueError("Unreasonable packet length")
            data=self.file.read(inc)
            if len(data)!=inc: raise ValueError("Truncated PCAP packet data")
            yield {"ts_sec":sec,"ts_frac":frac,"incl_len":inc,"orig_len":orig,"header":h,"data":data}
    def close(self):
        if self.file: self.file.close(); self.file=None
    def __enter__(self): return self.open()
    def __exit__(self,*exc): self.close()

def write_pcap(filename,global_header,packet_records):
    with open(filename,"wb") as f:
        f.write(global_header)
        for header,data in packet_records: f.write(header); f.write(data)
