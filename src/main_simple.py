"""Single-threaded SNI inspection CLI port of the original src/main_simple.cpp."""
import argparse
from .pcap_reader import PcapReader
from .packet_parser import parse_packet
from .sni_extractor import extract_tls_sni

def main(argv=None):
    parser=argparse.ArgumentParser(description="Simple DPI/SNI analyzer")
    parser.add_argument("pcap_file")
    args=parser.parse_args(argv)
    count=sni_count=0
    try:
        with PcapReader(args.pcap_file) as reader:
            print("Processing packets...")
            for record in reader.packets():
                count+=1; data=record["data"]; info=parse_packet(data)
                if info is None: continue
                line=f"Packet {count}: {info.src_ip}:{info.src_port} -> {info.dst_ip}:{info.dst_port}"
                if info.transport=="TCP" and info.dst_port==443 and info.payload_length:
                    payload=data[info.payload_offset:info.payload_offset+info.payload_length]
                    sni=extract_tls_sni(payload)
                    if sni: line+=f" [SNI: {sni}]"; sni_count+=1
                print(line)
    except (OSError,ValueError) as exc:
        parser.exit(1,f"Error: {exc}\n")
    print(f"\nTotal packets: {count}\nSNI extracted: {sni_count}")
    return 0
if __name__=="__main__": raise SystemExit(main())
