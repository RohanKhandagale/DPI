"""Packet-summary CLI port of the original src/main.cpp."""
import argparse
import datetime
from .pcap_reader import PcapReader
from .packet_parser import parse_packet

def main(argv=None):
    parser=argparse.ArgumentParser(description="Packet Analyzer v1.0")
    parser.add_argument("pcap_file")
    parser.add_argument("max_packets",nargs="?",type=int,default=0)
    args=parser.parse_args(argv)
    count=errors=0
    print("="*36+"\n     Packet Analyzer v1.0\n"+"="*36)
    try:
        with PcapReader(args.pcap_file) as reader:
            for record in reader.packets():
                count+=1; data=record["data"]; info=parse_packet(data)
                ts=datetime.datetime.fromtimestamp(record["ts_sec"]).strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n========== Packet #{count} ==========\nTime: {ts}.{record['ts_frac']:06d}")
                if info is None:
                    print("[Packet] Unsupported or malformed Ethernet/IPv4/TCP/UDP packet")
                    errors+=1
                else:
                    print("\n[IPv4]\n  Source IP:      "+info.src_ip+"\n  Destination IP: "+info.dst_ip)
                    print(f"\n[{info.transport}]\n  Source Port:      {info.src_port}\n  Destination Port: {info.dst_port}")
                    payload=data[info.payload_offset:info.payload_offset+info.payload_length]
                    if payload: print(f"\n[Payload]\n  Length: {len(payload)} bytes\n  Preview: {payload[:32].hex(' ')}")
                if args.max_packets>0 and count>=args.max_packets:
                    print(f"\n(Stopped after {args.max_packets} packets)"); break
    except (OSError,ValueError) as exc:
        parser.exit(1,f"Error: {exc}\n")
    print(f"\n{'='*36}\nSummary:\n  Total packets read:  {count}\n  Parse errors:        {errors}\n{'='*36}")
    return 0
if __name__=="__main__": raise SystemExit(main())
