"""Extract visible TLS SNI and HTTP Host values from packet payloads."""
import struct

def extract_http_host(payload):
    if not payload: return ""
    head=payload.split(b"\r\n\r\n",1)[0]
    if not (head.startswith(b"GET ") or head.startswith(b"POST ") or head.startswith(b"HEAD ") or head.startswith(b"PUT ") or head.startswith(b"CONNECT ") or head.startswith(b"DELETE ") or head.startswith(b"OPTIONS ")): return ""
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"host:"): return line.split(b":",1)[1].strip().decode("ascii","ignore").lower().rstrip(".")
    return ""

def extract_tls_sni(payload):
    try:
        if len(payload)<9 or payload[0]!=22: return ""
        rec_len=struct.unpack_from("!H",payload,3)[0]
        if len(payload)<5+rec_len or payload[5]!=1: return ""
        p=9; p+=2+32
        sid=payload[p]; p+=1+sid
        cs=struct.unpack_from("!H",payload,p)[0]; p+=2+cs
        comp=payload[p]; p+=1+comp
        if p+2>len(payload): return ""
        ext_end=p+2+struct.unpack_from("!H",payload,p)[0]; p+=2
        while p+4<=min(ext_end,len(payload)):
            typ,n=struct.unpack_from("!HH",payload,p); p+=4; e=p+n
            if e>len(payload): return ""
            if typ==0 and p+5<=e:
                q=p+2; name_type=payload[q]; q+=1; name_len=struct.unpack_from("!H",payload,q)[0]; q+=2
                if name_type==0 and q+name_len<=e: return payload[q:q+name_len].decode("idna","ignore").lower().rstrip(".")
            p=e
    except (IndexError,struct.error,ValueError): return ""
    return ""
