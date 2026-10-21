"""Flow-affine load balancer: packets from the same 5-tuple use one fast-path queue."""
import hashlib
from .thread_safe_queue import ThreadSafeQueue

class LoadBalancer:
    def __init__(self,lb_id,fp_queues):
        if not fp_queues: raise ValueError('at least one fast-path queue is required')
        self.lb_id=lb_id; self.fp_queues=fp_queues; self.packet_count=0
    def choose_queue(self,tuple_):
        raw='|'.join(map(str,tuple_ if isinstance(tuple_,(tuple,list)) else (tuple_.src_ip,tuple_.dst_ip,tuple_.src_port,tuple_.dst_port,tuple_.protocol))).encode()
        index=int.from_bytes(hashlib.blake2s(raw,digest_size=4).digest(),'big')%len(self.fp_queues)
        return index,self.fp_queues[index]
    def dispatch(self,tuple_,packet):
        _,q=self.choose_queue(tuple_); self.packet_count+=1; return q.push(packet)
