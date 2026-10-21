"""Thread-safe bidirectional flow table with connection counters and expiry."""
from threading import RLock
from time import monotonic
from .types import Connection, ConnectionState, FiveTuple

class ConnectionTracker:
    def __init__(self,timeout_seconds=300): self.timeout=timeout_seconds; self._lock=RLock(); self._flows={}
    def get_or_create(self,tuple_):
        now=monotonic()
        with self._lock:
            key=tuple_
            reverse=tuple_.reverse()
            c=self._flows.get(key) or self._flows.get(reverse)
            if c is None:
                c=Connection(tuple_); c.first_seen=now; c.last_seen=now
                self._flows[key]=c
            c.last_seen=now
            return c
    def update(self,tuple_,byte_count=0,direction='in'):
        c=self.get_or_create(tuple_)
        with self._lock:
            if direction=='in': c.packets_in+=1; c.bytes_in+=byte_count
            else: c.packets_out+=1; c.bytes_out+=byte_count
            if c.state==ConnectionState.NEW: c.state=ConnectionState.ESTABLISHED
        return c
    def cleanup_expired(self):
        now=monotonic()
        with self._lock:
            expired=[k for k,v in self._flows.items() if getattr(v,'last_seen',None) is not None and now-v.last_seen>self.timeout]
            for k in expired: del self._flows[k]
            return len(expired)
    def snapshot(self):
        with self._lock: return list(self._flows.values())
    def size(self):
        with self._lock: return len(self._flows)
