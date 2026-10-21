"""Bounded blocking queue used to connect reader, load balancers and workers."""
from collections import deque
from threading import Condition

class ThreadSafeQueue:
    def __init__(self,max_size=10000):
        if max_size < 1: raise ValueError("max_size must be positive")
        self.max_size=max_size; self._items=deque(); self._cv=Condition(); self._shutdown=False
    def push(self,item):
        with self._cv:
            self._cv.wait_for(lambda: len(self._items)<self.max_size or self._shutdown)
            if self._shutdown: return False
            self._items.append(item); self._cv.notify_all(); return True
    def try_push(self,item):
        with self._cv:
            if self._shutdown or len(self._items)>=self.max_size: return False
            self._items.append(item); self._cv.notify_all(); return True
    def pop(self,timeout=None):
        with self._cv:
            if not self._cv.wait_for(lambda: bool(self._items) or self._shutdown,timeout): return None
            if not self._items: return None
            item=self._items.popleft(); self._cv.notify_all(); return item
    def shutdown(self):
        with self._cv: self._shutdown=True; self._cv.notify_all()
    def empty(self):
        with self._cv: return not self._items
    def size(self):
        with self._cv: return len(self._items)
    def is_shutdown(self):
        with self._cv: return self._shutdown
