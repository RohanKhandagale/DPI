"""Thread-safe IP/application/domain/port blocking rules with JSON persistence."""
import ipaddress, json, fnmatch
from threading import RLock

class RuleManager:
    def __init__(self): self._lock=RLock(); self.ips=set(); self.apps=set(); self.domains=set(); self.ports=set()
    def block_ip(self,ip):
        value=str(ipaddress.ip_address(ip));
        with self._lock: self.ips.add(value)
    def unblock_ip(self,ip):
        with self._lock: self.ips.discard(str(ipaddress.ip_address(ip)))
    def block_app(self,app):
        with self._lock: self.apps.add(str(app).casefold())
    def unblock_app(self,app):
        with self._lock: self.apps.discard(str(app).casefold())
    def block_domain(self,domain):
        d=domain.strip().lower().rstrip('.')
        if not d: raise ValueError('domain cannot be empty')
        with self._lock: self.domains.add(d)
    def unblock_domain(self,domain):
        with self._lock: self.domains.discard(domain.strip().lower().rstrip('.'))
    def block_port(self,port):
        p=int(port)
        if not 1<=p<=65535: raise ValueError('port must be between 1 and 65535')
        with self._lock: self.ports.add(p)
    def unblock_port(self,port):
        with self._lock: self.ports.discard(int(port))
    def should_block(self,src_ip,dst_port,app='Unknown',domain=''):
        d=(domain or '').lower().rstrip('.'); a=str(app).casefold()
        with self._lock:
            if src_ip in self.ips: return ('IP',src_ip)
            if int(dst_port) in self.ports: return ('PORT',str(dst_port))
            if a in self.apps: return ('APP',str(app))
            for pat in self.domains:
                if fnmatch.fnmatchcase(d,pat) or (not pat.startswith('*.') and d==pat): return ('DOMAIN',pat)
        return None
    def save_rules(self,path):
        with self._lock: data={'ips':sorted(self.ips),'apps':sorted(self.apps),'domains':sorted(self.domains),'ports':sorted(self.ports)}
        with open(path,'w',encoding='utf-8') as f: json.dump(data,f,indent=2)
    def load_rules(self,path):
        with open(path,encoding='utf-8') as f: data=json.load(f)
        for x in data.get('ips',[]): self.block_ip(x)
        for x in data.get('apps',[]): self.block_app(x)
        for x in data.get('domains',[]): self.block_domain(x)
        for x in data.get('ports',[]): self.block_port(x)
    def clear_all(self):
        with self._lock: self.ips.clear(); self.apps.clear(); self.domains.clear(); self.ports.clear()
    def stats(self):
        with self._lock: return {'blocked_ips':len(self.ips),'blocked_apps':len(self.apps),'blocked_domains':len(self.domains),'blocked_ports':len(self.ports)}
