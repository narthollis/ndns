import ipaddr

from providers.null import NullProvider
import utils

'''
Localhost resolver.

Returns valid loopback responses
'''

class LocalhostProvider(NullProvider):
    
    zones = [
            [b'127', b'in-addr', b'arpa'],
            [b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'ip6', b'arpa'],
            [b'localhost'],
            [b'localdomain']
        ]
    
    def __init__(self):
        self.filters = [] 
    
    def getNameServers(self, zone, clientaddress):
        return [
                ([b'localhost'], ipaddr.IPv4Address('127.0.0.1'), 1200),
                ([b'localhost'], ipaddr.IPv6Address('::1'), 1200)
            ]
    
    def getZones(self, clientaddress):
        return self.zones
    
    def getResponse(self, query, zone, qtype, qclass, clientaddress):
        ret = (3,[])
    
        if zone == self.zones[2]:
            if qtype == 1:
                ret = (0, [{'qtype': qtype, 'qclass':qclass, 'ttl': 1200, 'rdata': ipaddr.IPv4Address('127.0.0.1').packed}])
            elif qtype == 2:
                ret = (0, [{'qtype': qtype, 'qclass':qclass, 'ttl': 1200, 'rdata': utils.labels2str(b'localhost'.split(b'.'))}])
            elif qtype == 28:
                ret = (0, [{'qtype': qtype, 'qclass':qclass, 'ttl': 1200, 'rdata': ipaddr.IPv6Address('::1').packed}])
            else:
                ret = (4, [])
        return ret
    
    def getFilters(self):
        return []
    
    def addFilter(self, f):
        self.filters.append(f)