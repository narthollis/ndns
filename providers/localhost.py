import ipaddr

import dns.name
import dns.reversename
import dns.message
import dns.rdata

import dns.rdataclass
import dns.rdatatype

import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.NS
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA


from providers.null import NullProvider
import utils

'''
Localhost resolver.

Returns valid loopback responses
'''

class LocalhostProvider:
    
    zones = [
            dns.name.from_text('127.in-addr.arpa'),
            dns.name.from_text('::1'),
            dns.name.from_text('localhost'),
        ]
    
    def __init__(self):
        self.filters = [] 
        
    def getZones(self, clientaddress):
        return self.zones
    
    def getResponse(self, request, clientaddress):
        print(request)
        
        soa = dns.rdtypes.ANY.SOA.SOA(
                dns.rdataclass.IN,
                dns.rdatatype.SOA,
                dns.name.from_text('localhost.'),
                dns.name.from_text('hostmaster.localhost.'),
                2012082901,
                7200,
                1200,
                240000,
                700
            )
    
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.NXDOMAIN)
        
        rrSet = request.question[0]
    
        if rrSet.name.is_subdomain(self.zones[2]):
            if rrSet.rdtype == dns.rdatatype.SOA:
                response.set_rcode(dns.rcode.NOERROR)
                
                soaRRset = response.find_rrset(response.answer, dns.name.from_text('localhost.'), dns.rdataclass.IN, dns.rdatatype.SOA, soa.covers, None, True)
                soaRRset.add(soa, 7200)
            
            elif rrSet.rdtype == dns.rdatatype.A:
                response.set_rcode(dns.rcode.NOERROR)
                
                rdata = dns.rdtypes.IN.A.A(rrSet.rdclass, rrSet.rdtype, '127.0.0.1')
            
                responseRrSet = response.find_rrset(response.answer, rrSet.name, rrSet.rdclass, rrSet.rdtype, rdata.covers, None, True)
                responseRrSet.add(rdata, 1200)
                
               
            elif rrSet.rdtype == dns.rdatatype.AAAA:
                response.set_rcode(dns.rcode.NOERROR)
                
                rdata = dns.rdtypes.IN.AAAA.AAAA(rrSet.rdclass, rrSet.rdtype, '::1')
            
                responseRrSet = response.find_rrset(response.answer, rrSet.name, rrSet.rdclass, rrSet.rdtype, rdata.covers, None, True)
                responseRrSet.add(rdata, 1200)
                
            else:                
                soaRRset = response.find_rrset(response.authority, dns.name.from_text('localhost.'), dns.rdataclass.IN, dns.rdatatype.SOA, soa.covers, None, True)
                soaRRset.add(soa, 7200)
            
        return response
                
    def getFilters(self):
        return []
    
    def addFilter(self, f):
        self.filters.append(f)