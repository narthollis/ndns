"""
Copyright (c) 2012, Nicholas Steicke
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies,
either expressed or implied, of the project author/s.
"""

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

                soaRRset = response.find_rrset(
                    response.answer,
                    dns.name.from_text('localhost.'),
                    dns.rdataclass.IN,
                    dns.rdatatype.SOA,
                    soa.covers,
                    None,
                    True
                )
                soaRRset.add(soa, 7200)

            elif rrSet.rdtype == dns.rdatatype.NS:
                response.set_rcode(dns.rcode.NOERROR)

                rdata = dns.tdtypes.ANY.NS.NS(
                    rrSet.rdclass,
                    rrSet.rdtype,
                    dns.name.from_text('localhost.')
                )

                responseRrSet = response.find_rrset(
                    response.answer,
                    rrSet.name,
                    rrSet.rdclass,
                    rrSet.rdtype,
                    rdata.covers,
                    None,
                    True
                )
                responseRrSet.add(rdata, 1200)

                additionalRdata = dns.rdtypes.IN.A.A(
                    rrSet.rdclass,
                    rrSet.rdtype,
                    '127.0.0.1'
                )
                additionalRrSet = response.find_rrset(
                    response.additional,
                    rrSet.name,
                    rrSet.rdclass,
                    rrSet.rdtype,
                    rdata.covers,
                    None,
                    True
                )

            elif rrSet.rdtype == dns.rdatatype.A:
                response.set_rcode(dns.rcode.NOERROR)

                rdata = dns.rdtypes.IN.A.A(
                    rrSet.rdclass,
                    rrSet.rdtype,
                    '127.0.0.1'
                )

                responseRrSet = response.find_rrset(
                    response.answer,
                    rrSet.name,
                    rdata.rdclass,
                    rdata.rdtype,
                    rdata.covers,
                    None,
                    True
                )
                responseRrSet.add(rdata, 1200)

            elif rrSet.rdtype == dns.rdatatype.AAAA:
                response.set_rcode(dns.rcode.NOERROR)

                rdata = dns.rdtypes.IN.AAAA.AAAA(
                    rrSet.rdclass,
                    rrSet.rdtype,
                    '::1'
                )

                responseRrSet = response.find_rrset(
                    response.answer,
                    rrSet.name,
                    rrSet.rdclass,
                    rrSet.rdtype,
                    rdata.covers,
                    None,
                    True
                )
                responseRrSet.add(rdata, 1200)

            else:
                soaRRset = response.find_rrset(
                    response.authority,
                    dns.name.from_text('localhost.'),
                    dns.rdataclass.IN,
                    dns.rdatatype.SOA,
                    soa.covers,
                    None,
                    True
                )
                soaRRset.add(soa, 7200)

        return response

    def getFilters(self):
        return []

    def addFilter(self, f):
        self.filters.append(f)
