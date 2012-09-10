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

import logging

import dns.name
import dns.rdtypes.ANY.NS
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA

import utils.ipv6

logger = logging.getLogger('DNS.Filter.Delegation')


class Delegation:

    def __init__(self, zone, nameservers, ttl=7200, glue={}):
        self.zone = zone
        if type(zone) == str:
            self.zone = dns.name.from_text(zone)

        self.nameservers = []
        self.glue = {}
        self.ttl = ttl

        for ns in nameservers:
            self.nameservers.append(
                dns.rdtypes.ANY.NS.NS(
                    dns.rdataclass.IN,
                    dns.rdatatype.NS,
                    dns.name.from_text(ns)
                )
            )

        for name, addresses in self.glue.items():
            name = dns.name.from_text(name)
            self.glue[name] = []

            for address in addresses:
                if address.find(':') > 0:
                    self.glue[name].append(
                        dns.rdtypes.IN.AAAA.AAAA(
                            dns.rdataclass.IN,
                            dns.rdatatype.AAAA,
                            address
                        )
                    )
                else:
                    self.glue[name].append(
                        dns.rdtypes.IN.A.A(
                            dns.rdataclass.IN,
                            dns.rdatatype.A,
                            address
                        )
                    )

    def filter(self, request, response):
        if request.question[0].name.is_subdomain(self.zone):
            response = dns.message.make_response(request)

            nsRRset = response.find_rrset(
                response.answer,
                self.zone,
                self.nameservers[0].rdclass,
                self.nameservers[0].rdtype,
                self.nameservers[0].covers,
                None,
                True
            )

            for ns in self.nameservers:
                nsRRset.add(ns, self.ttl)

            for name, glue in self.glue:
                glueRRset = response.find_rrset(
                    response.additional,
                    name,
                    glue.rdclass,
                    glue.rdtype,
                    glue.covers,
                    None,
                    True
                )

                glueRRset.add(glue, self.ttl)

        return response

    def __eq__(self, other):
        return self.zone.__eq__(other)

    def __ne__(self, other):
        return self.zone.__ne__(other)

    def __lt__(self, other):
        return self.zone.__lt__(other)

    def __le__(self, other):
        return self.zone.__le__(other)

    def __ge__(self, other):
        return self.zone.__ge__(other)

    def __gt__(self, other):
        return self.zone.__gt__(other)


class ReverseIPv6Delegation(Delegation):

    def __init__(self, v6prefix, *args, **kwargs):
        zone = utils.ipv6.prefixToReverseName(v6prefix)

        super().__init__(zone, *args, **kwargs)
