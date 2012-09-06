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
import dns.zone
import dns.message
import dns.rdatatype

"""
This is a very basic dns provider that reads a zone file and
loads it into memory.
"""

logger = logging.getLogger('DNS.File')


class FileProvider:
    def __init__(self, file, zone):
        logger.info("Serving zone '{}' from '{}'".format(zone, file))

        self.zone = dns.name.from_text(zone)
        self.data = dns.zone.from_file(
            file,
            origin=zone,
            relativize=False
        )

        self.filters = []

    def getZones(self, clientaddress):
        return [self.zone]

    def getRdatasetWildcardRecursion(self, name, rdtype, first=True):
        try:
            rdataset = self.data.find_rdataset(
                name,
                rdtype
            )
        except KeyError as e:
            if name.is_wild():
                name = name.parent()
            name.relativize(self.zone)
            if not first:
                name = name.parent()
            name = dns.name.Name(['*']).concatenate(name)

            rdataset = self.getRdatasetWildcardRecursion(name, rdtype, False)

        return rdataset

    def getResponse(self, request, clientaddress):
        response = dns.message.make_response(request)

        for question in response.question:
            rdtypes = [question.rdtype]

            if question.rdtype == dns.rdatatype.ANY:
                rdtypes = dns.rdatatype._by_value.keys()

            for rdtype in rdtypes:
                try:
                    rdataset = self.getRdatasetWildcardRecursion(
                        question.name,
                        rdtype
                    )

                    rrset = response.find_rrset(
                        response.answer,
                        question.name,
                        rdataset.rdclass,
                        rdataset.rdtype,
                        rdataset.covers,
                        None,
                        True
                    )

                    for item in rdataset:
                        rrset.add(item, rdataset.ttl)

                except (KeyError, dns.name.NoParent) as e:
                    pass

        if len(response.answer) <= 1:
            response.set_rcode(dns.rcode.NXDOMAIN)

            rdataset = self.getRdatasetWildcardRecursion(
                self.zone,
                dns.rdatatype.SOA
            )

            rrset = response.find_rrset(
                response.authority,
                self.zone,
                rdataset.rdclass,
                rdataset.rdtype,
                rdataset.covers,
                None,
                True
            )

            for item in rdataset:
                rrset.add(item, rdataset.ttl)

        return response

    def getFilters(self):
        return self.filters

    def addFilter(self, dnsfilter):
        self.filters.append(dnsfilter)
