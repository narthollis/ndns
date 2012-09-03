
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

        return response

    def getFilters(self):
        return self.filters

    def addFilter(self, dnsfilter):
        self.filters.append(dnsfilter)
