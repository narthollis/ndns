# Copyright (c) 2011 Robert Mibus & Internode
#		Modified for ndns by Nicholas Steicke
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
#     The above copyright notice and this permission notice shall be
#     included in all copies or substantial portions of the Software.
#
#     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT


#
# A pymds source filter.
#
# pymdsautogen makes stuff up on the fly
#
# initializer: a "base domain" under which AAAA records go, and an IPv6 prefix
# (for which PTR records work).
#

import logging
import datetime

import dns.name
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.PTR
import dns.rdtypes.IN.AAAA
import dns.rdataclass
import dns.rdatatype


logger = logging.getLogger('DNS.AutoRv6')


class ReverseIpv6:

    def __init__(self, basedomain, v6prefix, soa, nameservers):
        logger.info('Serving auto generated reveser zone {} for {}'.format(
            v6prefix,
            basedomain
        ))

        self._answers = {}
        self.basedomain = dns.name.from_text(basedomain)
        self.v6prefix = v6prefix

        v6bits = v6prefix.strip(':').split(':')
        v6bits = [x.rjust(4, '0') for x in v6bits]
        v6bits = list(''.join(v6bits))
        v6bits.reverse()
        self.zone = dns.name.Name(v6bits + ['ip6', 'arpa', ''])

        self.nameservers = []
        for nameserver in nameservers:
            self.nameservers.append(
                dns.rdtypes.ANY.NS.NS(
                    dns.rdataclass.IN,
                    dns.rdatatype.NS,
                    dns.name.from_text(nameserver)
                )
            )

        self.soa = dns.rdtypes.ANY.SOA.SOA(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            dns.name.from_text(soa['ns']),
            dns.name.from_text(soa['contact']),
            int(datetime.datetime.now().strftime('%Y%m%d00')),
            soa['refresh'],
            soa['retry'],
            soa['expire'],
            soa['minimum']
        )
        self.soaTtl = soa['ttl']

    def getZones(self, clientaddress):
        zones = [self.zone, self.basedomain]
        return zones

    def getResponse(self, request, clientaddress):
        response = dns.message.make_response(request)

        for question in request.question:
            zone = None
            if question.name.is_subdomain(self.zone):
                zone = self.zone
            else:
                zone = self.basedomain

            if (question.rdtype == dns.rdatatype.AAAA
                    or question.rdtype == dns.rdatatype.ANY) \
                    and zone == self.basedomain:
                v6bits = self.v6prefix.strip(':').split(':')
                v6bits = [x.rjust(4, '0').encode() for x in v6bits]

                questionBits = question.name.labels[0].split(b'-')
                if questionBits[:len(v6bits)] == v6bits:
                    aaaa = dns.rdtypes.IN.AAAA.AAAA(
                        dns.rdataclass.IN,
                        dns.rdatatype.AAAA,
                        (b':'.join(questionBits)).decode('UTF-8')
                    )

                    aaaaRRset = response.find_rrset(
                        response.answer,
                        question.name,
                        aaaa.rdclass,
                        aaaa.rdtype,
                        aaaa.covers,
                        None,
                        True
                    )

                    aaaaRRset.add(aaaa, self.soaTtl)

                else:
                    response.set_rcode(dns.rcode.NXDOMAIN)

            elif (question.rdtype == dns.rdatatype.PTR
                    or question.rdtype == dns.rdatatype.ANY) \
                    and zone == self.zone:
                subdomain = list(question.name.labels[:-3])
                subdomain.reverse()  # cause, you know PRT is backwards
                subdomain = b''.join(subdomain)
                subdomain = [
                    subdomain[i:i + 4] for i in range(0, len(subdomain), 4)
                ]
                subdomain = b'-'.join(subdomain)

                ptr = dns.rdtypes.ANY.PTR.PTR(
                    question.rdclass,
                    dns.rdatatype.PTR,
                    dns.name.Name([subdomain] + list(self.basedomain.labels))
                )

                ptrRRset = response.find_rrset(
                    response.answer,
                    question.name,
                    ptr.rdclass,
                    ptr.rdtype,
                    ptr.covers,
                    None,
                    True
                )

                ptrRRset.add(ptr, self.soaTtl)

                nsRRset = response.find_rrset(
                    response.authority,
                    zone,
                    self.nameservers[0].rdclass,
                    self.nameservers[0].rdtype,
                    self.nameservers[0].covers,
                    None,
                    True
                )

                for ns in self.nameservers:
                    nsRRset.add(ns, self.soaTtl)

            elif question.rdtype == dns.rdatatype.NS:
                nsRRset = response.find_rrset(
                    response.answer,
                    zone,
                    self.nameservers[0].rdclass,
                    self.nameservers[0].rdtype,
                    self.nameservers[0].covers,
                    None,
                    True
                )
                for ns in self.nameservers:
                    nsRRset.add(ns, self.soaTtl)

            elif question.rdtype == dns.rdatatype.SOA:
                soaRRset = response.find_rrset(
                    response.answer,
                    zone,
                    self.soa.rdclass,
                    self.soa.rdtype,
                    self.soa.covers,
                    None,
                    True
                )
                soaRRset.add(self.soa, self.soaTtl)

            else:
                soaRRset = response.find_rrset(
                    response.authority,
                    zone,
                    self.soa.rdclass,
                    self.soa.rdtype,
                    self.soa.covers,
                    None,
                    True
                )
                soaRRset.add(self.soa, self.soaTtl)

                response.set_rcode(dns.rcode.NOTIMP)

        return response

    def getFilters(self):
        return []
