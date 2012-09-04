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

        v6bits = list(v6prefix.replace(':', ''))
        v6bits.reverse()
        self.zone = dns.name.Name(v6bits + ['ipv6', 'arpa', ''])

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
            datetime.datetime.now().strftime('%Y%m%d00'),
            soa['refresh'],
            soa['retry'],
            soa['expire'],
            soa['minimum']
        )
        self.soaTtl = soa['ttl']

    def getZones(self, clientaddress):
        zones = [self.zone, self.basedomain]
        print(zones)
        return zones

    def getResponse(self, request, clientaddress):
        response = dns.message.make_response(request)

        for question in request.question:
            if question.rdtype == dns.rdatatype.AAAA:
                pass

            elif question.rdtype == dns.rdatatype.PTR:
                print(question)

            elif question.rdtype == dns.rdatatype.NS:
                response.find

            elif question.rdtype == dns.rdatatype.SOA:
                pass

            else:
                soaRRset = response.find_rrset(
                    response.authority,
                    self.soa.name,
                    self.soa.rdclass,
                    self.soa.rdtype,
                    soa.covers,
                    None,
                    True
                )
                soaRRset.add(soa, 7200)

                response.set_rcode(dns.rcode.NOTIMP)

        return response

    def getFilters(self):
        return []
