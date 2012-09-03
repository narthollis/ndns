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

import dns.name
import dns.rdatatype


logger = logging.getLogger('DNS.AutoRv6')


class ReverseIpv6:

    def __init__(self, basedomain, v6prefix):
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

    def getZones(self, clientaddress):
        return [self.zone, self.basedomain]

    def getResponse(self, request, clientaddress):
        response = dns.message.make_response(request)

        for question in request.question:
            if question.rdtype == dns.rdatatype.AAAA:
                pass

            elif question.rdtype == dns.rdatatype.PTR:
                pass

            elif question.rdtype == dns.rdatatype.NS:
                pass

            elif question.rdtype == dns.rdatatype.SOA:
                pass

            else:
                response.set_rcode(dns.rcode.NOTIMP)

        return response

    def getFilters(self):
        return []
