#!/usr/bin/python3

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

import struct
import socket
import select
import queue
import threading
import logging

import dns
import dns.message

import utils

logger = logging.getLogger('DNS')


class DnsError(Exception):

    def __init__(self, message, rcode=None, *args, **kwargs):
        self.rcode = rcode
        self.message = message


class DnsRequestHandler(threading.Thread):

    def __init__(self, ndns, request, isUdp, clientaddress):
        self.raw_request = request
        self.ndns = ndns
        self.isUdp = isUdp
        self.clientaddress = clientaddress

        super().__init__()

    def run(self):
        request = dns.message.from_wire(self.raw_request, question_only=True)
        response = dns.message.make_response(request)

        bestFitProvider = None
        bestFitProviderDetails = None

        name = request.question[0].name

        found = False
        for provider in self.ndns.getProviders():
            for zone in provider.getZones(self.clientaddress):
                compare = name.fullcompare(zone)

                if compare[0] == dns.name.NAMERELN_EQUAL:
                    bestFitProvider = provider
                    bestFitProviderDetails = compare
                    found = True
                    break
                elif compare[0] == dns.name.NAMERELN_SUBDOMAIN:
                    if bestFitProvider is None:
                        bestFitProvider = provider
                        bestFitProviderDetails = compare
                    elif compare[1] < bestFitProviderDetails[1]:
                        bestFitProvider = provider
                        bestFitProviderDetails = compare
            if found:
                break

        if bestFitProvider is not None:
            resp = bestFitProvider.getResponse(request, self.clientaddress)
            if resp is not None:
                for f in bestFitProvider.getFilters():
                    resp = f.filter(request, resp)

                response = resp
        else:
            response.set_rcode(dns.rcode.NXDOMAIN)

        if self.isUdp:
            self.ndns.udpOut.put((response.to_wire(), self.clientaddress))
        else:
            data = response.to_wire()
            self.ndns.tcpOut[self.clientaddress].put(
                struct.pack('!H', len(data)) + data
            )


class Ndns:
    '''
    classdocs
    '''

    def __init__(self, host='::', port=53):
        '''
        Constructor
        '''

        self.host = host
        self.port = port

        self.tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

        try:
            self.udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            self.tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except AttributeError:
            pass

        self.udp.setblocking(False)
        self.tcp.setblocking(False)

        self.clients = {}
        self.tcpOut = {}
        self.udpOut = queue.Queue()
        self.tcpIn = {}

        self.running = True

        self.providers = []

    def registerProvider(self, provider):
        self.providers.append(provider)

    def getProviders(self):
        return self.providers

    def run(self):

        logger.info('Bind and Listen')

        self.udp.bind((self.host, self.port))

        self.tcp.bind((self.host, self.port))
        self.tcp.listen(5)

        logger.info('Starting Main Loop')

        inputs = {}
        outputs = {}

        while self.running:
            ins = list(inputs.values()) + [self.udp, self.tcp]
            outs = list(outputs.values()) + [self.udp, self.tcp]
            try:
                (rlist, wlist, xlist) = select.select(ins, outs, [])

                del xlist

                for s in rlist:
                    if s == self.udp:
                        # Max UDP DNS packet size
                        data, clientaddress = s.recvfrom(512)

                        if not data:
                            continue

                        handler = DnsRequestHandler(
                            self,
                            data,
                            s == self.udp,
                            clientaddress
                        )

                        handler.start()

                        logger.info('Received UDP from %s' % (clientaddress, ))

                    elif s == self.tcp:
                        conn, clientaddress = s.accept()
                        inputs[clientaddress] = conn
                        outputs[clientaddress] = conn
                        self.tcpOut[clientaddress] = queue.Queue()
                        self.tcpIn[clientaddress] = None

                        logger.info('Accepted TCP from %s' % (clientaddress, ))

                    else:
                        # http://www.ietf.org/rfc/rfc1035.txt
                        # 4.2.2.

                        data = s.recv(1024)
                        caddr = s.getpeername()

                        if not data:
                            logger.debug(
                                'Closing connection %s' % (s.getpeername(), )
                            )

                            del inputs[caddr]
                            del outputs[caddr]
                            del self.tcpOut[caddr]
                            del self.tcpIn[caddr]
                            s.close()
                        else:
                            if self.tcpIn[caddr] is None:
                                length = struct.unpack('!H', data[:2])[0]
                                data = data[2:]

                                self.tcpIn[caddr] = {
                                    'length': length,
                                    'buff': b''
                                }

                            self.tcpIn[caddr]['buff'] += data

                            if len(self.tcpIn[caddr]['buff']) == \
                                    self.tcpIn[caddr]['length']:

                                logger.debug(
                                    'Got data from %s' % (s.getpeername(), )
                                )

                                handler = DnsRequestHandler(
                                    self,
                                    data,
                                    False,
                                    s.getpeername()
                                )

                                handler.start()

                for s in wlist:
                    if s == self.udp:
                        if not self.udpOut.empty():
                            s.sendto(*self.udpOut.get())
                    elif s == self.tcp:
                        pass
                    else:
                        clientaddress = s.getpeername()
                        if clientaddress in self.tcpOut:
                            if not self.tcpOut[clientaddress].empty():
                                s.send(self.tcpOut[clientaddress].get())

                                del inputs[clientaddress]
                                del outputs[clientaddress]
                                del self.tcpOut[clientaddress]
                                s.close()

            except KeyboardInterrupt:
                self.running = False
            except Exception as e:
                self.running = False

        self.tcp.close()
        self.udp.close()

if __name__ == "__main__":

    logFormat = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
    )

    logConsole = logging.StreamHandler()
    logConsole.setLevel(logging.DEBUG)
    logConsole.setFormatter(logFormat)

    logger.setLevel(logging.DEBUG)
    logger.addHandler(logConsole)

    from providers import file
    from providers import reverseipv6
    from filters import delegation
    import os.path
    import sys

    s = Ndns('::', int(sys.argv[1]))
    path = os.path.join(
        os.path.dirname(__file__),
        'providers' + os.sep + 'example.txt'
    )

    ns = ['localhost.', 'ns0.localhost.', 'ns1.localhost.']

    soa = {
        'ns': ns[0],
        'contact': 'hostmaster.example.',
        'refresh': 7200,
        'retry': 600,
        'expire': 36000,
        'minimum': 300,
        'ttl': 7200
    }

    v6revLookup = reverseipv6.AutoReverseIpv6(
        'v6.example.',
        '2001:44b8:236:8f00::',
        soa,
        ns
    )

    v6revLookup.addFilter(delegation.ReverseIPv6Delegation(
        '2001:44b8:236:8f00:0000::',
        ns,
        ttl=7200,
        glue={'localhost.': ['::1']}
    ))

    v6revLookup.addFilter(delegation.ReverseIPv6Delegation(
        '2001:44b8:236:8f00:0000:0000::',
        ['agasgasg.', 'fsadfsafsd.'],
        ttl=7200,
        glue={}
    ))

    s.registerProvider(
        v6revLookup
    )

    s.registerProvider(file.ZoneFile(path, 'example.'))

    s.run()
