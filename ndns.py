'''
Created on 27/08/2012

@author: nsteicke
'''

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
        request = dns.message.from_wire(self.raw_request)
        response = dns.message.make_response(request)

        found = False
        for provider in self.ndns.getProviders():
            for zone in provider.getZones(self.clientaddress):
                if request.question[0].name.is_subdomain(zone):
                    resp = provider.getResponse(request, self.clientaddress)
                    
                    if resp is not None:
                        response = resp
                        found = True
                        break
                    
            if found:
                break
    
        if not found:
            response.set_rcode(dns.rcode.NXDOMAIN)
    
        if self.isUdp:
            self.ndns.udpOut.put((response.to_wire(), self.clientaddress))
        else:
            self.ndns.tcpOut.put((response.to_wire(), self.clientaddress))
            
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
        
        self.udp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.tcp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        
        try:
            self.udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY,0)
            self.tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY,0)
        except AttributeError:
            pass        
        
        self.udp.bind((self.host, self.port))
        self.tcp.bind((self.host, self.port))

        self.clients = {}
        self.tcpOut = queue.Queue()
        self.udpOut = queue.Queue()
        
        self.running = True
        
        self.providers = []
        
    def registerProvider(self, provider):
        self.providers.append(provider)
        
    def getProviders(self):
        return self.providers

    def run(self):
        logger.info('Starting Main Loop')
        
        while self.running:
            (rlist,wlist,xlist) = select.select(
                    [self.udp, self.tcp],
                    [self.udp, self.tcp],
                    []
                )
                
            del xlist
            
            for s in rlist:
                data,clientaddress = s.recvfrom(512) # Max UDP DNS packet size
                if not data:
                    continue
                    
                handler = DnsRequestHandler(self, data, s == self.udp, clientaddress)
                handler.start()
                                
                logger.info('Accepting connection from %s' % (clientaddress, ))
                    
            for s in wlist:
                if s == self.udp:
                    if not self.udpOut.empty():
                        s.sendto(*self.udpOut.get())
                elif s == self.tcp:
                    if not self.tcpOut.empty():
                        s.sendto(*self.tcpOut.get())

if __name__ == "__main__":

    logConsole = logging.StreamHandler()
    logConsole.setLevel(logging.DEBUG)
    
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logConsole)

    from providers import localhost
    
    s = Ndns()
    s.registerProvider(localhost.LocalhostProvider())
    
    s.run()
    