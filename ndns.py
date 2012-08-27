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

import utils

logger = logging.getLogger('DNS')

class DnsError(Exception):
    
    def __init__(self, message, rcode=None, *args, **kwargs):
        self.rcode = rcode
        self.message = message


class DnsRequestHandler(threading.Thread):
    
    def __init__(self, ndns, client, clientaddress):
        self.ndns = ndns
        self.client = client
        self.clientaddress = clientaddress
    
    def parseRequest(self, request):
        headerLength = 12
        header = request[:headerLength]
        
        qid, flags, qdcount, _, _, _ = struct.unpack('!HHHHHH', header)
        qr = (flags >> 15) & 0x1
        opcode = (flags >> 11) & 0xf
        rd = (flags >> 8) & 0x1
        
        #print "qid", qid, "qdcount", qdcount, "qr", qr, "opcode", opcode, "rd", rd
        
        if qr != 0 or opcode != 0 or qdcount == 0:
            raise DnsError("Invalid query", rcode=1)
        
        body = request[headerLength:]
        labels = []
        offset = 0
        
        while True:
            label_len, = struct.unpack('!B', body[offset:offset+1])
            offset += 1
            if label_len & 0xc0:
                raise DnsError("Invalid label length %d" % label_len)
            if label_len == 0:
                break
            label = body[offset:offset+label_len]
            offset += label_len
            labels.append(label)
            
        qtype, qclass= struct.unpack("!HH", body[offset:offset+4])
        
        if qclass != 1:
            raise DnsError("Invalid class: " + qclass)
        return (qid, labels, qtype, qclass)
    
    def buildNameServerResource(self, provider, zone):
        ns = []
        ar = []
                
        for name_server, ip, ttl in provider.getNameServers(zone, self.clientaddress):
            ns.append({
                       'qtype':2,
                       'qclass':1,
                       'ttl':ttl,
                       'rdata':utils.labels2str(name_server),
                       'question': zone
                    })
            
            ar.append({'qtype':1, 'qclass':1, 'ttl':ttl, 'rdata':struct.pack("!I", ip)})
    
        return ns, ar
    
    def formatResponse(self, qid, question, qtype, qclass, rcode, an_resource_records, ns_resource_records, ar_resource_records):
        resources = []
        resources.extend(an_resource_records)
        num_an_resources = len(an_resource_records)
        num_ns_resources = num_ar_resources = 0
        if rcode == 0:
            resources.extend(ns_resource_records)
            resources.extend(ar_resource_records)
            num_ns_resources = len(ns_resource_records)
            num_ar_resources = len(ar_resource_records)
        pkt = self.formatHeader(qid, rcode, num_an_resources, num_ns_resources, num_ar_resources)
        pkt += self.formatQuestion(question, qtype, qclass)
        for resource in resources:
            if resource.has_key('question'):
                pkt += self.formatResource(resource, resource['question'])
        else:
                pkt += self.formatResource(resource, question)
        return pkt
    
    def formatHeader(self, qid, rcode, ancount, nscount, arcount):
        flags = 0
        flags |= (1 << 15)
        flags |= (1 << 10)
        flags |= (rcode & 0xf)
        hdr = struct.pack("!HHHHHH", qid, flags, 1, ancount, nscount, arcount)
        return hdr
    
    def formatQuestion(self, question, qtype, qclass):
        q = utils.labels2str(question)
        q += struct.pack("!HH", qtype, qclass)
        return q
    
    def formatResource(self, resource, question):
        r = ''
        r += utils.labels2str(question)
        r += struct.pack("!HHIH", resource['qtype'], resource['qclass'], resource['ttl'], len(resource['rdata']))
        r += resource['rdata']
        return r
    
    def run(self, request):
        qid = question = qtype = qclass = rcode = None
        an_resource_records = ns_resource_records = ar_resource_records = None
        
        response = None
        
        try:
            (qid, question, qtype, qclass) = self.parseRequest(request)
            
            question = map(lambda x: x.lower(), question)
            
            found = False
            
            for provider in self.ndns.getProviders():
                for zone in provider.getZones(self.clientaddress):
                    if question[1:] == zone:
                        query = question[0]
                    elif question == zone:
                        query = ''
                    elif question[-len(zone):] == zone:
                        query = question[:-len(zone)]
                    else:
                        continue
            
                    ns_resource_records, IGNORE_ar_resource_records = self.buildNameServerResource(provider, zone)
                    del IGNORE_ar_resource_records
                    # Copy the NS data for later.
                    original_ns_resource_records = ns_resource_records
            
                    rcode, an_resource_records = provider.getResponse(query, zone, qtype, qclass, self.clientaddress)
                    
                    logger.debug("Got from get_response(): %s / %s" % (rcode, an_resource_records))
                    
                    if rcode == 0:
                        for f in provider.getFilters():
                            logger.debug("Running filter %s" % (f,))
                            an_resource_records, ns_resource_records = f.filter(query, zone, qtype, qclass, self.clientaddress, an_resource_records, ns_resource_records)
                            logger.debug("Filter returned %s/%s" % (an_resource_records, ns_resource_records))
                    
                    # If there's no error and no responses, wipe NS information
                    # (or, if it's an NS query, move it to the answer section)
                    # If we don't do this, it'd be considered a referral instead of an answer...
                    if rcode == 0 and len(an_resource_records) == 0 and ns_resource_records == original_ns_resource_records:
                        if qtype == 2:
                            an_resource_records = ns_resource_records
                        ns_resource_records = []
                    
                    logger.debug("About to send back:\nAN: %s\nNS: %s\nAR: %s\n" % (an_resource_records, ns_resource_records, ar_resource_records))
                    response = self.formatResponse(qid, question, qtype, qclass, rcode, an_resource_records, ns_resource_records, ar_resource_records)
                    
                    found = True
                    break
                
                if found:
                    break
                
            if not found:
                raise DnsError("query is not for our domain: %s" % ".".join(question), 3)
                    
        except DnsError as e:
            if qid:
                if e.rcode == None:
                    e.rcode = 2
                
                response = self.format_response(qid, question, qtype, qclass, e.rcode, [], [], [])
                
                logger.error(e)
            else:
                pass
                
        self.client.send(response)



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
        self.udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY,0)
        self.udp.bind((self.host, self.port))
        
        self.tcp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY,0)
        self.tcp.bind((self.host, self.port))

        self.clients = {}
        self.clientOut = {}
        
        self.running = True

    def run(self):
        
        while self.running:
            (rlist,wlist,xlist) = select.select([self.upd, self.tdp] + self.clients.keys(), [self.clients], [])
            del xlist
            
            for s in rlist:
                if s == self.upd or s == self.tcp:
                    client, clientaddress = self.sock.accept()
                    self.clients[client] = DnsRequestHandler(self, client, clientaddress)
                    self.clientOut[client] = queue.Queue()
                    
                elif s in self.clients.keys():
                    data = s.recv(512) # Max UDP DNS packet size
                    if not data:
                        del self.clients[s]
                        del self.clientOut[s]
                        s.close()
                    else:
                        self.clients.run(data)
                    
            for s in wlist:
                if s in self.clients:
                    if not self.clientOut[s].empty():
                        s.send(self.clientOut[s].get())

