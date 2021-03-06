#!/usr/bin/env python
#-*- coding: utf-8 -*-
#############################################################################
# DNS64 server for IPv6 with Python3
# - Code by Jioh L. Jung (ziozzang@gmail.com)
#############################################################################
#
# Functions: DNS Proxy (for IPv6)
#
# Code from
#   - Original DNS Server from https://github.com/dsbaars/python-dns64-proxy

import socket,ipaddress

from dnslib import *
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

import doh

DNSMAP = { 5:CNAME, 1:A, 28:AAAA, 16:TXT, 15:MX,
          12:PTR, 6:SOA, 2:NS, 35: NAPTR, 33:SRV,
          48:DNSKEY, 46:RRSIG, 47:NSEC, 257:CAA
        }

DNS_AAAA_RECORD = 28
DNS_A_RECORD = 1

config = {
    #"IPV6_PREFIX":"fdcb:b3ab:4522:fa5a::",
    "IPV6_PREFIX":"64:ff9b::",

    #"DNS_RESOLVER_HOST": "8.8.8.8", # Google (ipv4)
    "DNS_RESOLVER_HOST": "1.1.1.1", # Cloudflare (ipv4)
    "DNS_RESOLVER_PORT": 53,
    "DNS_RESOLVER_TIMEOUT": 5, #Sec
    "DNS_RESOLVER_URL": 'https://dns.google.com/resolve', # For DNS over HTTPS (Google)
    #"DNS_RESOLVER_URL": "https://1.1.1.1/dns-query", # For DNS over HTTPS (Cloudflare) - TODO

    "DNS_RESOLVER_TYPE": "doh", # doh, udp

    "port": 5354,
    "addr": "0.0.0.0",

    "allow_ip_list": ["0.0.0.0/0",'0::'],
}

class DNS64ProxyResolver(BaseResolver):
    def __init__(self,address,port,timeout=0):
        self.address = address
        self.port = port
        self.timeout = timeout

    def _check_ip_in_allow_list(self, ip):
        # Check IP is in allowed list
        for i in config["allow_ip_list"]:
            # Tricky but to auto-detect network address type.
            n = ipaddress.ip_network(i)
            if (
                    # For IPv6 Detect
                    (n.__class__ == ipaddress.IPv6Network('0::').__class__) and (ipaddress.IPv6Address(ip) in n)
                ) or (
                    # For IPv4 Detect
                    (n.__class__ == ipaddress.IPv4Network('0.0.0.0/0').__class__) and (ipaddress.IPv4Address(ip) in n)
                ):
                    return True
        return False

    def _conv_ipv4_to_v6(self, ipv4_str):
        # Convert IPv4 Addr to IPv6 (for compatibility of NAT64)
        ipv6_str = AAAA(
            str(
                ipaddress.IPv6Address(
                        (int(ipaddress.IPv6Address(config["IPV6_PREFIX"]))) | \
                        (int(ipaddress.IPv4Address(ipv4_str))
                     )
                )
            )
        )
        return ipv6_str

    def resolve(self,request,handler):
        try:
            if handler.protocol == 'udp':
                # Server only listening UDP protocol

                if not self._check_ip_in_allow_list(handler.client_address[0]):
                    # Return Nothing - if not allowed list
                    reply = request.reply()
                    reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
                    return reply

                if config["DNS_RESOLVER_TYPE"] == 'doh':
                    dohr = doh.SecureDNS(query_type=request.q.qtype, url=config["DNS_RESOLVER_URL"]).\
                        resolve(request.q.qname)

                    reply = request.reply()

                    if request.q.qtype == DNS_AAAA_RECORD:
                        if (dohr is None) or ((type(dohr) == type([])) and (len(dohr) == 0)):
                            dohr = doh.SecureDNS(query_type=DNS_A_RECORD, url=config["DNS_RESOLVER_URL"]).\
                                resolve(request.q.qname)

                        for r in dohr:
                            if r['type'] == DNS_A_RECORD:
                                reply.add_answer(
                                        RR(r['name'], rtype=DNS_AAAA_RECORD,ttl=r['TTL'],
                                           rdata=self._conv_ipv4_to_v6(r['data']))
                                )
                            else:
                                reply.add_answer(
                                        RR(r['name'], rtype=r['type'],ttl=r['TTL'],
                                           rdata=DNSMAP[r['type']](r['data']))
                                    )

                    else:
                        if (type(dohr) == type([])) and (len(dohr) > 0):
                            for r in dohr:
                                if r['type'] == 15:
                                    rmx = r['data'].split()
                                    rd = DNSMAP[r['type']](rmx[1],int(rmx[0]))
                                    reply.add_answer(
                                            RR(r['name'], rtype=r['type'],ttl=r['TTL'],
                                               rdata=rd)
                                    )
                                else:
                                    rd = DNSMAP[r['type']](r['data'])
                                    reply.add_answer(
                                        RR(r['name'], rtype=r['type'], ttl=r['TTL'],
                                           rdata=rd)
                                    )

                    if dohr is None:
                        reply = request.reply()
                        reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

                    return reply

                elif config["DNS_RESOLVER_TYPE"] == 'udp':
                    orig_proxy_r = request.send(
                                        self.address,self.port,
                                        timeout=self.timeout
                                    )
                    reply = DNSRecord.parse(orig_proxy_r)

                    if  (request.q.qtype == DNS_AAAA_RECORD) and \
                        (
                          (len(reply.rr) < 1) or
                          (reply.rr[0].rtype != DNS_AAAA_RECORD)
                        ):

                        request.q.qtype = DNS_A_RECORD
                        orig_proxy_r = request.send(
                                    self.address,
                                    self.port,
                                    timeout=self.timeout)
                        orig_reply = DNSRecord.parse(orig_proxy_r)
                        request.q.qtype = DNS_AAAA_RECORD

                        if len(orig_reply.rr) > 0:
                            # Upstream results are more than one item,
                            reply = DNSRecord(
                                DNSHeader(
                                    id=orig_reply.header.id,qr=1,ra=1
                                ),
                                q=request.q
                            )

                            for r in orig_reply.rr:
                                if  (r.rtype != DNS_AAAA_RECORD) and \
                                    (r.rtype != DNS_A_RECORD):
                                    # CNAME or some DNS type must be same as upstream result.
                                    reply.add_answer(
                                        RR(r.rname, rtype=r.rtype, ttl=r.ttl,
                                           rdata=r.rdata)
                                    )
                                else:
                                    reply.add_answer(
                                        RR(r.rname, rtype=DNS_AAAA_RECORD, ttl=r.ttl,
                                           rdata=self._conv_ipv4_to_v6(r.rdata))
                                    )
                else:
                    proxy_r = request.send(self.address,self.port,
                                    tcp=True,timeout=self.timeout)
        except socket.timeout:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE,'NXDOMAIN')

        return reply

if __name__ == '__main__':
    import argparse,sys,time
    resolver = DNS64ProxyResolver(
        config["DNS_RESOLVER_HOST"],
        config["DNS_RESOLVER_PORT"],
        config["DNS_RESOLVER_TIMEOUT"])
    handler = DNSHandler
    logger = DNSLogger([],False)
    udp_server = DNSServer(resolver,
                           port=config["port"],
                           address=config["addr"],
                           logger=None,
                           handler=handler)
    udp_server.start_thread()

    while udp_server.isAlive():
        #time.sleep(1)
        pass
