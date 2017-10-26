#!/usr/bin/python3.5

import asyncio
import logging
import sys
import time
import traceback
import cetpManager
import CETPH2H
import CETPC2C

import dns
import dns.query
import dns.message
from dns.exception import DNSException
from dns.rdataclass import *
from dns.rdatatype import *

LOGLEVELDNS = logging.INFO

def _sanitize_query(query):
    try:
        #assert (query.opcode() == dns.opcode.QUERY)  # Standard QUERY
        assert (query.rcode() == dns.rcode.NOERROR)  # No Error
        assert ((query.flags & dns.flags.QR) != dns.flags.QR)  # Message is query
        assert (len(query.question) == 1)  # Query contains 1 question
    except Exception as e:
        print('Failed to sanitize DNS query: {}'.format(e))
        return False
    return True


class DNSServer(asyncio.DatagramProtocol):
    def __init__(self, cesid, cetp_mgr = None):
        self._cetpManager   = cetp_mgr
        self.cesid          = cesid
        self._load_naptr_records()
        self._logger        = logging.getLogger('DNSServer')
        self._logger.setLevel(LOGLEVELDNS)
        
    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data, addr):
        try:
            self._logger.debug('Received {2} bytes data from {0}:{1}'.format(addr[0], addr[1], len(data)))
            query = dns.message.from_wire(data)
            self.process_dns_query(query, addr)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            self._logger.error('Failed to process DNS message from {0}:{1}'.format(addr[0], addr[1]))
            return

    def process_dns_query(self, query, addr):
        """ Takes DNS query received by the DNS Server as an input & triggers CETP resolution. """
        if not _sanitize_query(query):
            self._send_error(query, addr, dns.rcode.FORMERR)
            return

        q = query.question[0]
        dst_name, rdtype, rdclass = q.name, q.rdtype, q.rdclass
        dst_domain = str(dst_name)
        opcode = query.opcode()
        key = (query.id, dst_name, rdtype, rdclass, addr)

        cb = self.dns_query_callback
        cb_args = (query, addr)
        
        if len(dst_domain)!=0:
            #print("\nReceived DNS query for '%s'" % str(name))
            if ((rdtype == dns.rdatatype.A) or (rdtype == dns.rdatatype.AAAA)) and (self.cesid in dst_domain):
                # DNS A query for local domains
                self._cetpManager.process_dns_message(cb, cb_args, dst_domain)
                return        
            else:
                naptr_response_list = self.resolve_naptr(dst_domain)                        # Simulating resolution process for NAPTR response records
                # Sanitization of NAPTR response must happen at this place
                for naptr_resp in naptr_response_list:
                    dest_id, r_cesid, r_ip, r_port, r_transport = naptr_resp                # Assumption: Destination is reachable via one CES only. All list of DNS NAPTR response records point to one remote cesids?
                                                                                            # TBD: Destination reachable via multiple CES nodes.
                self._cetpManager.process_dns_message(cb, cb_args, dst_domain, r_cesid, naptr_list=naptr_response_list)
            

    def dns_query_callback(self, dns_query, addr, r_addr="", success=True):
        """ Sending DNS Response """
        qtype      = dns_query.question[0].rdtype
        domain     = dns_query.question[0].name.to_text().lower()
        flags      = [dns.flags.AA, dns.flags.RA]

        if success:
            rrset = dns.rrset.from_text(domain, 10, dns.rdataclass.IN, dns_query.question[0].rdtype, r_addr)
            dns_response = self.create_dns_response(dns_query, dns.rcode.NOERROR, flags, [rrset], authority_rr = [], additional_rr=[])
        else:
            dns_response = self.create_dns_response(dns_query, dns.rcode.NXDOMAIN, flags, [], authority_rr = [], additional_rr=[])
        self._transport.sendto(dns_response.to_wire(), addr)
    
    
    def create_dns_response(self, dns_query, rcode, flags, answer_rr, authority_rr = [], additional_rr = []):
        """
        Create a DNS response. 
        
        @param dns_query: The original DNS query.
        @param rcode: The DNS_RCODE of the response. 
        @param flags: A list with the flags of the response. 
        @param answer_rr: A list of rrset with the response records. 
        @param authority_rr: A list of rrset with the authority records. 
        @param additional_rr: A list of rrset with the additional records. 
        @return: The built DNS message.
        """
        #print "create_dns_response"
        dns_response = dns.message.make_response(dns_query)
        dns_response.set_rcode(rcode)
        for rr in answer_rr:
            dns_response.answer.append(rr)
        for rr in authority_rr:
            dns_response.authority.append(rr)
        for rr in additional_rr:
            dns_response.additional.append(rr)
        for flag in flags:
            dns_response.flags |= flag
        return dns_response
    
    def _load_naptr_records(self):
        """ Simulating availability of NAPTR records from DNS """
        self.naptr_records = {}
        self.naptr_records['dest-id']                       = ("destHost/service-id,         dest-cesid,    dest-ip, dest-port, proto")
        self.naptr_records['hosta1.cesa.lte.']              = ('hosta1.cesa.lte.',          'cesa.lte.', '10.0.3.101', '48001', 'tcp')
        self.naptr_records['hosta2.cesa.lte.']              = ('hosta2.cesa.lte.',          'cesa.lte.', '10.0.3.101', '48002', 'tcp')
        self.naptr_records['srv1.hosta1.cesa.lte.']         = ('srv1.hosta1.cesa.lte.',     'cesa.lte.', '10.0.3.101', '48001', 'tcp')
        self.naptr_records['srv2.hosta1.cesa.lte.']         = ('srv2.hosta1.cesa.lte.',     'cesa.lte.', '10.0.3.101', '48002', 'tcp')
        self.naptr_records['hostb1.cesb.lte.']              = ('hostb1.cesb.lte.',          'cesb.lte.', '10.0.3.103', '49001', 'tcp')
        self.naptr_records['hostb2.cesb.lte.']              = ('hostb2.cesb.lte.',          'cesb.lte.', '10.0.3.103', '49002', 'tcp')
        self.naptr_records['srv1.hostb1.cesb.lte.']         = ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tcp')
        #self.naptr_records['srv2.hostb1.cesb.lte.']         = ('srv2.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tcp')
        self.naptr_records['srv2.hostb1.cesb.lte.']         = ('srv2.hostb1.cesb.lte.',     'cesc.lte.', '10.0.3.103', '49001', 'tcp')
        self.naptr_records['raimo.cesb.lte.']               = ('raimo.cesb.lte.',           'cesb.lte.', '10.0.3.103', '49001', 'tcp')
        self.naptr_records['raimo2.cesb.lte.']              = ('raimo2.cesb.lte.',          'cesb.lte.', '10.0.3.103', '49002', 'tcp')
        self.naptr_records['www.google.com.']               = ('www.google.com.',           'cesd.lte.', '10.0.3.103', '49001', 'tcp')
        self.naptr_records['www.aalto.fi.']                 = ('www.aalto.fi.',             'cese.lte.', '10.0.3.101', '48001', 'tcp')
        self.naptr_records['test.']                         = ('test.',                     'cesa.lte.', '10.0.3.101', '48001', 'tcp')
        
        # Just for the sake of testing
        self.naptr_records['hostc1.cesb.lte.']              = ('hostb1.cesb.lte.',          'cesc.lte.', '10.0.3.103', '49001', 'tcp')
        self.naptr_records['hostd1.cesb.lte.']              = ('hostb1.cesb.lte.',          'cesd.lte.', '10.0.3.103', '49001', 'tcp')
        self.naptr_records['hoste1.cesb.lte.']              = ('hostb1.cesb.lte.',          'cese.lte.', '10.0.3.103', '49001', 'tcp')
        
        
        
    def resolve_naptr(self, domain):
        """ Resolves a domain name, and returns a list of NAPTR record parsed in format: ('host-id', 'ces-id', 'ip', 'port', 'protocol') """
        search_domain = str(domain)
        #self._logger.info("Resolving DNS NAPTR for domain: {}".format(search_domain))
        if search_domain in self.naptr_records:
            naptr_resp = self.naptr_records[search_domain]
            return [naptr_resp]
        else:
            #print("Domain names doesn't exist.. Returning the default result")
            default_dns_rec = []
            naptr_rr1 = (search_domain, 'cesb.lte.', '10.0.3.103', '49001', 'tcp')
            naptr_rr2 = (search_domain, 'cesb.lte.', '10.0.3.103', '49002', 'tcp')
            #naptr_rr3 = (search_domain, 'cesb.lte.', '127.0.0.1', '49003', 'tls')
            naptr_rr3 = (search_domain, 'cesb.lte.', '10.0.3.103', '49003', 'tls')
            default_dns_rec = [naptr_rr1, naptr_rr2, naptr_rr3]
            return default_dns_rec

