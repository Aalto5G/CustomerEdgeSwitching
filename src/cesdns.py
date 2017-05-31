#!/usr/bin/python3.5

import asyncio
import logging
import sys
import time
import traceback
import cetpManager
import ocetpLayering
import icetpLayering

import dns
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
    def __init__(self, cetp_mgr = None):
        self._logger = logging.getLogger('DNSServer')
        self._logger.setLevel(LOGLEVELDNS)
        self._cetpManager = cetp_mgr
        self._load_naptr_records2()
        
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
        name, rdtype, rdclass = q.name, q.rdtype, q.rdclass
        opcode = query.opcode()
        key = (query.id, name, rdtype, rdclass, addr)
        
        #print("\nReceived DNS query for '%s'" % str(name))
        naptr_response_list = self.resolve_naptr(name)
        for naptr_resp in naptr_response_list:
            dest_id, r_cesid, r_ip, r_port, r_transport = naptr_resp                # Expected format of NAPTR_response: (remote_ip, remote_port, remote_transport, dst_hostid)
                                                                                    # Assumption: Detsination domain is reachable via one CES only. All list of DNS NAPTR response records point to one remote cesids?
                                                                                    # TBD: Destination reachable via multiple CES nodes.
        cb_args = (query, addr)
        self._cetpManager.process_outbound_cetp(r_cesid, naptr_response_list, self.process_dns_query_callback, cb_args)
        

    def process_dns_query_callback(self, dns_query, addr, success=True):
        """ Sending DNS Response """
        qtype      = dns_query.question[0].rdtype
        domain     = dns_query.question[0].name.to_text().lower()
        flags      = [dns.flags.AA, dns.flags.RA]

        if success:
            rrset = dns.rrset.from_text(domain, 10, dns.rdataclass.IN, dns_query.question[0].rdtype, "127.0.0.1")
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
        self.naptr_records['dest-id']            = ("destHost/service-id, dest-cesid,    dest-ip, dest-port, proto")
        self.naptr_records['hosta1.demo.lte.']   = ('hosta1.demo.lte.',     'cesa.demo.lte.', '127.0.0.1', '49001', 'tcp')
        self.naptr_records['hosta2.demo.lte.']   = ('hosta2.demo.lte.',     'cesa.demo.lte.', '127.0.0.1', '49001', 'tcp')
        self.naptr_records['hosta3.demo.lte.']   = ('hosta3.demo.lte.',     'cesa.demo.lte.', '127.0.0.1', '49002', 'tcp')
        self.naptr_records['hosta4.demo.lte.']   = ('hosta4.demo.lte.',     'cesa.demo.lte.', '127.0.0.1', '49002', 'tcp')
        self.naptr_records['hostb1.demo.lte.']   = ('hostb1.demo.lte.',     'cesb.demo.lte.', '127.0.0.1', '49001', 'tcp')
        self.naptr_records['hostb2.demo.lte.']   = ('hostb2.demo.lte.',     'cesb.demo.lte.', '127.0.0.1', '49001', 'tcp')
        self.naptr_records['hostb3.demo.lte.']   = ('hostb3.demo.lte.',     'cesb.demo.lte.', '127.0.0.1', '49002', 'tcp')
        self.naptr_records['hostb4.demo.lte.']   = ('hostb4.demo.lte.',     'cesb.demo.lte.', '127.0.0.1', '49002', 'tcp')
        self.naptr_records['hostb5.demo.lte.']   = ('hostb5.demo.lte.',     'cesb.demo.lte.', '127.0.0.1', '49003', 'tls')
        self.naptr_records['hostb6.demo.lte.']   = ('hostb6.demo.lte.',     'cesb.demo.lte.', '127.0.0.1', '49003', 'tls')
        self.naptr_records['hostc1.demo.lte.']   = ('hostc1.demo.lte.',     'cesc.demo.lte.', '127.0.0.3', '49001', 'tcp')
        self.naptr_records['hostc2.demo.lte.']   = ('hostc2.demo.lte.',     'cesc.demo.lte.', '127.0.0.3', '49001', 'tcp')
        self.naptr_records['www.google.com.']    = ('www.google.com.',      'cesd.demo.lte.', '127.0.0.4', '49001', 'tcp')
        self.naptr_records['www.aalto.fi.']      = ('www.aalto.fi.',        'cese.demo.lte.', '127.0.0.5', '49001', 'tcp')
        self.naptr_records['test.']              = ('test.',                'cesb.demo.lte.', '127.0.0.1', '49001', 'tcp')        
        self.naptr_records['raimo.aalto.lte.']   = ('raimo.aalto.lte.',     'cesb.demo.lte.', '127.0.0.1', '49001', 'tcp')
        self.naptr_records['raimo2.aalto.lte.']  = ('raimo2.aalto.lte.',    'cesb.demo.lte.', '127.0.0.1', '49002', 'tcp')
    
    def _load_naptr_records2(self):
        """ Simulating availability of NAPTR records from DNS """
        self.naptr_records = {}
        self.naptr_records['dest-id']                   = ("destHost/service-id, dest-cesid,    dest-ip, dest-port, proto")
        self.naptr_records['hosta1.demo.lte.']          = ('hosta1.demo.lte.',     'cesa.demo.lte.', '127.0.0.1', '49001', 'tcp')
        self.naptr_records['hosta2.demo.lte.']          = ('hosta2.demo.lte.',     'cesa.demo.lte.', '127.0.0.1', '49001', 'tcp')
        self.naptr_records['hosta3.demo.lte.']          = ('hosta3.demo.lte.',     'cesa.demo.lte.', '127.0.0.1', '49002', 'tcp')
        self.naptr_records['hosta4.demo.lte.']          = ('hosta4.demo.lte.',     'cesa.demo.lte.', '127.0.0.1', '49002', 'tcp')
        self.naptr_records['hostc1.demo.lte.']          = ('hostc1.demo.lte.',     'cesc.demo.lte.', '127.0.0.3', '49001', 'tcp')
        self.naptr_records['hostc2.demo.lte.']          = ('hostc2.demo.lte.',     'cesc.demo.lte.', '127.0.0.3', '49001', 'tcp')
        self.naptr_records['www.google.com.']           = ('www.google.com.',      'cesd.demo.lte.', '127.0.0.4', '49001', 'tcp')
        self.naptr_records['www.aalto.fi.']             = ('www.aalto.fi.',        'cese.demo.lte.', '10.0.3.101', '48001', 'tcp')
        self.naptr_records['test.']                     = ('test.',                'cesa.demo.lte.', '10.0.3.101', '48001', 'tcp')        
        self.naptr_records['raimo.aalto.lte.']          = ('raimo.aalto.lte.',          'cesb.demo.lte.', '10.0.3.103', '49001', 'tcp')
        self.naptr_records['raimo2.aalto.lte.']         = ('raimo2.aalto.lte.',         'cesb.demo.lte.', '10.0.3.103', '49002', 'tcp')
        self.naptr_records['hosta1.demo.lte.']          = ('hosta1.demo.lte.',          'cesa.demo.lte.', '10.0.3.101', '48001', 'tcp')
        self.naptr_records['hosta2.demo.lte.']          = ('hosta1.demo.lte.',          'cesa.demo.lte.', '10.0.3.101', '48001', 'tcp')
        self.naptr_records['srv1.hosta1.demo.lte.']     = ('srv1.hosta1.demo.lte.',     'cesa.demo.lte.', '10.0.3.101', '48001', 'tcp')
        self.naptr_records['srv2.hosta1.demo.lte.']     = ('srv2.hosta1.demo.lte.',     'cesa.demo.lte.', '10.0.3.101', '48001', 'tcp')
        self.naptr_records['hostb1.demo.lte.']          = ('hostb1.demo.lte.',          'cesb.demo.lte.', '10.0.3.103', '49001', 'tcp')
        self.naptr_records['hostb2.demo.lte.']          = ('hostb1.demo.lte.',          'cesb.demo.lte.', '10.0.3.103', '49001', 'tcp')
        self.naptr_records['srv1.hostb1.demo.lte.']     = ('srv1.hostb1.demo.lte.',     'cesb.demo.lte.', '10.0.3.103', '49001', 'tcp')
        self.naptr_records['srv2.hostb1.demo.lte.']     = ('srv2.hostb1.demo.lte.',     'cesb.demo.lte.', '10.0.3.103', '49002', 'tcp')
        
    def resolve_naptr(self, domain):
        """ Resolves a domain name, and returns a list of NAPTR record parsed in format: ('host-id', 'ces-id', 'ip', 'port', 'protocol') """
        search_domain = str(domain)
        self._logger.info("Resolving DNS NAPTR for domain: {}".format(search_domain))
        if search_domain in self.naptr_records:
            naptr_resp = self.naptr_records[search_domain]
            return [naptr_resp]
        else:
            #print("Domain names doesn't exist.. Returning the default result")
            default_dns_rec = []
            naptr_rr1 = (search_domain, 'cesb.demo.lte.', '10.0.3.103', '49001', 'tcp')
            naptr_rr2 = (search_domain, 'cesb.demo.lte.', '10.0.3.103', '49002', 'tcp')
            #naptr_rr3 = (search_domain, 'cesb.demo.lte.', '127.0.0.1', '49003', 'tls')
            naptr_rr3 = (search_domain, 'cesb.demo.lte.', '10.0.3.103', '49003', 'tls')
            default_dns_rec = [naptr_rr1, naptr_rr2, naptr_rr3]
            return default_dns_rec

