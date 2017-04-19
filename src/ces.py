#!/usr/bin/python3

import asyncio
import configparser
import dns
import logging
import signal
import sys
import traceback
import time
import yaml
import json
import cesdns
import cetpManager
import ocetpLayering
import icetpLayering
import functools
import PolicyManager

LOGLEVELMAIN    = logging.INFO
LOGLEVELCES     = logging.DEBUG

class RetCodes(object):
    POLICY_OK  = 0
    POLICY_NOK = 1
    
    AP_AVAILABLE = 0
    AP_DEPLETED = 1
    
    DNS_NOERROR  = 0    # DNS Query completed successfully
    DNS_FORMERR  = 1    # DNS Query Format Error
    DNS_SERVFAIL = 2    # Server failed to complete the DNS request
    DNS_NXDOMAIN = 3    # Domain name does not exist. For help resolving this error, read
    DNS_NOTIMP   = 4    # Function not implemented
    DNS_REFUSED  = 5    # The server refused to answer for the query
    DNS_YXDOMAIN = 6    # Name that should not exist, does exist
    DNS_XRRSET   = 7    # RRset that should not exist, does exist
    DNS_NOTAUTH  = 8    # Server not authoritative for the zone
    DNS_NOTZONE  = 9    # Name not in zone



def trace():
    print('Exception in user code:')
    print('-' * 60)
    traceback.print_exc(file=sys.stdout)
    print('-' * 60)
    
class CustomerEdgeSwitch(object):
    def __init__(self, name='CustomerEdgeSwitch', async_loop = None, config_file=None):
        self._logger = logging.getLogger(name)
        logging.basicConfig(level=LOGLEVELMAIN)
        self._logger.setLevel(LOGLEVELCES)
        
        # Get event loop
        self._loop = async_loop
        self._read_configuration(config_file)
        
        # Enable debugging
        #self._set_verbose()
        
        # Capture signals
        self._capture_signal()
        
        # Initialize CETP
        self._init_cetp()

        # Initialize DNS
        self._init_dns()
        
    
    def _capture_signal(self):
        for signame in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(getattr(signal, signame), lambda: asyncio.ensure_future(self._signal_handler(signame)))
    
    """
    def _capture_signal(self):
        for signame in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(getattr(signal, signame), functools.partial(self._signal_handler, signame))
    """
        
    
    def _read_configuration(self, filename):
        config_file = open(filename)
        self.ces_conf = yaml.load(config_file)
        
    def _init_cetp(self):
        """ Initiate CETP manager... Manages CETPLocalManager() and CETPServers() """
        self.ces_params      = self.ces_conf['CESParameters']
        self.ces_name        = self.ces_params['name']
        self.cesid           = self.ces_params['cesid']
        self.ces_certificate = self.ces_params['certificate']
        self.ces_privatekey  = self.ces_params['private_key']
        self.ca_certificate  = self.ces_params['ca_certificate']                     # Could be a list of popular/trusted (certificate issuing) CA's certificates

        self._host_policies = self.ces_conf["cetp_policy_file"]
        self.cetp_mgr = cetpManager.CETPManager(self._host_policies, self.cesid, self.ces_params, loop=self._loop)
        cetp_server_list = self.ces_conf["CETPServers"]["serverNames"]
        for srv in cetp_server_list:
            srv_info = self.ces_conf["CETPServers"][srv]
            srv_addr, srv_port, srv_proto = srv_info["ip"], srv_info["port"], srv_info["transport"]
            self.cetp_mgr.create_server_endpoint(srv_addr, srv_port, srv_proto)

        
    def _init_dns(self):
        # Store all DNS related parameters in a dictionary
        self._dns = {}
        self._dns['addr'] = {}
        self._dns['node'] = {}
        self._dns['activequeries'] = {}
        self._dns['soa'] = self.ces_conf['DNS']['soa']
        self._dns['timeouts'] = self.ces_conf['DNS']['timeouts']
        
        # Create DNS Zone file to be populated
        #self._dns['zone'] = cesdns.load_zone(self.ces_conf['DNS']['zonefile'], self.ces_conf['DNS']['soa'])
        
        self._logger.warning('DNS rtx-timeout for CES NAPTR: {}'.format(self._dns['timeouts']['naptr']))
        self._logger.warning('DNS rtx-timeout for CES A:     {}'.format(self._dns['timeouts']['a']))
        self._logger.warning('DNS rtx-timeout for other:     {}'.format(self._dns['timeouts']['any']))
        
        # Get address tuple configuration of DNS servers
        for k, v in self.ces_conf['DNS']['server'].items():
            self._dns['addr'][k] = (v['ip'], v['port'])
        
        # Initiate specific DNS servers
        self._init_dns_loopback()
        
    def _init_dns_loopback(self):
        # Initiate DNS Server in Loopback
        #zone = self._dns['zone']
        addr = self._dns['addr']['loopback']
        self._logger.warning('Creating DNS Server {} @{}:{}'.format('loopback', addr[0],addr[1]))
        
        # Define callbacks for different DNS queries
        cb_noerror = None
        cb_nxdomain = self.process_dns_query
        cb_udpate = self.process_dns_update
        
        factory = cesdns.DNSServer(cb_noerror, cb_nxdomain, cb_udpate, cetp_mgr = self.cetp_mgr)
        self._dns['node']['loopback'] = factory
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: factory, local_addr=addr))
    
    def _init_datarepository(self):
        self._logger.warning('Initializing data repository')
        self._udr = self.ces_conf['DATAREPOSITORY']
        self._init_userdata(self._udr['userdata'])
    
    def _init_userdata(self, filename):
        self._logger.warning('Initializing user data')
        
        data = self._load_configuration(filename)
        for k, v in data['HOSTS'].items():
            self._logger.warning('Registering host {}'.format(k))
            ipaddr = data['HOSTS'][k]['ipv4']
            self.register_user(k, 1, ipaddr)
    
    def _init_network(self):
        kwargs = self.ces_conf['NETWORK']
        self._network = network.Network(self._loop, **kwargs)
        
    def _set_verbose(self):
        self._logger.warning('Enabling logging.DEBUG')
        logging.basicConfig(level=logging.DEBUG)
        self._loop.set_debug(True)
    
    @asyncio.coroutine
    def _signal_handler(self, signame):
        self._logger.critical('Got signal %s: exit' % signame)
        try:
            self._logger.info(" Closing the CETP listening service.")
            for server_obj in self.cetp_mgr.get_server_endpoints():
                server_obj.close()
            
            self._logger.info(" Closing the CETPClients towards remote CES nodes.")
            self.cetp_mgr.close_all_local_client_endpoints()

            self._logger.info(" Closing the DNS listening servers.")
            #addr = self._dns['addr'][k]
            #self._logger.warning('Terminating DNS Server {} @{}:{}'.format(k, addr[0],addr[1]))
            #v.connection_lost(None)
            
            self._logger.info(" Closing the remote endpoints to local CES.")
            self.cetp_mgr.close_all_connected_remote_endpoints()

            yield from asyncio.sleep(0.5)                             # Prevents asyncio-loop from stopping, and thus allows Asyncio task.cancel() to complete.
            
            
        except:
            trace()
        finally:
            self._loop.stop()
    
    def begin(self):
        print('CESv2 will start now...')
        self._loop.run_forever()
        
    ############################################################################
    ######################  POLICY PROCESSING FUNCTIONS  #######################
    
    def _process_local_policy(self, src_policy, dst_policy):
        self._logger.warning('Processing local policy for {} -> {}'.format(src_policy, dst_policy))
        if src_policy is dst_policy:
            return (RetCodes.POLICY_OK, True)
        else:
            return (RetCodes.POLICY_NOK, False)
    
    def create_local_connection(self, src_host, dst_service):
        self._logger.warning('Connecting host {} to service {}'.format(src_host, dst_service))
        import random
        # Randomize policy check
        retCode = self._process_local_policy(1, random.randint(0,1))
        if retCode[0] is RetCodes.POLICY_NOK:
            self._logger.warning('Failed to match policy!')
            return (RetCodes.DNS_NXDOMAIN, 'PolicyMismatch')
        
        try:
            self._logger.warning('Policy matched! Create a connection')
            ap = self._addresspoolcontainer.get('proxypool')
            ipaddr = ap.allocate(src_host)
            
            d = {'src':'192.168.0.50','psrc':'172.16.0.0',
                 'dst':'192.168.0.50','pdst':'172.16.0.1'}
            connection = network.ConnectionCESLocal(**d)
            self._network.create_connection(connection)
            
            return (RetCodes.DNS_NOERROR, ipaddr)
        except KeyError:
            self._logger.warning('Failed to allocate proxy address for host')
            return (RetCodes.DNS_REFUSED, 'PoolDepleted')
    
    
    ############################################################################
    ########################  DNS PROCESSING FUNCTIONS  ########################
    
    def process_dns_query(self, query, addr, cback):
        """ Perform public DNS resolutions of a query """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)
        
        self._logger.warning('Resolve query {0} {1}/{2} from {3}:{4}'.format(query.id, q.name.to_text(), dns.rdatatype.to_text(q.rdtype), addr[0], addr[1]))
        
        if key in self._dns['activequeries']:
            # Continue ongoing resolution
            (resolver, query) = self._dns['activequeries'][key]
            resolver.process_query(query, addr)
        else:
            # Resolve DNS query as is
            self._do_resolve_dns_query(query, addr, cback)

    def process_dns_query_lan_noerror(self, query, addr, cback):
        """ Process DNS query from private network of an existing host """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)

        if (is_ipv4(addr[0]) and q.rdtype == dns.rdatatype.A) or \
        (is_ipv6(addr[0]) and q.rdtype == dns.rdatatype.AAAA):
            self._logger.warning('Resolve local CES policy')
            retCode = self.create_local_connection(addr[0], q.name)
            if retCode[0] is RetCodes.DNS_NOERROR:
                response = cesdns.make_response_answer_rr(query, q.name, q.rdtype, retCode[1])
            else:
                response = cesdns.make_response_rcode(query, retCode[0])
            cback(query, response, addr)
        else:
            # Resolve DNS query as is
            self._do_resolve_dns_query(query, addr, cback)
    
    def process_dns_query_lan_nxdomain(self, query, addr, cback):
        """ Process DNS query from private network of a non existing host """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)
        
        self._logger.warning('Resolve query for CES discovery {0} {1}/{2} from {3}:{4}'.format(query.id, q.name.to_text(), dns.rdatatype.to_text(q.rdtype), addr[0], addr[1]))
        
        if key in self._dns['activequeries']:
            # Continue ongoing resolution
            (resolver, query) = self._dns['activequeries'][key]
            resolver.process_query(query, addr)
        elif is_ipv4(addr[0]) and q.rdtype == dns.rdatatype.A:
            # Resolve DNS query for CES IPv4
            timeouts = dict(self._dns['timeouts'])
            resolver = cesdns.DNSResolverCESIPv4(self._loop, query, addr, self._dns['addr']['resolver'],self._do_resolver_callback, key, timeouts=timeouts)
            self._dns['activequeries'][key] = (resolver, query)
            resolver.begin()
        elif is_ipv6(addr[0]) and q.rdtype == dns.rdatatype.AAAA:
            # Resolve DNS query for CES IPv6
            timeouts = dict(self._dns['timeouts'])
            resolver = cesdns.DNSResolverCESIPv6(self._loop, query, addr, self._dns['addr']['resolver'],self._do_resolver_callback, key, timeouts=timeouts)
            self._dns['activequeries'][key] = (resolver, query)
            resolver.begin()
        else:
            # Resolve DNS query as is
            self._do_resolve_dns_query(query, addr, cback)
            
    def process_dns_query_wan_noerror(self, query, addr, cback):
        """ Process DNS query from public Internet of an existing host """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)
        
        # Serve public records...
        
        ## Filter NAPTR and A records
        cback(query, None, addr)
    
    def process_dns_query_wan_nxdomain(self, query, addr, cback):
        """ Process DNS query from public Internet of a non existing host """
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)
        
        # We have received a query for a domain that should exist in our zone but it doesn't
        cback(query, None, addr)
    
    def process_dns_update(self, query, addr, cback):
        """ Generate NoError DNS response """
        self._logger.debug('process_update')
        
        try:
            rr_a = None
            #Filter hostname and operation
            for rr in query.authority:
                #Filter out non A record types
                if rr.rdtype == dns.rdatatype.A:
                    rr_a = rr
                    break
            
            if not rr_a:
                # isc-dhcp-server uses additional TXT records -> don't process
                self._logger.debug('Failed to find an A record')
                return
            
            name_str = rr_a.name.to_text()
            if rr_a.ttl:
                self.register_user(name_str, rr_a.rdtype, rr_a[0].address)
            else:
                self.deregister_user(name_str, rr_a.rdtype, rr_a[0].address)
                
        except Exception as e:
            self._logger.error('Failed to process UPDATE DNS message')
            trace()
        finally:
            # Send generic DDNS Response NOERROR
            response = cesdns.make_response_rcode(query, RetCodes.DNS_NOERROR)
            self._logger.debug('Sent DDNS response to {}:{}'.format(addr[0],addr[1]))
            cback(query, response, addr)
            
    def _do_resolver_callback(self, metadata, response=None):
        try:
            (queryid, name, rdtype, rdclass, addr, cback) = metadata
            (resolver, query) = self._dns['activequeries'].pop(metadata)
        except KeyError:
            self._logger.warning('Query has already been processed {0} {1}/{2} from {3}:{4}'.format(queryid, name, dns.rdatatype.to_text(rdtype), addr[0], addr[1]))
            return

        if response is None:
            self._logger.warning(
                'This seems a good place to create negative caching...')

        # Callback to send response to host
        cback(query, response, addr)

    def _do_resolve_dns_query(self, query, addr, cback):
        q = query.question[0]
        key = (query.id, q.name, q.rdtype, q.rdclass, addr, cback)

        self._logger.warning(
            'Resolve normal query {0} {1}/{2} from {3}:{4}'.format(
                query.id, q.name.to_text(), dns.rdatatype.to_text(
                    q.rdtype), addr[0], addr[1]))

        # This DNS resolution does not require any kind of mangling
        timeouts = list(self._dns['timeouts']['any'])
        resolver = cesdns.ResolverWorker(self._loop, query, self._do_resolver_callback,
                                   key, timeouts)
        self._dns['activequeries'][key] = (resolver, query)
        raddr = self._dns['addr']['resolver']
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: resolver, remote_addr=raddr))
    
    
    
    
if __name__ == '__main__':
    try:
        loop = asyncio.get_event_loop()
        ces = CustomerEdgeSwitch(async_loop = loop, config_file = sys.argv[1])
        ces.begin()
    except Exception as e:
        print(format(e))
        trace()
    finally:
        loop.close()
    print('Bye!')
