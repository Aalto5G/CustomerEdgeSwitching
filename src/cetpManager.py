#!/usr/bin/python3.5

import asyncio
import logging
import signal
import socket
import sys
import random
import time
import traceback
import json
import yaml
import ssl
import functools
import copy
import dns

import CETP
import C2CTransaction
import H2HTransaction
import CETPH2H
import CETPC2C
import CETPTransports
import PolicyManager
import CETPSecurity
import connection
import host
import customdns
from customdns import dnsutils 

LOGLEVEL_CETPManager    = logging.DEBUG            # Any message above this level will be printed.    WARNING > INFO > DEBUG


class CETPManager:
    """
    At CES bootup:      It initiates CETP listening service (on server end-points) to accept the inbound connection from remote CES. 
    On NAPTR response:  It initiates and registers the CETP-H2H instance towards a remote 'cesid' -- (NAPTR response towards new cesid).
                            CETPManager indexes/retrieves the 'CETPH2H' & 'CETPC2C' instance based on 'remote-cesid'. AND enqueues the NAPTR response in the CETPH2H for handling H2H transactions.
    It also aggregates different CETPTransport endpoints from a remote CES-ID under one C2C-Layer.
    """
    
    def __init__(self, cetpPolicyFile, cesid, ces_params, hosttable, conn_table, pool_table, network, cetpstate_table, loop=None, name="CETPManager"):
        self._cetp_endpoints        = {}                           # Dictionary of endpoints towards remote CES nodes.
        self._serverEndpoints       = []                           # List of server endpoint offering CETP listening service.
        self.c2c_register           = {}
        self.cesid                  = cesid                        # Local ces-id
        self.ces_params             = ces_params
        self.host_table             = hosttable
        self.conn_table             = conn_table
        self.pool_table             = pool_table
        self.cetpstate_table        = cetpstate_table                                                           # Records the established CETP transactions (both H2H & C2C). Required for preventing the re-allocation already in-use SST & DST (in CETP transaction).
        self.payloadID_table        = CETP.PayloadIDTable()
        self.cetp_security          = CETPSecurity.CETPSecurity(loop, self.conn_table, ces_params)
        self.interfaces             = PolicyManager.DPConfigurations(cesid, ces_params = ces_params)
        self.policy_mgr             = PolicyManager.PolicyManager(self.cesid, policy_file = cetpPolicyFile)     # Gets cetp policies from a local configuration file.
        #self.policy_mgr             = PolicyManager.RESTPolicyClient(loop, tcp_conn_limit=100)                 # Fetches cetp policies from the Policy Management System.
        self.network                = network
        self._loop                  = loop
        self.name                   = name
        self._inbound_transports    = {}                        # {'cesid': [transports]} - Temporary record of list of transports connected against a cesid
        self._load_cetp_params()
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPManager)
        self.local_cetp             = CETPH2H.CETPH2HLocal(l_cesid=self.cesid, cetpstate_table=self.cetpstate_table, policy_mgr=self.policy_mgr, cetp_mgr=self, \
                                                           cetp_security=self.cetp_security, host_table=self.host_table, conn_table=self.conn_table, \
                                                           network=network, pool_table=self.pool_table)

    def _load_cetp_params(self):
        try:
            self.ces_certificate_path   = self.ces_params['certificate']
            self.ces_privatekey_path    = self.ces_params['private_key']
            self.ca_certificate_path    = self.ces_params['ca_certificate']                         # Path of X.509 certificate of trusted CA, for validating the remote node's certificate.  -- # Could be a list of popular/trusted (certificate issuing) CA's certificates
            self.max_naptrs_per_msg     = self.ces_params["max_naptrs_per_dns"]
            self.max_dns_cetp_responses = self.ces_params["max_naptrs_per_sec"]
            self.allowed_dns            = copy.copy(self.max_dns_cetp_responses)
        except Exception as ex:
            self._logger.error("Exception '{}' in reading config file".format(ex))
        

    def create_cetp_endpoint(self, r_cesid, c2c_layer=None, c2c_negotiated=False):
        """ Creates the CETP-H2H layer towards remote CES-ID """
        cetp_ep = CETPH2H.CETPH2H(l_cesid = self.cesid, r_cesid = r_cesid, cetpstate_table= self.cetpstate_table, policy_mgr=self.policy_mgr, policy_client=None, \
                                  loop=self._loop, cetp_mgr=self, ces_params=self.ces_params, cetp_security=self.cetp_security, host_table=self.host_table, network=self.network, \
                                  interfaces=self.interfaces, c2c_layer=c2c_layer, c2c_negotiated=c2c_negotiated, conn_table=self.conn_table, pool_table=self.pool_table)
        self.add_cetp_endpoint(r_cesid, cetp_ep)
        return cetp_ep

    def has_cetp_endpoint(self, r_cesid):
        """ Determines whether CETPEndpoint towards r_cesid exists """
        return r_cesid in self._cetp_endpoints

    def add_cetp_endpoint(self, r_cesid, ep):
        self._cetp_endpoints[r_cesid] = ep
        
    def get_cetp_endpoint(self, r_cesid):
        """ Retrieves the CETPEndpoint towards r_cesid """
        return self._cetp_endpoints[r_cesid]

    def remove_cetp_endpoint(self, r_cesid):
        """ Removes the CETPEndpoint towards the r_cesid, from the list of connected clients to remote endpoints  """
        if self.has_cetp_endpoint(r_cesid):
            del self._cetp_endpoints[r_cesid]                     

    def _get_cetp_endpoints(self):
        """ Provides the list of all the local CETPEndpoints """
        end_points = []
        for key, ep in self._cetp_endpoints.items():
            end_points.append(ep)
        return end_points

    def close_cetp_endpoint(self, r_cesid):
        """ Triggers resource cleanup in a CETPEndpoint """
        for cesid, cetp_ep in self._cetp_endpoints.items():
            if cesid == r_cesid:
                cetp_ep.handle_interrupt()
        
    def close_all_cetp_endpoints(self):
        """ Triggers interrupt handler in all CETPEndpoints """
        for ep in list(self._cetp_endpoints.items()):
            cesid, cetp_ep = ep
            cetp_ep.handle_interrupt()
        
    def set_max_dns_naptr_responses(self):
        self.allowed_dns = copy.copy(self.max_dns_cetp_responses)
            
    def dns_threshold_exceeded(self):
        """ Check to detect DNS flood, AND to prevent CES/CETP processing from subjecting to high loads  """
        if self.allowed_dns == self.max_dns_cetp_responses:
            self._loop.call_later(1.0, self.set_max_dns_naptr_responses)

        elif self.allowed_dns ==0:
            return True
            
        self.allowed_dns -= 1
        return False
            
    def has_connection(self, src_id, dst_id):
        #return False
        key = (connection.KEY_MAP_HOST_FQDNs, src_id, dst_id) 
        if self.conn_table.has(key):
            return True
        else:
            return False

    def get_connection(self, src_id, dst_id):
        key   = (connection.KEY_MAP_HOST_FQDNs, src_id, dst_id) 
        conn  = self.conn_table.get(key)
        return conn

    def process_dns_message(self, dns_cb, cb_args, dst_id, r_cesid="", naptr_list=[]):
        """ Enforce rate limit on DNS NAPTRs served by CETP Engine """
        try:
            if not self.dns_threshold_exceeded():
                
                dns_q, addr      = cb_args
                src_ip, src_port = addr
                key              = (host.KEY_HOST_IPV4, src_ip)
        
                if not self.host_table.has(key):
                    self._logger.error("Sender IP '{}' is not a registered host".format(src_ip))
                    return
    
                host_obj  = self.host_table.get(key)
                src_id    = host_obj.fqdn
                self._logger.info("Connection from '{}'->'{}'".format(src_id, dst_id))
                
                if self.has_connection(src_id, dst_id):
                    conn = self.get_connection(src_id, dst_id)
                    lpip = conn.lpip
                    response = dnsutils.make_response_answer_rr(dns_q, dst_id, dns.rdatatype.A, lpip, rdclass=1, ttl=120, recursion_available=True)
                    dns_cb(dns_q, addr, response)
                else:
                    self.process_cetp(dns_cb, cb_args, dst_id, r_cesid, naptr_list)

        except Exception as ex:
            self._logger.info("Exception '{}' in process_dns_message()".format(ex))
            return


    def process_cetp(self, dns_cb, cb_args, dst_id, r_cesid="", naptr_list=[]):
        """ Enforce rate limit on DNS NAPTRs served by CETP Engine """
        if len(naptr_list)!=0:
            self.process_outbound_cetp(dns_cb, cb_args, dst_id, r_cesid, naptr_list)
        else:
            self.process_local_cetp(dns_cb, cb_args, dst_id)
    
    def process_local_cetp(self, dns_cb, cb_args, dst_id):
        cb = (dns_cb, cb_args)
        self.local_cetp.resolve_cetp(dst_id, cb)

    def process_outbound_cetp(self, dns_cb, cb_args, dst_id, r_cesid, naptr_list):
        """ Gets/Creates the CETPH2H instance AND enqueues the NAPTR response for handling the H2H transactions """
        try:
            if self.has_cetp_endpoint(r_cesid):
                ep = self.get_cetp_endpoint(r_cesid)
                ep.process_naptrs(dst_id, naptr_list, (dns_cb, cb_args))                            # Enqueues the NAPTR response and DNS-callback function.    # put_nowait() on queue will raise exception on a full queue.    - Use try: except:
            else:
                sanitized_naptrs = self._pre_check(naptr_list)
                if sanitized_naptrs == None:
                    self._logger.error(" Cannot initiate CETP endpoint towards CES '{}'".format(r_cesid))
                    return
                else:
                    self._logger.info(" Initiating a CETP-Endpoint towards CES '{}': ".format(r_cesid))
                    ep = self.create_cetp_endpoint(r_cesid)
                    ep.get_cetp_c2c_layer()
                    ep.process_naptrs(dst_id, sanitized_naptrs, (dns_cb, cb_args))                  # Enqueues the NAPTR response and DNS-callback function.    # put_nowait() on queue will raise exception on a full queue.    - Use try: except:
    
        except Exception as ex:
            self._logger.info("Exception '{}' in process_outbound_cetp".format(ex))
            return


    def register_server_endpoint(self, ep):
        self._serverEndpoints.append(ep)
        
    def get_server_endpoints(self):
        """ Provides list of all CETP server endpoints """
        return self._serverEndpoints
        
    def close_server_endpoint(self, ep):
        """ Stops the listening CETP service on (ip, port, proto) """
        if ep in self.get_server_endpoints():
            self._serverEndpoints.remove(ep)
            ep.close()

    def close_server_endpoints(self):
        """ Stops the listening CETP service on all server endpoints """
        for server_ep in self.get_server_endpoints():
            self.close_server_endpoint(server_ep)

    def initiate_cetp_service(self, server_ip, server_port, proto):
        """ Creates CETPServer Endpoint for accepting connections from remote CES """
        try:
            self._logger.info("Initiating CETPServer on {} protocol @ {}.{}".format(proto, server_ip, server_port))
            if proto == "tcp":
                server = yield from self._loop.create_server(lambda: CETPTransports.iCESServerTCPTransport(self._loop, self.ces_params, cetp_mgr=self),\
                                                 host=server_ip, port=server_port)
                
            elif proto == "tls":
                sc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sc.verify_mode = ssl.CERT_REQUIRED
                sc.load_cert_chain(self.ces_certificate_path, self.ces_privatekey_path)
                #sc.check_hostname = True
                sc.load_verify_locations(self.ca_certificate_path)
                server = yield from self._loop.create_server(lambda: CETPTransports.iCESServerTLSTransport(self._loop, self.ces_params, cetp_mgr=self), \
                                                host=server_ip, port=server_port, ssl=sc)
                
            self.register_server_endpoint(server)
            self._logger.info(" CETP Server is listening on '{}' protocol: {}:{}".format(proto.upper(), server_ip, server_port))
            
        except Exception as ex:
            self._logger.warning(" Exception '{}' in creating CETP server on {} protocol @ {}:{}".format(ex, proto, server_ip, server_port))


    # Functions to register/unregister the C2CLayer AND handle newly connected remote endpoints.
    def has_c2c_layer(self, r_cesid):
        return r_cesid in self.c2c_register

    def get_c2c_layer(self, r_cesid):
        return self.c2c_register[r_cesid]

    def create_c2c_layer(self, r_cesid="", cetp_h2h=None):
        """ Creates a C2CLayer for a remote CES-ID """
        cetp_c2c = CETPC2C.CETPC2CLayer(self._loop, l_cesid=self.cesid, r_cesid=r_cesid, cetpstate_table= self.cetpstate_table, policy_mgr=self.policy_mgr, conn_table=self.conn_table, \
                                        ces_params=self.ces_params, cetp_security=self.cetp_security, cetp_mgr=self, cetp_h2h=cetp_h2h, interfaces=self.interfaces, \
                                        payloadID_table=self.payloadID_table)
        
        self.register_c2c_layer(r_cesid, cetp_c2c)
        return cetp_c2c
    
    def register_c2c_layer(self, r_cesid, c2c_layer):
        self.c2c_register[r_cesid] = c2c_layer
        
    def remove_c2c_layer(self, r_cesid):
        if self.has_c2c_layer(r_cesid):
            del self.c2c_register[r_cesid]
            
    def get_all_c2c_layers(self):
        c2c_layers = []
        for cesid, c2clayer in self.c2c_register.items():
            c2c_layers.append(c2clayer)
        return c2c_layers

    def _packetize(self, cetp_msg):
        return json.dumps(cetp_msg)
    
    def _depacketize(self, packet):
        return json.loads(packet)

    def _close_unverified_transport(self, transport):
        """ close_inbound_connected_transport -> """
        ip_addr, port = transport.remotepeer
        self.register_unverifiable_cetp_sender(ip_addr)
        transport.close()

    def _pre_process(self, packet):
        """ Pre-processes the received packet for validity of session tags & CETP version """
        try:
            cetp_msg = self._depacketize(packet)
            inbound_sstag, inbound_dstag, ver = cetp_msg['SST'], cetp_msg['DST'], cetp_msg['VER']
            sstag, dstag    = inbound_dstag, inbound_sstag
            
            if ver!= self.ces_params["CETPVersion"]:
                self._logger.info(" CETP version {} is not supported.".format(ver))
                return
            
            if ( (sstag < 0) or (dstag < 0) or ((sstag==0) and (dstag ==0)) or (inbound_sstag == 0)):
                self._logger.info(" Session tag (SST={}, DST={}) values are invalid".format(sstag, dstag))
                return
            
            if inbound_dstag !=0:
                self._logger.debug(" Possible Attack scanning the session tag sapce?")       # First inbound CETP message shall have DST=0
                return
        
            return cetp_msg
        
        except Exception as ex:
            self._logger.error(" Exception in pre-processing the received message.")
            return None
        

    def process_inbound_message(self, packet, transport):
        """ 
        Pre-processes first few packets received from a newly connected transport, and initiates C2C negotiation upon successful pre-processing.
        """
        cetp_msg = self._pre_process(packet)
        
        if cetp_msg is None:
            self._close_unverified_transport(transport)
            return
        
        asyncio.ensure_future( self.process_c2c_message(cetp_msg, transport) )

    @asyncio.coroutine
    def process_c2c_message(self, cetp_msg, transport):
        """
        Evaluates C2C policy negotiation, and upon success it assigns CETP-H2H and CETP-C2C layer to the connected endpoint
        """
        response = yield from self.process_c2c_negotiation(cetp_msg, transport)
        status, cetp_resp = response
        
        if status == False:
            self._logger.error(" CES-to-CES negotiation failed with remote edge. Closing transport ")
            if len(cetp_resp) != 0:
                cetp_packet = self._packetize(cetp_resp)
                transport.send_cetp(cetp_packet)
                
            self._close_unverified_transport(transport)
            return
            
        elif status == None:
            if len(cetp_resp) != 0:
                self._logger.info(" CES-to-CES negotiation not completed yet -> Send the response packet.")
                cetp_packet = self._packetize(cetp_resp)
                transport.send_cetp(cetp_packet)
        
        elif status == True:
            self._logger.debug(" CES-to-CES policies are negotiated")
            sstag, dstag = cetp_resp['SST'], cetp_resp['DST']
            key = (H2HTransaction.KEY_ESTABLISHED_TAGS, sstag, dstag)
            cetp_transaction = self.cetpstate_table.get(key)
            r_cesid = cetp_transaction.get_remote_cesid()
            
            if not self.has_c2c_layer(r_cesid): 
                self._logger.info(" Create CETP-H2H and CETP-C2C layer")
                self._establish_inbound_cetp_layering(r_cesid, cetp_transaction)
                cetp_packet = self._packetize(cetp_resp)
                transport.send_cetp(cetp_packet)

    
    @asyncio.coroutine
    def process_c2c_negotiation(self, cetp_msg, transport):
        """ Initiates CETP C2C negotiation message  """ 
        inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dstag, inbound_sstag
        r_addr          = transport.get_remotepeer()
        proto           = transport.proto
        r_cesid         = transport.get_remote_cesid()
        self._logger.info("No C2CTransaction (SST={} -> DST={}) exists -> Initiating inbound C2CTransaction".format(inbound_sstag, inbound_dstag))
        
        ic2c_transaction = C2CTransaction.iC2CTransaction(self._loop, r_addr=r_addr, sstag=sstag, dstag=sstag, l_cesid=self.cesid, r_cesid= r_cesid, policy_mgr=self.policy_mgr, \
                                                           cetpstate_table=self.cetpstate_table, ces_params=self.ces_params, proto=proto, cetp_security=self.cetp_security, \
                                                           interfaces=self.interfaces, conn_table=self.conn_table, cetp_mgr=self, payloadID_table=self.payloadID_table)
        response = yield from ic2c_transaction.process_c2c_transaction(cetp_msg)
        return response


    def _establish_inbound_cetp_layering(self, r_cesid, cetp_transaction):
        """ Establishes CETP layering on successfully negotiated C2C relation on an inbound transport from a new remote CES node """
        c2c_layer = self.create_c2c_layer(r_cesid)
        cetp_transaction._assign_c2c_layer(c2c_layer)                
        h2h_layer = self.create_cetp_endpoint(r_cesid, c2c_layer=c2c_layer, c2c_negotiated=True)
        c2c_layer.assign_cetp_h2h_layer(h2h_layer)    # Top layer to handle inbound H2H
        c2c_layer.register_c2c(cetp_transaction)
        c2c_layer.set_c2c_negotiation()
        c2c_layer.set_connectivity()
        connected_transports = self._inbound_transports[r_cesid]
        
        for t in connected_transports:
            t.set_c2c_details(r_cesid, c2c_layer)
            c2c_layer.register_connected_transport(t)
        
        del self._inbound_transports[r_cesid]


    def register_unverifiable_cetp_sender(self, ip_addr):
        self.cetp_security.register_unverifiable_cetp_sender(ip_addr)

    def report_connected_transport(self, transport, r_cesid):
        """ """
        if not self.has_c2c_layer(r_cesid): 
            self._logger.info(" No CETP-C2C layer exists for sender '{}'".format(r_cesid))
            if r_cesid not in self._inbound_transports:
                self._inbound_transports[r_cesid] = [transport]
            else:
                connected_transports = self._inbound_transports[r_cesid]
                connected_transports.append(transport)
        else:
            c2c_layer = self.get_c2c_layer(r_cesid)                 # Gets c2c-layer for remote cesid
            c2c_layer.register_connected_transport(transport)
            transport.set_c2c_details(r_cesid, c2c_layer)
            

    def _pre_check(self, naptr_rrs):
        """ Checks the number of NAPTR records in DNS response; AND filters out the NAPTRs that recently failed connectivity. """
        try:
            if len(naptr_rrs) > self.max_naptrs_per_msg:
                return None                                                     # > 10 naptr_rrs could create high traffic flood
            
            remove_naptrs =  []
            for n_rr in naptr_rrs:
                dst_id, r_cesid, r_ip, r_port, r_proto = n_rr                   # Assumption: All NAPTRs point towards one 'r_cesid'.    (Destination domain is reachable via one CES only)
                key = (r_ip, r_port, r_proto)
                
                if self.cetp_security.is_unreachable_cetp(r_ip, r_port, r_proto):
                    remove_naptrs.append(n_rr)
            
            for p in remove_naptrs:
                naptr_rrs.remove(p)
            
            if len(naptr_rrs)==0:
                return None
            
            return naptr_rrs
        
        except Exception as ex:
            self._logger.error("Exception in_pre_check() '{}'".format(ex))
            return None

        
    """ Functions/Methods supported by CETPManager API, i.e. to drop, terminate or allow connections """
    
    def disable_local_domain(self, local_domain=""):
        """ Disables connection initiations to and from this local_domain """
        if len(local_domain) != 0:
            self.cetp_security.register_filtered_domains(CETPSecurity.KEY_DisabledLHosts, local_domain)                 #Store the domain-name to filter
        
    def block_connections_to_local_domain(self, l_domain="", r_cesid=""):
        """ Reports remote CES to stop sending connection requests to a 'l_domain' destination """
        self.block_local_domain_connections(l_domain=l_domain, r_cesid=r_cesid, to_ldomain=True)
        
    def block_connections_from_local_domain(self, l_domain="", r_cesid=""):
        """ Drops future connections from this local host (to a remote CES) """
        self.block_local_domain_connections(l_domain=l_domain, r_cesid=r_cesid, to_ldomain=False)
        
    def block_local_domain_connections(self, l_domain="", r_cesid="", to_ldomain=True):
        """ Blocks (future) outbound or inbound connections of this local host (towards or from a remote CES node) """
        try:
            if len(l_domain)==0: return
            
            if to_ldomain:
                if len(r_cesid) != 0:
                    keytype = CETPSecurity.KEY_LCES_UnreachableDestinationsForRCES
                    self.cetp_security.register_filtered_domains(keytype, l_domain, key=r_cesid)
                    
                    if self.has_c2c_layer(r_cesid):
                        c2c_layer = self.get_c2c_layer(r_cesid)
                        c2c_layer.drop_connection_to_local_domain(l_domain)
                    
                else:
                    #Store locally to detect non-compliance by remote CES
                    keytype = CETPSecurity.KEY_LocalHosts_Inbound_Disabled
                    self.cetp_security.register_filtered_domains(keytype, l_domain)
                    
            else:
                #Store locally to detect non-compliance by remote CES
                if len(r_cesid) != 0:
                    #Records a host that acted as malicious towards a remote CES
                    keytype = CETPSecurity.KEY_LCES_FilteredSourcesTowardsRCES
                    self.cetp_security.register_filtered_domains(keytype, l_domain, key=r_cesid)
                else:
                    keytype = CETPSecurity.KEY_LocalHosts_Outbound_Disabled
                    self.cetp_security.register_filtered_domains(keytype, l_domain)
                
        except Exception as ex:
            self._logger.info("Exception '{}'".format(ex))
            return


    def blacklist_remote_host(self, r_hostid="", timeout=None):
        """ Blacklists & Drops all the connection to and from to this remote host-id """
        if len(r_hostid) != 0:
            self.cetp_security.register_filtered_domains(CETPSecurity.KEY_BlacklistedRHosts, r_hostid, timeout=timeout)

    def block_connections_from_remote_ces_host(self, r_hostid="", r_cesid=""):
        """ Reports (to block future connections) from a host served by a remote CES-ID """
        self.block_remote_host_connections(r_hostid=r_hostid, r_cesid=r_cesid, to_remoteHost=False)
    
    def block_connections_to_remote_ces_host(self, r_hostid="", r_cesid=""):
        """ Blocks future connections to a host served by a remote CES-ID """
        self.block_remote_host_connections(r_hostid=r_hostid, r_cesid=r_cesid, to_remoteHost=True)
        
    def block_remote_host_connections(self, r_hostid="", r_cesid="", to_remoteHost=True):
        try:
            if len(r_hostid)==0:    return
            
            if to_remoteHost:
                if len(r_cesid) != 0:
                    #Stores the remote-host to be filtered in the security module.         # to detect non-compliance from remote CES
                    keytype = CETPSecurity.KEY_RCES_UnreachableRCESDestinations
                    self.cetp_security.register_filtered_domains(keytype, r_hostid, key=r_cesid)
                    
                else:
                    keytype = CETPSecurity.KEY_RemoteHosts_inbound_Disabled
                    self.cetp_security.register_filtered_domains(keytype, r_hostid)

            else:
                if len(r_cesid) != 0:
                    #Stores the remote-host to be filtered in the security module.         # to detect non-compliance from remote CES
                    keytype = CETPSecurity.KEY_LCES_BlockedHostsOfRCES
                    self.cetp_security.register_filtered_domains(keytype, r_hostid, key=r_cesid)
                
                    #Report malicious-host to remote CES
                    if self.has_c2c_layer(r_cesid):
                        print("Sending request")
                        c2c_layer = self.get_c2c_layer(r_cesid)
                        c2c_layer.block_malicious_remote_host(r_hostid)
                else:
                    keytype = CETPSecurity.KEY_BlacklistedRHosts
                    self.cetp_security.register_filtered_domains(keytype, r_hostid)

        except Exception as ex:
            self._logger.info("Exception '{}'".format(ex))

            
    def terminate_cetp_c2c_signalling(self, r_cesid="", terminate_h2h=False):
        """ Terminates the CETP signalling channel with remote-CESID """
        try:
            if len(r_cesid)==0:
                return
            
            if terminate_h2h:
                self._logger.debug("Terminate all H2H transactions to/from {}".format(r_cesid))
                self.terminate_rces_h2h_sessions(r_cesid)
            
            if self.has_c2c_layer(r_cesid):
                c2c_layer = self.get_c2c_layer(r_cesid)
                c2c_layer.shutdown()
            
        except Exception as ex:
            self._logger.info("Exception '{}' in terminating cetp signalling channel to '{}'".format(ex, r_cesid))


    def terminate_sessions_by_tags(self, tags_list):
        """ Terminates CETP sessions identified as a list of (SST, DST) pairs """
        try:
            for tags in tags_list:
                sstag, dstag = tags
                self.terminate_session_by_tags(sstag, dstag)
                        
        except Exception as ex:
            self._logger.info("Exception '{}' in terminate_sessions_by_tags()".format(ex))


    def terminate_session_by_tags(self, sstag, dstag):
        """ Terminates a CETP session identified by its tags """
        try:
            if (sstag >= 0) and (dstag >= 0):
                key = (H2HTransaction.KEY_ESTABLISHED_TAGS, sstag, dstag)
                
                if self.cetpstate_table.has(key):
                    cetp_transaction = self.cetpstate_table.get(key)
                    cetp_transaction.set_terminated()       # Terminate CETP state and connection instance                     
                    # Reporting to remote CES is not done yet.
                    
        except Exception as ex:
            self._logger.info("Exception '{}' in terminating session".format(ex))
            return
        
    
    def terminate_rces_h2h_sessions(self, r_cesid):
        """ Terminate all H2H sessions to/from a remote-CESID """
        key = (H2HTransaction.KEY_RCESID, r_cesid)
        established_h2h = False
        
        if self.cetpstate_table.has(key):
            cetpstates1 = self.cetpstate_table.get(key)
            cetpstates = copy.copy(cetpstates1)
            
            for cetpstate in cetpstates:
                if cetpstate.name == "H2HTransactionOutbound":
                    if cetpstate.is_negotiated():   established_h2h = True          # Indicates atleast one established H2H session
                    cetpstate.set_terminated()
            
            # Reporting remote CES to close all established CETP session states.
            if established_h2h and self.has_c2c_layer(r_cesid):
                c2c_layer = self.get_c2c_layer(r_cesid)
                c2c_layer.close_all_h2h_sessions()                  

        
    def process_session_terminate_message(self, r_cesid, tag_list=None):
        """ Terminate all H2H sessions with a remote-CESID upon an inbound CETP terminate message 
            @param tag_list: List of session tags provided by the remote CES.
        """
        try:
            keytype  = (H2HTransaction.KEY_RCESID, r_cesid)
            
            if self.cetpstate_table.has(key):
                cetpstates1 = self.cetpstate_table.get(key)
                cetpstates = copy.copy(cetpstates1)
                
                if tag_list is None:
                    self._logger.warning(" Terminating all H2H session with CES '{}'".format(r_cesid))
                    
                    for cetpstate in cetpstates:
                        if cetpstate.name == "H2HTransactionOutbound":
                            cetpstate.set_terminated()
                else:
                    self._logger.warning(" Terminating {} H2H session with CES '{}'".format(len(tag_list), r_cesid))
                    
                    for cetpstate in cetpstates:
                        if cetpstate.name == "H2HTransactionOutbound":
                            sstag, dstag = cetpstate.sstag, cetpstate.dstag
                            if (dstag, sstag) in tag_list:
                                cetpstate.set_terminated()
        except Exception as ex:
            self._logger.error("Exception '{}' in process_session_terminate_message()".format(ex))

        
    def close_dp_connections(self, conn_list=[]):
        """ Deletes a given list of Connection objects """            # Side Question: Does removing the connection state affect ongoing DP connections as well?
        for num in range(0, len(conn_list)):
            conn = conn_list[0]
            conn_list.remove(conn)
            self.conn_table.remove(conn)

    
    def report_misbehavior_evidence(self, sstag=0, dstag=0, lip="", lpip="", evidence=""):
        """ The method is used to send misbehavior evidence observed by the dataplane to a remote CES 
        @params sstag & dstag:     CETP session tags of Host-to-host session for which misbehavior is observed.
        @params lip & lpip:        IP address of the local-host and the proxy-IP address for remote host
        @params evidence:          Evidence of misbehavior/attack observed at data-plane 
        """
        try:
            keytype, key = None, None
            if evidence == "" and ( (sstag <= 0 and dstag <= 0) or (lip == "" and lpip == "") ):
                self._logger.info("Insufficient information to associate misbehavior to a remote host.")
                return

            if (sstag > 0) and (dstag > 0):
                key = (connection.KEY_MAP_CES_TO_CES, sstag, dstag)
            
            elif (len(lip) > 0) and (len(lpip) > 0):
                key = (connection.KEY_MAP_CETP_PRIVATE_NW, lip, lpip)
            
            if self.conn_table.has(key):
                conn = self.conn_table.get(key)
                r_cesid, r_hostid, sstag, dstag = conn.r_cesid, conn.remoteFQDN, conn.sstag, conn.dstag
                self.cetp_security.record_misbehavior_evidence(r_cesid, r_hostid, evidence)
            
                if self.has_c2c_layer(r_cesid):                 # Forward the evidence to remote CES, if C2C-signalling channel is present
                    c2c_layer = self.get_c2c_layer(r_cesid)
                    c2c_layer.report_evidence(sstag, dstag, r_hostid, r_cesid, evidence)
        
        except Exception as ex:
            self._logger.info("Exception '{}' in terminating session".format(ex))


    def terminate_host_session_by_fqdns(self, l_hostid="", r_hostid=""):
        """ Terminates CETP session (and connection) between two hosts specified by their FQDNs """
        key = (connection.KEY_MAP_CES_FQDN, l_hostid, r_hostid)
        self._terminate_host_connections(key)
        
    def terminate_remote_host_sessions(self, r_hostid=""):
        """ Terminates all CETP session with remote host """
        key = (connection.KEY_MAP_REMOTE_FQDN, r_hostid)
        self._terminate_host_connections(key)
        
    def terminate_local_host_sessions(self, l_hostid="", lip=""):
        """ Terminates all CETP sessions to/from a local FQDN """
        if len(l_hostid) != 0:
            self._logger.warning("Terminating sessions of local-hostID '{}'".format(l_hostid))
            key = (connection.KEY_MAP_LOCAL_FQDN, l_hostid)
            self._terminate_host_connections(key)
            
        elif len(lip) != 0:
            self._logger.warning("Terminating sessions of local-hostIP '{}'".format(lip))
            key = (connection.KEY_MAP_LOCAL_HOST, lip)
            self._terminate_host_connections(key)
        

    def _terminate_host_connections(self, key):
        """ Deletes a connection object and corresponding CETP State """
        if self.conn_table.has(key):
            conns = self.conn_table.get(key)
            
            if type(conns) == type(list()):
                for num in range(0, len(conns)):
                    conn = conns[0]
                    self.terminate_host_connection(conn)
                    
            elif type(conns) == type(set()):
                for num in range(0, len(conns)):
                    conn = list(conns)[0]
                    self.terminate_host_connection(conn)
            else:
                conn = conns
                self.terminate_host_connection(conn)
                
        
    def terminate_host_connection(self, conn):
        """ Deletes a connection object provided as input parameter, and corresponding CETP State """
        if conn.connectiontype == "CONNECTION_H2H":
            sstag, dstag = conn.sstag, conn.dstag
            key = (H2HTransaction.KEY_ESTABLISHED_TAGS, sstag, dstag)
            
            if self.cetpstate_table.has(key):
                h2h_transaction = self.cetpstate_table.get(key)
                h2h_transaction.terminate_session()
                self.conn_table.remove(conn)

        if conn.connectiontype=="CONNECTION_LOCAL":
            self.conn_table.remove(conns)


""" Test functions """

def some_cb(dns_q, addr, r_addr=None, success=True):
    """ Dummy callback indicating success/Failure of a negotiation """
    print("H2HTransaction status = '{}'".format(success))

def test_output(cetp_mgr):
    print("\n\nCETP endpoints: ", cetp_mgr._cetp_endpoints )
    print("C2C Layers: ", cetp_mgr.c2c_register )

@asyncio.coroutine   
def test_local_cetp(cetp_mgr):
    sender_info = ("10.0.3.111", 43333)
    dns_cb = (some_cb,(2, sender_info))
    cb_args = (2, sender_info)
    dst_id = "srv1.hosta1.cesa.lte."
    #cetp_mgr.block_connections_to_local_domain(l_domain=dst_id)
    cetp_mgr.process_dns_message(some_cb, cb_args, dst_id)
    yield from asyncio.sleep(2)

@asyncio.coroutine
def test_cetp_layering(cetp_mgr):
    """ Tests the establishment of CETP-H2H, CETP-C2C layer and CETPTransport(s) towards r-ces upon getting a list of NAPTR records."""
    sender_info = ("10.0.3.111", 43333)
    l_hostid, l_hostip = "hosta1.cesa.lte.", sender_info[0]
    dst_id, r_cesid, r_ip, r_port, r_proto = "", "", "", "", ""
    naptr_records = {}
    naptr_records['srv1.hostb1.cesb.lte.']         = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'), ('srv2.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls')]
    print("Initiating H2H negotiation towards '{}'".format(dst_id))
    naptr_list = naptr_records['srv1.hostb1.cesb.lte.']    
    cb_args = ("SomeValue", sender_info)

    dst_id, r_cesid, r_ip, r_port, r_proto = naptr_list[0]
    cetp_mgr.process_dns_message(some_cb, cb_args, dst_id, r_cesid= "cesb.lte.", naptr_list=naptr_list)
    #return (sender_info, naptr_records, l_hostid, l_hostip)
    test_output(cetp_mgr)
    yield from asyncio.sleep(2)
    test_output(cetp_mgr)

def getCETPManager(loop):
    try:
        config_file     = "config_cesa/config_cesa.yaml"
        ces_conf        = yaml.load(open(config_file))
        ces_params      = ces_conf['CESParameters']
        cesid           = ces_params['cesid']
        cetp_policies   = ces_conf["cetp_policy_file"]
        logging.basicConfig(level=logging.DEBUG)
        cetp_mgr = CETPManager(cetp_policies, cesid, ces_params, loop=loop)
        cetp_mgr.initiate_cetp_service("10.0.3.101", 48001, "tls")
        return cetp_mgr
    except Exception as ex:
        print("Exception: ", ex)
    
def test_func(loop):
    asyncio.ensure_future(test_cetp_layering(cetp_mgr))
    #asyncio.ensure_future(test_local_cetp(cetp_mgr))

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    cetp_mgr = getCETPManager(loop)
    if cetp_mgr is not None:    
        print("Ready for testing")
        test_func(loop)
        
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            print("Ctrl+C Handled")
        finally:
            loop.close()
