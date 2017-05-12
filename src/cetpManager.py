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
import ssl
import cetpManager
import CETP
import C2CTransaction
import H2HTransaction
import ocetpLayering
import icetpLayering
import PolicyManager
import CETPSecurity

LOGLEVEL_CETPManager    = logging.DEBUG            # Sets the root level of Logger. Any message of this and above level will be printed.    WARNING > INFO > DEBUG
LOGLEVEL_iCETPManager   = logging.INFO


class CETPManager:
    """
    At CES bootup: Initiates & Registers CETPServer end-points, to accept the inbound connection from remote CES.
    On demand: Initiates (and registers) the local client instances towards a remote 'cesid'.
        Operation:   For a given NAPTR response, CETPManager retrieves the 'cesid' & then gets the local client instance towards remote 'cesid. It then enqueues the NAPTR response in a queue for handling H2H transactions.
    
    Not tested: Registers the remote-client instances as per 'cesid'. And management
    """
    
    def __init__(self, cetp_policies, cesid, ces_params, loop=None, name="CETPManager"):
        self._localEndpoints        = {}                           # Dictionary of local client instances to remote CESIDs.
        self._remoteEndpoints       = {}                           # Dictionary of remote client instances connected to this CES.
        self._serverEndpoints       = []                           # List of server instances listening for CETP flows.
        self.cesid                  = cesid                        # Local ces-id
        self.ces_params             = ces_params
        self.ces_certificate_path   = self.ces_params['certificate']
        self.ces_privatekey_path    = self.ces_params['private_key']
        self.ca_certificate_path    = self.ces_params['ca_certificate']                                       # Path of X.509 certificate of trusted CA, for validating the remote node's certificate.
        self.cetp_security          = CETPSecurity.CETPSecurity(ces_params)
        self.cetpstate_mgr          = CETP.CETPConnectionObject()                                             # Records the established CETP transactions (both H2H & C2C). Required for preventing the re-allocation already in-use SST & DST (in CETP transaction).
        self.policy_mgr             = PolicyManager.PolicyManager(self.cesid, policy_file= cetp_policies)     # Shall ideally fetch the policies from Policy Management System (of Hassaan)    - And will be called, policy_sys_agent
        self.host_register          = PolicyManager.HostRegister()
        self._loop                  = loop
        self.name                   = name
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPManager)
        self.ic2c_mgr               = iCETPManager(loop=loop, policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr, l_cesid=cesid, ces_params=self.ces_params, cetp_security=self.cetp_security)
        

    def process_outbound_cetp(self, r_cesid, naptr_list, dns_cb_func, cb_args):
        """ Gets/Creates the CETP client instance, and puts the NAPTR response in a queue for handling the H2H transactions """
        # Expected format of NAPTR_response: (remote_ip, remote_port, remote_transport, dst_hostid)        - Assumption: All NAPTRs point towards one 'r_cesid'.    (Detsination domain is connected to one 'cesid' only)
        
        if self.has_local_endpoint(r_cesid):
            ep = self.get_local_endpoint(r_cesid)
        else:
            self._logger.info("Initiating a CETP client instance towards cesid '{}': ".format(r_cesid))
            ep = self.create_local_endpoint(self.cesid, r_cesid, naptr_list, dns_cb_func)
        ep.enqueue_h2h_requests_nowait(naptr_list, cb_args)                                # Enqueues the NAPTR response and DNS-callback function.
        # put_nowait() on queue will raise exception if the queue is full.    - Need for try: except:

    
    def create_local_endpoint(self, l_cesid, r_cesid, naptr_list, dns_cb_func):
        """ Creates the local CETPClient for connecting to the remote CES-ID """
        client_ep = ocetpLayering.CETPClient(l_cesid = l_cesid, r_cesid = r_cesid, cb_func=dns_cb_func, cetpstate_mgr= self.cetpstate_mgr, policy_mgr=self.policy_mgr, \
                                             policy_client=None, loop=self._loop, ocetp_mgr=self, ces_params=self.ces_params, cetp_security=self.cetp_security, host_register=self.host_register)
        
        self.add_local_endpoint(r_cesid, client_ep)
        client_ep.create_cetp_c2c_layer(naptr_list)
        return client_ep


    def has_local_endpoint(self, r_cesid):
        """ If client instance towards r_cesid exists """
        return r_cesid in self._localEndpoints

    def add_local_endpoint(self, r_cesid, ep):
        self._localEndpoints[r_cesid] = ep
        
    def get_local_endpoint(self, r_cesid):
        """ Retrieves the CETPClient instance towards r_cesid """
        return self._localEndpoints[r_cesid]

    def remove_local_endpoint(self, r_cesid):
        """ Removes the local CETPClient instance towards the r_cesid, from the list of connected clients to remote endpoints  """
        if self.has_local_endpoint(r_cesid):
            del self._localEndpoints[r_cesid]                     

    def _get_local_endpoints(self):
        """ Provides the list of all the local client endpoints """
        end_points = []
        for key, ep in self._localEndpoints.items():
            end_points.append(ep)
        return end_points

    def register_server_endpoint(self, ep):
        self._serverEndpoints.append(ep)
        
    def get_server_endpoints(self):
        """ Provides list of all CETP server endpoints """
        return self._serverEndpoints
        
    def close_server_endpoint(self, ep):
        """ Stops listening the CETP service on (Ip, port, proto) """
        if ep in self.get_server_endpoints():
            self._serverEndpoints.remove(ep)
            ep.close()

    def close_server_endpoints(self):
        """ Stops the listening CETP service on all server endpoints """
        for server_ep in self.get_server_endpoints():
            self.close_server_endpoint(server_ep)

    def initiate_cetp_service(self, server_ip, server_port, proto):
        """ Creates CETPServer Endpoint for accepting connections from remote oCES """
        try:
            self._logger.info("Initiating CETPServer on {} protocol @ {}.{}".format(proto, server_ip, server_port))
            if proto == "tcp":
                coro = self._loop.create_server(lambda: icetpLayering.iCESServerTransportTCP(self._loop, self.ces_params, c2c_mgr= self.ic2c_mgr ),\
                                                 host=server_ip, port=server_port)             # Not utilizing any pre-created objects.
                
            elif proto == "tls":
                sc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sc.verify_mode = ssl.CERT_REQUIRED
                sc.load_cert_chain(self.ces_certificate_path, self.ces_privatekey_path)
                #sc.check_hostname = True
                sc.load_verify_locations(self.ca_certificate_path)
                coro = self._loop.create_server(lambda: icetpLayering.iCESServerTransportTLS(self._loop, self.ces_params, self.ces_certificate_path, self.ca_certificate_path, \
                                                                                             c2c_mgr= self.ic2c_mgr), host=server_ip, port=server_port, ssl=sc)
                
            server = self._loop.run_until_complete(coro)            # Returns the server
            self.register_server_endpoint(server)
            self._logger.info(' CETP Server is listening on {} protocol: {}:{}'.format(proto, server_ip, server_port))
                
        except Exception as ex:
            self._logger.warning(" Failed to create CETP server on {} protocol @ {}:{}".format(proto, server_ip, server_port))
            self._logger.warning(ex)


    def close_local_client_endpoint(self, r_cesid):
        """ Closes CETPClient towards a remote cesid """
        for cesid, client_ep in self._localEndpoints.items():
            if cesid == r_cesid:
                client_ep.handle_interrupt()
        
    def close_all_local_client_endpoints(self):
        """ Closes CETPClient instances towards remote CES """
        for cesid, client_ep in self._localEndpoints.items():
            client_ep.handle_interrupt()
    
    def close_connected_remote_endpoint(self, r_cesid):
        """ Closes the connection from remote CETPClient """
        self.ic2c_mgr.delete_c2c_layer(r_cesid)
    
    def close_all_connected_remote_endpoints(self):
        """ Closes the connection from remote CETPClients """
        for c2c_layer in self.ic2c_mgr.get_all_c2c_layers():
            c2c_layer.handle_interrupt()
        
    # Asyncio.Task has a method to get list of all ongoing or pending tasks.
    # C2C-Layer could be instantiated by the CETPManager, upon request from CETPClient.


        
class iCETPManager:
    """ 
    Manager class for inbound CETPClients
    1. Aggregates different CETP Transport endpoints from a remote CES-ID under one C2C-Layer between CES nodes.
    """
    def __init__(self, loop=None, policy_mgr=None, cetpstate_mgr=None, l_cesid=None, ces_params=None, cetp_security=None, name="iCETPManager"):
        self._loop              = loop
        self.policy_mgr         = policy_mgr
        self.cetpstate_mgr      = cetpstate_mgr
        self.l_cesid            = l_cesid
        self.ces_params         = ces_params
        self.cetp_security      = cetp_security
        self.c2c_register       = {}                        # Registers a c2clayer corresponding to a remote 'cesid' --- Format: {cesid1: c2c_layer, cesid2: c2c_layer}
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCETPManager)

    def has_c2c_layer(self, r_cesid):
        return r_cesid in self.c2c_register

    def get_c2c_layer(self, r_cesid):
        return self.c2c_register[r_cesid]

    def delete_c2c_layer(self, r_cesid):
        if self.has_c2c_layer(r_cesid):
            del self.c2c_register[r_cesid]
            
    def register_c2c_layer(self, r_cesid, ic2c_layer):
        self.c2c_register[r_cesid] = ic2c_layer
        
    def get_all_c2c_layers(self):
        c2c_layers = []
        for cesid, c2clayer in self.c2c_register.items():
            c2c_layers.append(c2clayer)
        return c2c_layers
    
    def remote_endpoint_malicious_history(self, ip_addr):
        """ Informs whether the remote node has history of misbehavior """
        return False

    def create_c2c_layer(self, r_cesid):
        """ Creates a new c2cLayer for cesid AND passes the negotiated ces-to-ces transaction """
        ic2c_layer = icetpLayering.iCETPC2CLayer(r_cesid, self)
        self.register_c2c_layer(r_cesid, ic2c_layer)
        return ic2c_layer
    
    def _pre_process(self, msg):
        """ Pre-processes the received packet """
        try:
            self._logger.info(" Initiate/continue C2C-negotiation on new CETP Transport")
            cetp_msg = json.loads(msg)
            inbound_sstag, inbound_dstag, ver = cetp_msg['SST'], cetp_msg['DST'], cetp_msg['VER']
            sstag, dstag    = inbound_dstag, inbound_sstag
            
            if ( (sstag==0) and (dstag ==0)) or (sstag < 0) or (dstag < 0) or (inbound_sstag == 0):
                self._logger.info(" Session tag values are not acceptable")
                return False
            
            if inbound_dstag !=0:
                self._logger.debug(" iCETPManager does not processes completed CETPTransactions.")
                self._logger.warning(" Remote endpoint is scanning the Session-Tag space? ")
                return False
        
            if ver!=1:
                self._logger.info(" The CETP version is not supported.")
                return False
            
        except Exception as ex:
            self._logger.error(" Exception in pre-processing the received message.")
            return False

        return True
        # is iCES secure against a remote-connected CES from scanning the CETP session states table?
        
    
    def process_inbound_message(self, msg, transport):
        """ Processes first few packets from a newly connected 'endpoint', until the C2C-policies are negotiated. """
        result = self._pre_process(msg)
        if result == False:
            transport.close()
        
        (status, cetp_resp) = self.prcoess_c2c_negotiation(msg, transport)
        
        if status == False:
            self._logger.info(" CES-to-CES negotiation failed with remote edge.")
            if len(cetp_resp) !=0:
                self._logger.debug(" Sending CETP error_response, and closing the transport.")
                transport.send_cetp(cetp_resp)
            transport.close()
            
        elif status == None:
            self._logger.info(" CES-to-CES negotiation not completed yet -> Send the response packet.")
            transport.send_cetp(cetp_resp)
        
        elif status==True:
            self._logger.debug(" CES-to-CES policies negotiated -> Create CETPServer and C2CLayer")
            tmp_cetp = json.loads(cetp_resp)
            sstag, dstag = tmp_cetp['SST'], tmp_cetp['DST']
            stateful_transaction = self.cetpstate_mgr.get_established_transaction((sstag, dstag))
            r_cesid = stateful_transaction.r_cesid
            
            if not self.has_c2c_layer(r_cesid): 
                c2c_layer = self.create_c2c_layer(r_cesid)
                c2c_layer.create_cetp_server(r_cesid, self._loop, self.policy_mgr, self.cetpstate_mgr, self.l_cesid)    # Top layer to handle inbound H2H            
            else:
                c2c_layer = self.get_c2c_layer(r_cesid)                 # Gets existing c2c-layer for remote ’cesid’
            
            c2c_layer.register_transport_c2cTransaction(transport, stateful_transaction)
            transport.set_c2c_details(r_cesid, c2c_layer)
            transport.send_cetp(cetp_resp)


    def prcoess_c2c_negotiation(self, msg, transport):
        """ Checks whether inbound message is part of existing or new CETP-C2C negotiation from a legitimate node... """ 
        cetp_msg = json.loads(msg)
        inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dstag, inbound_sstag
        
        if not self.cetpstate_mgr.has_initiated_transaction( (sstag, dstag)):
            self._logger.info("No prior Outbound C2CTransaction -> Initiating inbound C2CTransaction (SST={} -> DST={})".format(inbound_sstag, inbound_dstag))
            peer_addr = transport.peername
            proto     = transport.proto
            ic2c_transaction = C2CTransaction.iC2CTransaction(self._loop, r_addr=peer_addr, sstag=sstag, dstag=sstag, l_cesid=self.l_cesid, policy_mgr=self.policy_mgr, \
                                                               cetpstate_mgr=self.cetpstate_mgr, ces_params=self.ces_params, proto=proto, transport=transport, cetp_security=self.cetp_security)
            response = ic2c_transaction.process_c2c_transaction(cetp_msg)
            return response
        

