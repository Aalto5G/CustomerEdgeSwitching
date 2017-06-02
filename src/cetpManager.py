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
import CETPH2H
import CETPC2C
import CETPTransports
import PolicyManager
import CETPSecurity

LOGLEVEL_CETPManager    = logging.DEBUG            # Any message above this level will be printed.    WARNING > INFO > DEBUG


class CETPManager:
    """
    At CES bootup:  It initiates CETPServer end-points to accept the inbound connection from remote CES.
    On demand:      It initiates and registers the local CETP-H2H instance towards a remote 'cesid' -- triggered by NAPTR response.
                        CETPManager indexes/retrieves the 'CETPClient' based on 'remote-cesid'. AND  enqueues the NAPTR response in the client for handling H2H transactions.
    
    TBD:             Aggregating/Registering the CETP-H2H instances (and CETP Transport instance) triggered by remote CES under one 'cesid'. [In a repository] 
                     Aggregates different CETPTransport endpoints from a remote CES-ID under one C2C-Layer between CES nodes.
    """
    
    def __init__(self, cetp_policies, cesid, ces_params, loop=None, name="CETPManager"):
        self._cetp_endpoints        = {}                           # Dictionary of local client instances to remote CESIDs.
        self._serverEndpoints       = []                           # List of server instances listening for CETP flows.
        self.c2c_register           = {}
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

    def process_outbound_cetp(self, r_cesid, naptr_list, dns_cb_func, cb_args):
        """ Gets/Creates the CETPH2H instance AND enqueues the NAPTR response for handling the H2H transactions """
        if self.has_cetp_endpoint(r_cesid):
            ep = self.get_cetp_endpoint(r_cesid)
        else:
            self._logger.info("Initiating a CETP-Endpoint towards cesid='{}': ".format(r_cesid))
            ep = self.create_client_endpoint(self.cesid, r_cesid, naptr_list, dns_cb_func)
        ep.enqueue_h2h_requests_nowait(naptr_list, (dns_cb_func, cb_args))                                # Enqueues the NAPTR response and DNS-callback function.    # put_nowait() on queue will raise exception on a full queue.    - Use try: except:

    def create_client_endpoint(self, l_cesid, r_cesid, naptr_list, dns_cb_func):
        """ Creates the local CETPClient for connecting to the remote CES-ID """
        cetp_ep = CETPH2H.CETPH2H(l_cesid = l_cesid, r_cesid = r_cesid, cetpstate_mgr= self.cetpstate_mgr, policy_mgr=self.policy_mgr, policy_client=None, \
                                  loop=self._loop, cetp_mgr=self, ces_params=self.ces_params, cetp_security=self.cetp_security, host_register=self.host_register)
        
        self.add_cetp_endpoint(r_cesid, cetp_ep)
        cetp_ep.create_cetp_c2c_layer(naptr_list)
        return cetp_ep

    def has_cetp_endpoint(self, r_cesid):
        """ If CETPEndpoint towards r_cesid exists """
        return r_cesid in self._cetp_endpoints

    def add_cetp_endpoint(self, r_cesid, ep):
        self._cetp_endpoints[r_cesid] = ep
        
    def get_cetp_endpoint(self, r_cesid):
        """ Retrieves the CETPEndpoint towards r_cesid """
        return self._cetp_endpoints[r_cesid]

    def remove_cetp_endpoint(self, r_cesid):
        """ Removes the CETPEndpoint instance towards the r_cesid, from the list of connected clients to remote endpoints  """
        if self.has_cetp_endpoint(r_cesid):
            del self._cetp_endpoints[r_cesid]                     

    def _get_cetp_endpoints(self):
        """ Provides the list of all the local CETPEndpoints """
        end_points = []
        for key, ep in self._cetp_endpoints.items():
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
                coro = self._loop.create_server(lambda: CETPTransports.iCESServerTCPTransport(self._loop, self.ces_params, cetp_mgr=self),\
                                                 host=server_ip, port=server_port)             # Not utilizing any pre-created objects.
                
            elif proto == "tls":
                sc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sc.verify_mode = ssl.CERT_REQUIRED
                sc.load_cert_chain(self.ces_certificate_path, self.ces_privatekey_path)
                #sc.check_hostname = True
                sc.load_verify_locations(self.ca_certificate_path)
                coro = self._loop.create_server(lambda: CETPTransports.iCESServerTLSTransport(self._loop, self.ces_params, self.ces_certificate_path, self.ca_certificate_path, \
                                                                                             cetp_mgr=self), host=server_ip, port=server_port, ssl=sc)
                
            server = self._loop.run_until_complete(coro)            # Returns the server
            self.register_server_endpoint(server)
            self._logger.info(' CETP Server is listening on {} protocol: {}:{}'.format(proto, server_ip, server_port))
                
        except Exception as ex:
            self._logger.warning(" Failed to create CETP server on {} protocol @ {}:{}".format(proto, server_ip, server_port))
            self._logger.warning(ex)


    def close_cetp_endpoint(self, r_cesid):
        """ Closes CETPEndpoint towards a remote cesid """
        for cesid, cetp_ep in self._cetp_endpoints.items():
            if cesid == r_cesid:
                cetp_ep.handle_interrupt()
        
    def close_all_cetp_endpoints(self):
        """ Closes CETPEndpoint instances towards remote CES """
        for cesid, cetp_ep in self._cetp_endpoints.items():
            cetp_ep.handle_interrupt()
    
    # Asyncio.Task has a method to get list of all ongoing or pending tasks.
    # Functions from inbound CETPManager 
    
    def remote_endpoint_malicious_history(self, ip_addr):
        return False

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

    def create_c2c_layer(self, r_cesid):
        """ Creates a new c2cLayer for cesid AND passes the negotiated ces-to-ces transaction """
        cetp_c2c = CETPC2C.CETPC2CLayer(self._loop, l_cesid=self.cesid, r_cesid=r_cesid, cetpstate_mgr= self.cetpstate_mgr, policy_mgr=self.policy_mgr, \
                                         ces_params=self.ces_params, cetp_security=self.cetp_security, cetp_mgr=self)
        
        self.register_c2c_layer(r_cesid, cetp_c2c)
        return cetp_c2c

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
                self._logger.debug(" CETPManager does not processes completed CETPTransactions.")
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
            self._logger.debug(" CES-to-CES policies negotiated")
            tmp_cetp = json.loads(cetp_resp)
            sstag, dstag = tmp_cetp['SST'], tmp_cetp['DST']
            stateful_transaction = self.cetpstate_mgr.get_established_transaction((sstag, dstag))
            r_cesid = stateful_transaction.r_cesid
            
            if not self.has_c2c_layer(r_cesid): 
                self._logger.info("Create CETP-H2H and CETP-C2C layer")
                c2c_layer = self.create_c2c_layer(r_cesid)
                c2c_layer.create_cetp_h2h(r_cesid, self.policy_mgr, self.cetpstate_mgr, self.cesid, self.ces_params, self.cetp_security, self.host_register)    # Top layer to handle inbound H2H
                c2c_layer.c2c_negotiated = True
            else:
                c2c_layer = self.get_c2c_layer(r_cesid)                 # Gets existing c2c-layer for remote ’cesid’
            
            stateful_transaction._assign_c2c_layer(c2c_layer)
            c2c_layer.register_c2c_transport(transport, stateful_transaction)
            transport.set_c2c_details(r_cesid, c2c_layer)
            transport.send_cetp(cetp_resp)


    def prcoess_c2c_negotiation(self, msg, transport):
        """ Checks whether inbound message is part of existing or new CETP-C2C negotiation from a legitimate node... """ 
        cetp_msg = json.loads(msg)
        inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dstag, inbound_sstag
        
        if not self.cetpstate_mgr.has_initiated_transaction( (sstag, dstag)):
            self._logger.info("No prior Outbound C2CTransaction -> Initiating inbound C2CTransaction (SST={} -> DST={})".format(inbound_sstag, inbound_dstag))
            peer_addr = transport.remotepeer
            proto     = transport.proto
            ic2c_transaction = C2CTransaction.iC2CTransaction(self._loop, r_addr=peer_addr, sstag=sstag, dstag=sstag, l_cesid=self.cesid, policy_mgr=self.policy_mgr, \
                                                               cetpstate_mgr=self.cetpstate_mgr, ces_params=self.ces_params, proto=proto, transport=transport, cetp_security=self.cetp_security)
            response = ic2c_transaction.process_c2c_transaction(cetp_msg)
            return response
        
