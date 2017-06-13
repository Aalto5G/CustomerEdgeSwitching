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
import functools

import cetpManager
import CETP
import C2CTransaction
import H2HTransaction
import CETPH2H
import CETPC2C
import CETPTransports
import PolicyManager
import CETPSecurity
import ConnectionTable

LOGLEVEL_CETPManager    = logging.DEBUG            # Any message above this level will be printed.    WARNING > INFO > DEBUG


class CETPManager:
    """
    At CES bootup:      It initiates CETP listening service (on server end-points) to accept the inbound connection from remote CES. 
    On NAPTR response:  It initiates and registers the CETP-H2H instance towards a remote 'cesid' -- (NAPTR response towards new cesid).
                            CETPManager indexes/retrieves the 'CETPH2H' & 'CETPC2C' instance based on 'remote-cesid'. AND enqueues the NAPTR response in the CETPH2H for handling H2H transactions.
    It also aggregates different CETPTransport endpoints from a remote CES-ID under one C2C-Layer.
    """
    
    def __init__(self, cetp_policies, cesid, ces_params, loop=None, name="CETPManager"):
        self._cetp_endpoints        = {}                           # Dictionary of endpoints towards remote CES nodes.
        self._serverEndpoints       = []                           # List of server endpoint offering CETP listening service.
        self.c2c_register           = {}
        self.cesid                  = cesid                        # Local ces-id
        self.ces_params             = ces_params
        self.ces_certificate_path   = self.ces_params['certificate']
        self.ces_privatekey_path    = self.ces_params['private_key']
        self.ca_certificate_path    = self.ces_params['ca_certificate']                                       # Path of X.509 certificate of trusted CA, for validating the remote node's certificate.
        self.cetp_security          = CETPSecurity.CETPSecurity(ces_params)
        self.cetpstate_mgr          = ConnectionTable.CETPStateTable()                                        # Records the established CETP transactions (both H2H & C2C). Required for preventing the re-allocation already in-use SST & DST (in CETP transaction).
        self.conn_table             = ConnectionTable.ConnectionTable()
        self.interfaces             = PolicyManager.Interfaces()
        self.policy_mgr             = PolicyManager.PolicyManager(self.cesid, policy_file= cetp_policies)     # Shall ideally fetch the policies from Policy Management System (of Hassaan)    - And will be called, policy_sys_agent
        self.host_register          = PolicyManager.HostRegister()
        self._loop                  = loop
        self.name                   = name
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPManager)
        self.local_cetp             = CETPH2H.CETPH2HLocal(cetpstate_mgr=self.cetpstate_mgr, policy_mgr=self.policy_mgr, cetp_mgr=self, \
                                                           cetp_security=self.cetp_security, host_register=self.host_register, conn_table=self.conn_table)
        self._loop.call_later(17, self.test_func)

    def test_func(self):
        #self.terminate_local_host_sessions(l_hostid="hosta1.cesa.lte.")
        #self.terminate_local_host_sessions(lip="10.0.3.118")
        #self.terminate_session_tags(200, 100)
        self.terminate_remote_host_session("srv1.hostb1.cesb.lte.")
        print("\nPost deletion check")
        print("CETP session states:\n", self.cetpstate_mgr.cetp_transactions[ConnectionTable.KEY_ESTABLISHED_CETP])
        print("Connection Table:\n", self.conn_table.connection_dict)
        pass
            
        
    def process_dns_message(self, dns_cb, cb_args, dst_id, r_cesid="", naptr_list=[]):
        if len(naptr_list)!=0:
            self.process_outbound_cetp(dns_cb, cb_args, dst_id, r_cesid, naptr_list)
        else:
            self.process_local_cetp(dns_cb, cb_args, dst_id)

    def process_local_cetp(self, dns_cb, cb_args, dst_id):
        cb = (dns_cb, cb_args)
        self.local_cetp.consume_h2h_requests(dst_id, cb)

    def process_outbound_cetp(self, dns_cb, cb_args, dst_id, r_cesid, naptr_list):
        """ Gets/Creates the CETPH2H instance AND enqueues the NAPTR response for handling the H2H transactions """
        try:
            if self.has_cetp_endpoint(r_cesid):
                ep = self.get_cetp_endpoint(r_cesid)
            else:
                self._logger.info("Initiating a CETP-Endpoint towards cesid='{}': ".format(r_cesid))
                ep = self.create_cetp_endpoint(r_cesid)
                ep.create_cetp_c2c_layer(naptr_list)
    
            ep.enqueue_h2h_requests_nowait(naptr_list, (dns_cb, cb_args))                                # Enqueues the NAPTR response and DNS-callback function.    # put_nowait() on queue will raise exception on a full queue.    - Use try: except:
        except Exception as ex:
            self._logger.info("Exception in '{}'".format(ex))
            return


    def create_cetp_endpoint(self, r_cesid, c2c_layer=None, c2c_negotiated=False):
        """ Creates the CETP-H2H layer towards remote CES-ID """
        cetp_ep = CETPH2H.CETPH2H(l_cesid = self.cesid, r_cesid = r_cesid, cetpstate_mgr= self.cetpstate_mgr, policy_mgr=self.policy_mgr, policy_client=None, \
                                  loop=self._loop, cetp_mgr=self, ces_params=self.ces_params, cetp_security=self.cetp_security, host_register=self.host_register, \
                                  interfaces=self.interfaces, c2c_layer=c2c_layer, c2c_negotiated=c2c_negotiated, conn_table=self.conn_table)
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
        for cesid, cetp_ep in self._cetp_endpoints.items():
            cetp_ep.handle_interrupt()

    def terminate_session(self, sstag, dstag, r_cesid="", r_host_id=""):
        pass

    def terminate_session_tags(self, sstag, dstag):
        """ Terminates a particular CETP session """
        try:
            if (sstag!=0) and (dstag!=0):
                if self.cetpstate_mgr.has_established_transaction((sstag, dstag)):
                    cetp_transaction = self.cetpstate_mgr.get_established_transaction((sstag, dstag))
                    self.cetpstate_mgr.remove_established_transaction((sstag, dstag))
                
                #Delete the connection instances from Connection table
                if cetp_transaction.name=="H2HTransactionOutbound":
                    conn = cetp_transaction.conn
                    self.conn_table.delete(conn)
                    cetp_transaction.terminate_session()
                
                elif cetp_transaction.name=="oC2CTransaction":
                    cetp_transaction.set_terminated()                   # TB Encode
                    #conn = cetp_transaction.conn
                    #self.conn_table.remove(conn)
        except Exception as ex:
            self._logger.info("Exception '{}' in terminating session".format(ex))
            return


    def terminate_remote_host_session(self, r_hostid):
        """ Terminates a local CETP session """
        keytype = ConnectionTable.KEY_MAP_REMOTE_FQDN
        key = r_hostid
        if self.conn_table.has(keytype, key):
            conn_list = self.conn_table.get(keytype, key)
            total_connections = len(conn_list)
            for num in range(0, total_connections):
                conn = conn_list[0]
                self.conn_table.delete(conn)
                
                if conn.connectiontype=="CONNECTION_H2H":
                    self._logger.debug("Terminating H2HTransaction state")
                    sstag, dstag = conn.sstag, conn.dstag
                    h2h_transaction = self.cetpstate_mgr.get_established_transaction((sstag,dstag))
                    self.cetpstate_mgr.remove_established_transaction((sstag,dstag))
                    h2h_transaction.terminate_session()

                elif conn.connectiontype=="CONNECTION_LOCAL":
                    self._logger.debug("Terminating Local H2HTransaction")
                    rip, rpip = conn.rip, conn.rpip
                    keytype = ConnectionTable.KEY_MAP_CETP_PRIVATE_NW
                    key = (rip, rpip)
                    r_conn = self.conn_table.get(keytype, key)
                    self.conn_table.delete(r_conn)                                              # Deleting the pair of local connection

            
    def terminate_local_host_sessions(self, l_hostid="", lip=""):
        """ Terminates all sessions to/from a local FQDN """
        if len(l_hostid)!=0:
            self._logger.info("Terminating sessions of local-hostID '{}'".format(l_hostid))
            keytype = ConnectionTable.KEY_MAP_LOCAL_FQDN
            key = l_hostid
        elif len(lip)!=0:
            self._logger.info("Terminating sessions of local-hostIP '{}'".format(lip))
            keytype = ConnectionTable.KEY_MAP_LOCAL_HOST
            key = lip            
        else:
            return
        
        if self.conn_table.has(keytype, key):
            conn_list = self.conn_table.get(keytype, key)
            total_connections = len(conn_list)
            for num in range(0, total_connections):
                conn = conn_list[0]
                #print("Before deleting connection: ", self.conn_table.connection_dict)
                #print("After deleting connection")
                self.conn_table.delete(conn)
                if conn.connectiontype=="CONNECTION_H2H":
                    self._logger.debug("Terminating H2HTransaction state")
                    sstag, dstag = conn.sstag, conn.dstag
                    h2h_transaction = self.cetpstate_mgr.get_established_transaction((sstag,dstag))
                    self.cetpstate_mgr.remove_established_transaction((sstag,dstag))
                    h2h_transaction.terminate_session()
                
                elif conn.connectiontype=="CONNECTION_LOCAL":
                    self._logger.debug("Terminating Local H2HTransaction")
                    rip, rpip = conn.rip, conn.rpip
                    keytype = ConnectionTable.KEY_MAP_CETP_PRIVATE_NW
                    key = (rip, rpip)
                    r_conn = self.conn_table.get(keytype, key)
                    self.conn_table.delete(r_conn)                                              # Deleting the pair of local connection
                    # Terminate at the local transaction at H2HLocalTransaction level.

        
    def terminate_remote_host_sessions(self, r_hostid):
        """ Terminate all sessions to/from a remote-FQDN """
        keytype = ConnectionTable.KEY_MAP_REMOTE_FQDN
        key = r_hostid
        if self.conn_table.has(keytype, key):
            conn_list = self.conn_table.get(keytype, key)
            for conn in conn_list:
                self.conn_table.delete(conn)
                if conn.connectiontype=="CONNECTION_H2H":
                    sstag, dstag = conn.sstag, conn.dstag
                    self.cetpstate_mgr.remove_established_transaction((sstag,dstag))

            
    def terminate_remote_ces_sessions(self, r_cesid):
        """ Terminate all sessions to/from a remote-FQDN """
        keytype = ConnectionTable.KEY_MAP_REMOTE_CESID
        key = r_cesid
        if self.conn_table.has(keytype, key):
            conn_list = self.conn_table.get(keytype, key)
            for conn in conn_list:
                self.conn_table.delete(conn)
                if conn.connectiontype=="CONNECTION_H2H":
                    sstag, dstag = conn.sstag, conn.dstag
                    self.cetpstate_mgr.remove_established_transaction((sstag,dstag))



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


    # Functions to register/unregister the C2CLayer AND handle newly connected remote endpoints.
    def has_c2c_layer(self, r_cesid):
        return r_cesid in self.c2c_register

    def get_c2c_layer(self, r_cesid):
        return self.c2c_register[r_cesid]

    def create_c2c_layer(self, r_cesid="", cetp_h2h=None):
        """ Creates a C2CLayer for a remote CES-ID """
        cetp_c2c = CETPC2C.CETPC2CLayer(self._loop, l_cesid=self.cesid, r_cesid=r_cesid, cetpstate_mgr= self.cetpstate_mgr, policy_mgr=self.policy_mgr, \
                                        ces_params=self.ces_params, cetp_security=self.cetp_security, cetp_mgr=self, cetp_h2h=cetp_h2h)
        
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

    def remote_endpoint_malicious_history(self, ip_addr):
        return False

    def _pre_process(self, msg):
        """ Pre-processes the received packet for validity of session tags & CETP version """
        try:
            self._logger.info(" Initiate/continue C2C-negotiation on new CETP Transport")
            cetp_msg = json.loads(msg)
            inbound_sstag, inbound_dstag, ver = cetp_msg['SST'], cetp_msg['DST'], cetp_msg['VER']
            sstag, dstag    = inbound_dstag, inbound_sstag
            
            if ver!=1:
                self._logger.info(" CETP version is not supported.")
                return False
            
            if ( (sstag==0) and (dstag ==0)) or (sstag < 0) or (dstag < 0) or (inbound_sstag == 0):
                self._logger.info(" Session tag values are invalid")
                return False
            
            if inbound_dstag !=0:
                self._logger.debug(" First inbound CETP message shall have DST=0 -> Attacker is scanning the session tag space?")
                return False
        
            return True
        except Exception as ex:
            self._logger.error(" Exception in pre-processing the received message.")
            return False

    
    def process_inbound_message(self, msg, transport):
        """ Processes first few packets from a newly connected 'endpoint',
        Upon successful negotiation of C2C policies, it assigns CETP-H2H and CETP-C2C layer to the remote CETP endpoint
        """
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
            self._logger.debug(" CES-to-CES policies are negotiated")
            tmp_cetp = json.loads(cetp_resp)
            sstag, dstag = tmp_cetp['SST'], tmp_cetp['DST']
            stateful_transaction = self.cetpstate_mgr.get_established_transaction((sstag, dstag))
            r_cesid = stateful_transaction.r_cesid
            
            if not self.has_c2c_layer(r_cesid): 
                self._logger.info("Create CETP-H2H and CETP-C2C layer")
                c2c_layer = self.create_c2c_layer(r_cesid)
                cetp_ep = self.create_cetp_endpoint(r_cesid, c2c_layer=c2c_layer, c2c_negotiated=True)
                c2c_layer.trigger_cetp_h2h(cetp_ep)    # Top layer to handle inbound H2H
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
            self._logger.info("No C2CTransaction exists -> Initiating inbound C2CTransaction (SST={} -> DST={})".format(inbound_sstag, inbound_dstag))
            peer_addr = transport.remotepeer
            proto     = transport.proto
            ic2c_transaction = C2CTransaction.iC2CTransaction(self._loop, r_addr=peer_addr, sstag=sstag, dstag=sstag, l_cesid=self.cesid, policy_mgr=self.policy_mgr, \
                                                               cetpstate_mgr=self.cetpstate_mgr, ces_params=self.ces_params, proto=proto, transport=transport, cetp_security=self.cetp_security)
            response = ic2c_transaction.process_c2c_transaction(cetp_msg)
            return response

