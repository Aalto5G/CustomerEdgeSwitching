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
import cetpTransaction
import ocetpLayering
import icetpLayering
import PolicyManager

LOGLEVEL_CETPManager    = logging.DEBUG            # Sets the root level of Logger. Any message if this and above level will be printed.    WARNING > INFO > DEBUG
LOGLEVEL_iCETPManager   = logging.INFO


class CETPManager:
    """
    Initiates & Registers CETPServer end-points at CES code boot-up (to accept inbound connection from remote CES).
    Triggers the remote client instances on need. Registers/sorts the remote-client instances against 'cesid'.
    
    Initiates the local client instances on demand towards a remote 'cesid'. Registers/sorts the local-client instances against 'cesid'.
    For a given NAPTR response, it retrieves the 'cesid' & then retrieves the local client instance to remote 'cesid' & enqueues the message to client instance for later processing.
    """
    
    def __init__(self, host_policies, cesid, ces_params, loop=None, name="CETPManager"):
        self._localEndpoints        = {}                           # Dictionary of local client instances to remote CESIDs.
        self._remoteEndpoints       = {}                           # Dictionary of remote client instances to this CESID.
        self._serverEndpoints       = []                           # List of server instances listening for CETP flows.
        self._pending_tasks         = {}                           # Contains the list of tasks that shall be terminated upon closing the CETPClient instance {client1:[task1, task2], client2:[task1, task2]}
        self.cesid                  = cesid                        # Local ces-id
        self.ces_params             = ces_params
        self.ces_certificate_path   = self.ces_params['certificate']
        self.ces_privatekey_path    = self.ces_params['private_key']
        self.ca_certificate_path    = self.ces_params['ca_certificate']                           # X.509 certificate of trusted CA. Used to validate remote node's certificate.
        
        self.cetp_state_mgr         = cetpTransaction.CETPConnectionObject()                      # Records the established CETP transactions (both h2h & c2c). Required for preventing the re-allocation already in-use SST & DST (in CETP transaction).
        self.policy_mgr             = PolicyManager.PolicyManager(policy_file= host_policies)     # Shall ideally fetch the policies from Policy Management System (of Hassaan)    - And will be called, policy_sys_agent
        self._loop                  = loop
        self.ic2c_mgr               = iCETPManager(loop=loop, policy_mgr=self.policy_mgr, cetp_state_mgr=self.cetp_state_mgr, l_cesid=cesid, ces_params=self.ces_params)
        self.name                   = name
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPManager)             # Within this class, logger will only handle message with this or higher level.    (Otherwise, default value of basicConfig() will apply)
        

    def process_outbound_cetp(self, r_cesid, naptr_list, dns_cb_func, cb_args):
        """ Gets/Creates the CETP client instance, and puts the message to process in its queue """
        # What is format of naptr_list?
        if self.has_local_endpoint(r_cesid):
            ep = self.get_local_endpoint(r_cesid)
        else:
            self._logger.info("Initiating a CETP client instance towards cesid '{}': ".format(r_cesid))
            ep = self.create_local_endpoint(self.cesid, r_cesid, naptr_list, dns_cb_func)
        ep.enqueue_h2h_requests_nowait(naptr_list, cb_args)                                                   # This shall enqueue the naptr response as well as the callback function.
        # put_nowait() on queue will raise exception if the queue is full.

    
    def create_local_endpoint(self, l_cesid, r_cesid, naptr_list, dns_cb_func):
        # Gets local cetp endpoint for connecting to this remote CES-ID
        if self.has_local_endpoint(r_cesid) == False:
            client_ep = ocetpLayering.CETPClient(l_cesid = l_cesid, r_cesid = r_cesid, cb_func=dns_cb_func, cetp_state_mgr= self.cetp_state_mgr, \
                                   policy_mgr=self.policy_mgr, policy_client=None, loop=self._loop, ocetp_mgr=self, ces_params=self.ces_params)
            
            self.add_local_endpoint(r_cesid, client_ep)
            client_ep.get_cetp_c2c(naptr_list)                         # naptr_record must have (remote_ip, remote_port, remote_transport, dst_hostid)
        return client_ep


    def has_local_endpoint(self, r_cesid):
        """ Whether CES already has a local client instance for the remote CES-ID """
        return r_cesid in self._localEndpoints

    def add_local_endpoint(self, r_cesid, ep):
        self._localEndpoints[r_cesid] = ep
        
    def get_local_endpoint(self, r_cesid):
        """ Retrieves the local cetp client instance for communicating to the remote CES-ID """
        ep = None
        if self.has_local_endpoint(r_cesid):
            ep = self._localEndpoints[r_cesid]
        return ep

    def remove_local_endpoint(self, r_cesid):
        """ Deletes the local cetp-client endpoint towards the remote CES-ID """
        if self.has_local_endpoint(r_cesid):
            del self._localEndpoints[r_cesid]                     # Hard close? OR shall there be more functionality? allowing packets on the wire to be delivered/received?


    def _get_local_endpoints(self):
        """ Provide list of all local client endpoints """
        end_points = []
        for key, ep in self._localEndpoints.items():
            end_points.append(ep)
        return end_points

    """ Server Endpoint shall have a listening service on advertised (IP, port, proto), and corresponding python object to process a connected client """
    
    def register_server_endpoint(self, ep):
        """ Stores server endpoint """
        self._serverEndpoints.append(ep)
        
    def get_server_endpoints(self):
        """ Provides list of all CETP server endpoints """
        return self._serverEndpoints
        
    def delete_server_endpoint(self, ep):
        """ Removes a given server endpoint from the list of all CETP server endpoints, and stops listening on the server endpoint for new connections.
            The connected remote endpoints can be closed separately
        """
        self._serverEndpoints.remove(ep)
        del ep                                          # Is this a correct way of achieving things?
        #ep.cancel()

    def delete_all_server_endpoints(self):
        """ Stops listening on all server endpoints for new connections """
        pass
        """
        for server_ep in self._serverEndpoints:
            self.delete_server_endpoint(ep)
        """

    def create_server_endpoint(self, server_ip, server_port, transport_proto):
        """ Creates CETPServer Endpoint for accepting connections from remote oCES """
        try:
            self._logger.info("Initiating CETPServer on {} protocol @ {}.{}".format(transport_proto, server_ip, server_port))
            if transport_proto == "tcp":
                protocol_factory = icetpLayering.iCESServerTransportTCP(self._loop, policy_mgr=self.policy_mgr, \
                                                                        cetpstate_mgr=self.cetp_state_mgr, c2c_mgr= self.ic2c_mgr )
                coro = self._loop.create_server(lambda: protocol_factory, host=server_ip, port=server_port)     # pre-created objects or Class() are used with 'lambda'
                                                                                        
            elif transport_proto == "tls":
                sc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sc.verify_mode = ssl.CERT_REQUIRED
                sc.load_cert_chain(self.ces_certificate_path, self.ces_privatekey_path)
                #sc.check_hostname = True
                sc.load_verify_locations(self.ca_certificate_path)
                protocol_factory = icetpLayering.iCESServerTransportTLS(self._loop, self.ces_certificate_path, self.ca_certificate_path, \
                                                                        policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetp_state_mgr, c2c_mgr= self.ic2c_mgr)
                coro = self._loop.create_server(lambda: protocol_factory, host=server_ip, port=server_port, ssl=sc)
                
            server = self._loop.run_until_complete(coro)            # Returns the task object
            self.register_server_endpoint(server)                   # Store the protocol_factory perhaps?    # We store the task object, i.e. for cancelling the task later. Can we close CETPServer etc via task.cancel() thing?
            self._logger.info(' CETP Server is listening on {} protocol: {}:{}'.format(transport_proto, server_ip, server_port))
                
        except Exception as ex:
            self._logger.warning(" Failed to create CETP server on {} protocol @ {}:{}".format(transport_proto, server_ip, server_port))
            self._logger.warning(ex)


    """ Methods for closing Client and Server Endpoints managed by CES  """
        
    def close_local_client_endpoint(self):
        """ Yet to implement """
        pass

    def close_all_local_client_endpoints(self):
        """ Yet to implement """
        for cesid, client_ep in self._localEndpoints.items():
            #self._logger.info("r_cesid: ", cesid)
            #self.remove_local_endpoint(cesid)
            del(client_ep)
    
        # for cesid, ep in self._localEndpoints.items():
        #    ep.enqueue_h2h_requests_nowait(None, ())
        # Some other links to terminate the tassk: http://stackoverflow.com/questions/33505066/python3-asyncio-task-was-destroyed-but-it-is-pending-with-some-specific-condit
        # http://stackoverflow.com/questions/27796294/when-using-asyncio-how-do-you-allow-all-running-tasks-to-finish-before-shutting
        # http://stackoverflow.com/questions/30765606/whats-the-correct-way-to-clean-up-after-an-interrupted-event-loop
        
    def close_connected_remote_endpoint(self, ep):
        """ Not very apparent, how this can be done in CETPManager class, as it doesn't instantiate it"""
        pass
    
    def close_all_connected_remote_endpoints(self):
        """ Not very apparent, how this can be done in CETPManager class, as it doesn't instantiate it"""
        pass


    def close_all(self):
        """Closes all the server endpoints, all the local client endpoints, and all the remote client endpoints 
            This can be useful, for example in gracefully closing the CES (which may be in interaction with many remote endpoints).
        """
        # self.delete_all_server_endpoints()
        self.close_all_local_client_endpoints()
        #self.close_all_connected_remote_endpoints()


    """ To terminate the pending asyncio tasks """
    def has_client(self, client):
        return client in self._pending_tasks

    def add_pending_tasks(self, client, task):
        if not self.has_client(client):
            self._pending_tasks[client] = [task]
        else:
            self._pending_tasks[client].append(task)
    
    def get_pending_tasks(self, client):
        for k, v in self._pending_tasks.items():
            if k == client:
                return v
        return None

    def get_all_pending_tasks(self):
        tsks = []
        for k, task_list in self._pending_tasks.items():
            for tsk in task_list:
                tsks.append(tsk)
        return tsks

    def close_all_pending_tasks(self):
        """ Terminating the tasks pending per client """
        for client, tsk_list in self._pending_tasks.items():
            for tsk in tsk_list:
                self._logger.warning("Closing a task")
                tsk.cancel() 
        
    """
    For consolidated management of things, (i.e. initiatied tasks)
    its probably best that c2cLayer for remote end is instantiated by the CETPManager, upon request from CETPClient.
    """


        
class iCETPManager:
    """ 
    This is a manager class, which aggregates different Transport endpoints from a remote CESID, such that at end there is only one c2c-layer between two CES nodes.
    """
    def __init__(self, loop=None, policy_mgr=None, cetp_state_mgr=None, l_cesid=None, ces_params=None, name="iCETPManager"):
        self._loop              = loop
        self.policy_mgr         = policy_mgr
        self.cetpstate_mgr      = cetp_state_mgr
        self.l_cesid            = l_cesid
        self.ces_params         = ces_params
        
        self.c2c_store          = {}               # Registers a c2clayer corresponding to a remote 'cesid' --- Format: {cesid1: c2c_layer, cesid2: c2c_layer}
        self.t2t_store          = {}               # Registers a t2tlayer corresponding to a remote 'cesid' --- Format: {cesid1: t2t_layer, cesid2: t2t_layer}
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCETPManager)

    def has_c2c_layer(self, cesid):
        return cesid in self.c2c_store

    def get_c2c_layer(self, cesid):
        return self.c2c_store[cesid]

    def delete_c2c_layer(self, cesid):
        if cesid in self.c2c_store:
            del self.c2c_store[cesid]

    def get_all_c2c_layers(self):
        c2c_layers = []
        for cesid, c2clayer in self.c2c_store:
            c2c_layers.append(c2clayer)
            
        return c2c_layers
    
    def remote_endpoint_malicious_history(self, ip_addr):
        """ If remote node has previous history of misbehavior and if it exceededed a threshold"""
        return False

    def create_c2c_layer(self, r_cesid, c2c_transaction):
        """ Creates a new c2cLayer for cesid.. And to it passes the negotiated ces-to-ces transaction """
        ic2c_layer = icetpLayering.iCETPC2CLayer(r_cesid, self)
        ic2c_layer.add_c2c_transactions(c2c_transaction)
        self.c2c_store[r_cesid] = ic2c_layer
        return ic2c_layer
        
    def process_new_sender(self, msg, transport):
        self.process_c2c_transaction(msg, transport)

    def process_c2c_transaction(self, msg, transport):
        """ The method is called on the first (or subsequent) packet from a remote CES, until C2C-policies are negotiated """
        self._logger.info(" New CETP Transport connected -> Initiate/continue C2C-negotiation")
        # A possible use of transport is to filter the remote IP, if it has misbehavior history.
        peer_addr = transport.peername
        (ip, port) = peer_addr
        # if sender_has_blacklisted_history(ip): return False            # When I have the security processing module implemented.
        
        cetp_resp, ic2c_transaction = self.prcoess_c2c_negotiation(msg, transport)
        (status, cetp_resp) = cetp_resp
        
        if status == False:
            self._logger.info(" CES-to-CES negotiation failed with remote edge -> Send(cetp_error_response) AND close the transport.")
            if len(cetp_resp) ==0:
                transport.send(cetp_resp)
            transport.close()
            
        elif status == None:
            self._logger.info(" CES-to-CES negotiation not completed yet -> Send C2C response packet.")
            transport.send_cetp(cetp_resp)
        
        elif status==True:
            self._logger.info(" CES-to-CES policies negotiated -> Assign CETPServer and C2CLayer (Retrieve cesid)")
            # Upon success, store stateful version of the inbound-c2c transaction.
            
            tmp_cetp = json.loads(cetp_resp)
            sstag, dstag = tmp_cetp['SST'], tmp_cetp['DST']
            stateful_transaction = self.cetpstate_mgr.get((sstag, dstag))
            
            r_cesid = "cesa"                                      # For testing
            if self.has_c2c_layer(r_cesid) == False: 
                c2c_layer = self.create_c2c_layer(r_cesid, stateful_transaction)                                                # Pass the completed c2c transaction as well
                c2c_layer.add_connected_transport(transport)
                c2c_layer.create_cetp_server(r_cesid, self._loop, self.policy_mgr, self.cetpstate_mgr, self.l_cesid)        # Top layer to handling H2H
                transport.set_cesid(r_cesid)
                transport.assign_c2c(c2c_layer)                                                                             # Assign c2c-layer for ’cesid’ to transport
                
            elif self.has_c2c_layer(r_cesid) == True:
                c2c_layer = self.get_c2c_layer(r_cesid)           # Existing c2c layer for remote ’cesid’
                c2c_layer.add_connected_transport(transport)
                transport.assign_c2c(c2c_layer)                   # Assigns  c2c-layer to CETPtransport
                #self.append_active_c2c_transaction_id(cetp_obj.sst, cetp_obj.dst)       # Commented for now    # CETP response active (CSST, CDST) session tags to use for c2c communication.
                
            transport.send_cetp(cetp_resp)


    def prcoess_c2c_negotiation(self, msg, transport):
        """ Pre-processes the received packet... Checks whether it is a new or existing CETP-C2C negotiation from a legitimate node... """ 
        try:
            cetp_msg = json.loads(msg)
            inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
            sstag, dstag    = inbound_dstag, inbound_sstag
        except Exception as msg:
            self._logger.error("Exception in parsing the received message.")
            return

        if inbound_sstag == 0:
            self._logger.error("Inbound SST cannot be zero")     # As this would mean that sender has not choosen any SST, and upon negotiation completion cetp-session state would be (0, DST)
            return None
            
        if self.cetpstate_mgr.has((sstag, dstag)):
            oc2c = self.cetpstate_mgr.get((sstag, dstag))
            self._logger.info("Outbound C2CTransaction found for (SST={}, DST={})".format(inbound_sstag, inbound_dstag))
            cetp_resp = oc2c.post_c2c_negotiation(cetp_msg)
            return cetp_resp
        
        elif inbound_dstag == 0:
            self._logger.info("No prior Outbound C2CTransaction found... Initiating Inbound C2CTransaction (SST={} -> DST={})".format(inbound_sstag, inbound_dstag))
            #time.sleep(10.0)
            peer_addr = transport.peername
            ic2c_transaction = cetpTransaction.iC2CTransaction(self._loop, r_addr=peer_addr, sstag=sstag, dstag=sstag, l_cesid=self.l_cesid, policy_mgr=self.policy_mgr, \
                                                               cetpstate_mgr=self.cetpstate_mgr, ces_params=self.ces_params, proto="tls")           # Better way of detecting if underlying transport is TCP or TLS.
            cetp_resp = ic2c_transaction.process_c2c_transaction(cetp_msg)
            return (cetp_resp, ic2c_transaction)

        # Incorporate the paper work, you did to prevent abuse of (SST,0) states from remote entity for messing up the connection state table, or CETP state table.

