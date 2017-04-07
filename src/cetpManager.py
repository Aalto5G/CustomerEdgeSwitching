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

LOGLEVEL_CETPManager    = logging.DEBUG            # Sets the root level of Logger. Any message of this and above level will be printed.    WARNING > INFO > DEBUG
LOGLEVEL_iCETPManager   = logging.INFO


class CETPManager:
    """
    At CES bootup: Initiates & Registers CETPServer end-points, to accept the inbound connection from remote CES.
    On demand: Initiates (and registers) the local client instances towards a remote 'cesid'.
        Operation:   For a given NAPTR response, CETPManager retrieves the 'cesid' & then gets the local client instance towards remote 'cesid. It then enqueues the NAPTR response in a queue for handling H2H transactions.
    
    Not tested: Registers the remote-client instances as per 'cesid'. And management
    """
    
    def __init__(self, host_policies, cesid, ces_params, loop=None, name="CETPManager"):
        self._localEndpoints        = {}                           # Dictionary of local client instances to remote CESIDs.
        self._remoteEndpoints       = {}                           # Dictionary of remote client instances connected to this CES.
        self._serverEndpoints       = []                           # List of server instances listening for CETP flows.
        self._pending_tasks         = {}                           # Contains the list of tasks that shall be terminated upon closing the CETPClient instance {client1:[task1, task2], client2:[task1, task2]}  - Not functional
        self.cesid                  = cesid                        # Local ces-id
        self.ces_params             = ces_params
        self.ces_certificate_path   = self.ces_params['certificate']
        self.ces_privatekey_path    = self.ces_params['private_key']
        self.ca_certificate_path    = self.ces_params['ca_certificate']                           # Path of X.509 certificate of trusted CA, for validating the remote node's certificate.
        
        self.cetp_state_mgr         = cetpTransaction.CETPConnectionObject()                      # Records the established CETP transactions (both h2h & c2c). Required for preventing the re-allocation already in-use SST & DST (in CETP transaction).
        self.policy_mgr             = PolicyManager.PolicyManager(policy_file= host_policies)     # Shall ideally fetch the policies from Policy Management System (of Hassaan)    - And will be called, policy_sys_agent
        self._loop                  = loop
        self.name                   = name
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPManager)
        self.ic2c_mgr               = iCETPManager(loop=loop, policy_mgr=self.policy_mgr, cetp_state_mgr=self.cetp_state_mgr, l_cesid=cesid, ces_params=self.ces_params)
        

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
        client_ep = ocetpLayering.CETPClient(l_cesid = l_cesid, r_cesid = r_cesid, cb_func=dns_cb_func, cetp_state_mgr= self.cetp_state_mgr, \
                               policy_mgr=self.policy_mgr, policy_client=None, loop=self._loop, ocetp_mgr=self, ces_params=self.ces_params)
        
        self.add_local_endpoint(r_cesid, client_ep)
        client_ep.create_cetp_c2c_layer(naptr_list)
        return client_ep


    def has_local_endpoint(self, r_cesid):
        """ If CES already has a client instance towards r_cesid """
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

    """ Server Endpoint shall have a listening service on advertised (IP, port, proto), and corresponding python object to process a connected client """
    
    def register_server_endpoint(self, ep):
        self._serverEndpoints.append(ep)
        
    def get_server_endpoints(self):
        """ Provides list of all CETP server endpoints """
        return self._serverEndpoints
        
    def delete_server_endpoint(self, ep):
        """ 
        Removes a given server endpoint from the list of all CETP server endpoints,     [Done]
        Stops listening on the server endpoint for new connections, AND the connected remote endpoints are closed separately.
        """
        if ep in self._serverEndpoints:
            self._serverEndpoints.remove(ep)
            del ep                                          # Is this a correct way of achieving things?
            #ep.cancel()

    def delete_all_server_endpoints(self):
        """ Stops listening on all server endpoints for new connections """
        for server_ep in self._serverEndpoints:
            self.delete_server_endpoint(ep)

    def create_server_endpoint(self, server_ip, server_port, proto):
        """ Creates CETPServer Endpoint for accepting connections from remote oCES """
        try:
            self._logger.info("Initiating CETPServer on {} protocol @ {}.{}".format(proto, server_ip, server_port))
            if proto == "tcp":
                coro = self._loop.create_server(lambda: icetpLayering.iCESServerTransportTCP(self._loop, c2c_mgr= self.ic2c_mgr ), host=server_ip, port=server_port)             # pre-created objects in protocol factory utilize same object for all accepted connections. So we avoid it.
                
            elif proto == "tls":
                sc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sc.verify_mode = ssl.CERT_REQUIRED
                sc.load_cert_chain(self.ces_certificate_path, self.ces_privatekey_path)
                #sc.check_hostname = True
                sc.load_verify_locations(self.ca_certificate_path)
                coro = self._loop.create_server(lambda: icetpLayering.iCESServerTransportTLS(self._loop, self.ces_certificate_path, self.ca_certificate_path, \
                                                                                             c2c_mgr= self.ic2c_mgr), host=server_ip, port=server_port, ssl=sc)
                
            server = self._loop.run_until_complete(coro)            # Returns the task object
            self.register_server_endpoint(server)                   # Perhaps, store the protocol_factory instead of the task object. Can we close CETPServer etc via task.cancel()?
            self._logger.info(' CETP Server is listening on {} protocol: {}:{}'.format(proto, server_ip, server_port))
                
        except Exception as ex:
            self._logger.warning(" Failed to create CETP server on {} protocol @ {}:{}".format(proto, server_ip, server_port))
            self._logger.warning(ex)



    """ Methods for closing Client and Server Endpoints managed by CES (on Ctrl+C)  - Not Correct (Gotta re-check and improve """
        
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
    Its probably best that c2cLayer for remote end is instantiated by the CETPManager, upon request from CETPClient.
    """


        
class iCETPManager:
    """ 
    Manager class to aggregate different CETP Transport endpoints from a remote CES-ID, such that at end there is only one c2c-layer between two CES nodes.
    """
    def __init__(self, loop=None, policy_mgr=None, cetp_state_mgr=None, l_cesid=None, ces_params=None, name="iCETPManager"):
        self._loop              = loop
        self.policy_mgr         = policy_mgr
        self.cetpstate_mgr      = cetp_state_mgr
        self.l_cesid            = l_cesid
        self.ces_params         = ces_params
        self.c2c_register       = {}                        # Registers a c2clayer corresponding to a remote 'cesid' --- Format: {cesid1: c2c_layer, cesid2: c2c_layer}
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCETPManager)

    def register_c2c_layer(self, r_cesid, ic2c_layer):
        self.c2c_register[r_cesid] = ic2c_layer

    def has_c2c_layer(self, r_cesid):
        return r_cesid in self.c2c_register

    def get_c2c_layer(self, r_cesid):
        return self.c2c_register[r_cesid]

    def delete_c2c_layer(self, r_cesid):
        if self.has_c2c_layer(r_cesid):
            del self.c2c_register[r_cesid]

    def get_all_c2c_layers(self):
        c2c_layers = []
        for cesid, c2clayer in self.c2c_register:
            c2c_layers.append(c2clayer)
        return c2c_layers
    
    def remote_endpoint_malicious_history(self, ip_addr):
        """ Check if the remote node has history of misbehavior """
        return False

    def create_c2c_layer(self, r_cesid):
        """ Creates a new c2cLayer for cesid AND passes the negotiated ces-to-ces transaction """
        ic2c_layer = icetpLayering.iCETPC2CLayer(r_cesid, self)
        self.register_c2c_layer(r_cesid, ic2c_layer)
        return ic2c_layer
    
    def _pre_process(self, msg):
        """ Pre-processes the received packet """
        try:
            self._logger.info(" New CETP Transport is connected -> Initiate/continue C2C-negotiation")
            cetp_msg = json.loads(msg)
            inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
            sstag, dstag    = inbound_dstag, inbound_sstag
        except Exception as ex:
            self._logger.error(" Exception in parsing the received message.")
            return False

        if inbound_sstag == 0:
            self._logger.error(" Inbound SST cannot be zero")            # Sender must choose an SST
            return False
        
        elif inbound_dstag !=0:
            self._logger.debug(" Remote endpoint is scanning the Session-Tag space?")
            self._logger.warning(" Unexpected CETP (SST={}, DST={}) -> As negotiated C2CTransactions are processed in iCETPC2CLayering ".format(inbound_sstag, inbound_dstag))
            return False
        
        return True
        # I guess this Incorporates the work done for preventing the abuse of connection states from remote entity scanning the connection state table.
        
    
    def process_inbound_message(self, msg, transport):
        """  Called on the first few packets from a (newly) connected end-point, until the C2C-policies are negotiated.
        """
        result = self._pre_process(msg)
        if result == False:
            transport.close()
        
        response, ic2c_transaction = self.prcoess_c2c_negotiation(msg, transport)
        (status, cetp_resp) = response
        
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
            stateful_transaction = self.cetpstate_mgr.get((sstag, dstag))
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
        self._logger.info("No prior Outbound C2CTransaction -> Initiating inbound C2CTransaction (SST={} -> DST={})".format(inbound_sstag, inbound_dstag))
        
        peer_addr = transport.peername
        proto     = transport.proto
        ic2c_transaction = cetpTransaction.iC2CTransaction(self._loop, r_addr=peer_addr, sstag=sstag, dstag=sstag, l_cesid=self.l_cesid, policy_mgr=self.policy_mgr, \
                                                           cetpstate_mgr=self.cetpstate_mgr, ces_params=self.ces_params, proto=proto, transport=transport)
        response = ic2c_transaction.process_c2c_transaction(cetp_msg)
        return (response, ic2c_transaction)

