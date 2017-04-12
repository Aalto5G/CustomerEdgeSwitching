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
import C2CTransaction
import H2HTransaction
import icetpLayering
import ocetpLayering


LOGLEVEL_CETPClient             = logging.INFO
LOGLEVEL_oCES2CESLayer          = logging.INFO
LOGLEVEL_oCESTransportMgr       = logging.INFO
LOGLEVEL_oCESTransportTCP       = logging.INFO



class CETPClient:
    def __init__(self, loop=None, l_cesid= None, r_cesid=None, cb_func=None, cetp_state_mgr= None, policy_client=None, policy_mgr=None, ocetp_mgr=None, ces_params=None, name="CETPClient"):
        self._loop              = loop
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.cb_func            = cb_func
        self.cetp_state_mgr     = cetp_state_mgr
        self.policy_client      = policy_client
        self.policy_mgr         = policy_mgr
        self.ces_params         = ces_params
        self.cetp_mgr           = ocetp_mgr
        
        self.client_q           = asyncio.Queue()           # Enqueues the naptr responses triggered by private hosts (served by CES)
        self.c2c_q              = asyncio.Queue()           # Enqueues the response from remote peer (iCES), to H2H transactions
        self.c2c_completed      = False
        self.c2c_succeeded      = False
        self.c2c_completed_timely = True
        self.pending_tasks      = []
        
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPClient)
        self.C2C_Negotiation_Threshold  = 3.0               # in seconds
        self.DNS_Cleanup_Threshold      = 5                 # No. of DNS queries gracefully handled in case of C2C termination 
        self.initiate_coroutines()

    def initiate_coroutines(self):
        t1=asyncio.ensure_future(self.consume_h2h_requests())
        self.store_pending_tasks(t1)
        self._logger.debug("consume_h2h_requests() task is initiated")           # Triggers task for consuming naptr_records (and initiates h2h transactions)
        t2=asyncio.ensure_future(self.consume_message_from_c2c())
        self.store_pending_tasks(t2)
        self._logger.debug("consume_message_from_c2c() task is initiated")
        
    def store_pending_tasks(self, t):
        self.pending_tasks.append(t)

    def create_cetp_c2c_layer(self, naptr_list):
        """ Initiates CETPc2clayer between two CES nodes """
        self.c2c = oCES2CESLayer(self._loop, naptr_list=naptr_list, cetp_client=self, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetp_state_mgr= self.cetp_state_mgr, \
                                 policy_mgr=self.policy_mgr, policy_client=self.policy_client, ces_params=self.ces_params)
        
        #asyncio.ensure_future(self.c2c.consume_transport_message())
        
        # Register by using c2cManager.getC2C(’cesid’)
        # This can be a function getting c2clayer from CETPManager?

    def enqueue_h2h_requests_nowait(self, naptr_records, cb_args):
        """ This method simply puts the message into the queue.     If the queue is full, it will simply drop the message (without waiting for space to be available in the queue) """
        """ How to handle a list of NAPTR records?    - For now I assume its just one NAPTR record always """
        
        self._logger.debug("Enqueuing the naptr response in CETPClient instance")
        queue_msg = (naptr_records, cb_args)
        self.client_q.put_nowait(queue_msg)               # Enqueues the naptr responses triggered by private hosts

    @asyncio.coroutine
    def enqueue_h2h_requests(self, msg):
        """ The method blocks (or doesn't return) until the queue has space to store this message. 
        The method can be triggered via asyncio.ensure_future(enqueue) for each message to pass.
        """
        self._logger.debug("Enqueuing the naptr response in client instance")
        yield from self.client_q.put(msg)           # Enqueues the naptr responses triggered by private hosts

    @asyncio.coroutine
    def consume_h2h_requests(self):
        start_time = time.time()
        while True:
            if self.c2c_completed == False:                     # Prevents processing of h2h, until the c2c-negotiation has completed.
                yield from asyncio.sleep(0.05)                  # 2-to-5 millisecond interval for re-checking if trust established
                if (time.time() - start_time) > self.C2C_Negotiation_Threshold:            # To prevent infinite blocking, incase if remote-ces is unreachable
                    self._logger.error(" C2C negotiation did not complete in To ={}".format(self.C2C_Negotiation_Threshold))
                    if self.client_q.qsize()>1:
                        self._logger.info(" Terminate CETPClient, c2cLayer and CETPTransport created for cesid '{}'".format(self.r_cesid))
                        break
                    else:
                        self._logger.info("Respond the host-DNS-queries with DNS NXDOMAIN")     # If less than 'N' number of requests are queued, respond with DNS NXDOMAIN. Otherwise, simply drop every thing.
                        queued_data = yield from self.client_q.get()
                        (naptr_rr, cb_args) = queued_data
                        asyncio.ensure_future(self.dns_nxdomain_callback(cb_args))
                        self.client_q.task_done()
                else:
                    continue
            else:
                try:
                    queued_data = yield from self.client_q.get()
                    (naptr_rr, cb_args) = queued_data                               # Could it be on a list on naptr records? If yes, how to handle it?
                    
                    for naptr in naptr_rr:
                        dest_id, r_cesid, r_ip, r_port, r_transport = naptr          # Assuming single naptr response... for now, for testing
                    
                except Exception as msg:
                    self._logger.info("Terminating CETPClient queue towards cesid {}".format(self.r_cesid))
                    break
                
                if self.c2c_succeeded == False:
                    self._logger.info("C2C Negotiation failed... Responding the host-DNS-queries with DNS NXDOMAIN")
                    asyncio.ensure_future(self.dns_nxdomain_callback(cb_args))
                    self.client_q.task_done()
                    if self.client_q.qsize()==0:
                        self._logger.debug(" Terminate CETPClient, c2cLayer and CETPTransport for this 'cesid'")
                        break
                    # How to clean remaining resources: CETPClient, C2C, Transport etc? - break and then terminate resources?
                else:
                    asyncio.ensure_future(self.h2h_transaction_start(cb_args, dest_id))
                    self.client_q.task_done()
                    
        self.clear_resources_pending_tasks()
                        
    def clear_resources_pending_tasks(self):
        self._logger.info("Deleting the pending tasks")
        del(self.c2c)
        self.cetp_mgr.remove_local_endpoint(self.r_cesid)
        
        
    @asyncio.coroutine
    def dns_nxdomain_callback(self, cb_args):
        """ Executes callback upon DNS success or failure """
        yield from asyncio.sleep(0.001)
        (query, addr) = cb_args
        self.cb_func(query, addr, success=False)

            
    @asyncio.coroutine
    def h2h_transaction_start(self, cb_args, dst_id):
        dns_q, addr = cb_args
        h2h = H2HTransaction.H2HTransactionOutbound(loop=self._loop, dns_q=dns_q, local_addr=addr, src_id="", dst_id=dst_id, l_cesid=self.l_cesid, r_cesid=self.r_cesid, \
                                                        policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetp_state_mgr, dns_callback=self.cb_func)
        cetp_packet = yield from h2h.start_cetp_processing()
        self._logger.debug(" Sending message from h2h_transaction_start() ")
        self.send(cetp_packet)

    @asyncio.coroutine
    def h2h_transaction_continue(self, cetp_packet, transport):
        o_transaction = None
        yield from asyncio.sleep(0.01)
        try:
            cetp_msg = json.loads(cetp_packet)
            inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
            sstag, dstag    = inbound_dstag, inbound_sstag
        except Exception as msg:
            self._logger.error(" Exception in parsing inbound CETP message.")
            return
            
        if self.cetp_state_mgr.has( (sstag, 0) ):
            self._logger.info(" Continue resolving h2h_transaction (SST={}, DST={})".format(sstag, dstag))
            o_h2h = self.cetp_state_mgr.get( (sstag, 0) )
            msg = o_h2h.continue_cetp_processing(cetp_msg)
            if msg!=None:
                self.send(msg)

        elif self.cetp_state_mgr.has( (sstag, dstag) ):
            self._logger.info(" CETP Signalling for a negotiated transaction (SST={}, DST={})".format(sstag, dstag))
            o_h2h = self.cetp_state_mgr.get( (sstag, dstag) )
            msg = o_h2h.post_c2c_negotiation(cetp_msg, transport)
            if msg!=None:
                self.send(msg)
        
    def c2c_negotiation_status(self, status=True):
        self.c2c_completed  = True
        self.c2c_succeeded  = status
        
    def get_c2c_negotiation_status(self):
        return self.c2c_succeeded
    
    def send(self, msg):
        """ Forwards the message to CETP c2c layer"""
        self.c2c.send_cetp(msg)

    def enqueue_message_from_c2c_nowait(self, msg):
        self.c2c_q.put_nowait(msg)                          # Enqueues the CETP message from iCES, forwarded by CETPTransport layer

    @asyncio.coroutine
    def enqueue_message_from_c2c(self, msg):
        yield from self.c2c_q.put(msg)                      # Enqueues the CETP message from iCES, forwarded by CETPTransport layer

    @asyncio.coroutine
    def consume_message_from_c2c(self):
        """ Consumes the message from c2cLayer to CETPClient (for H2H) """
        while True:
            try:
                de_queue = yield from self.c2c_q.get()                   # Gets the CETP message from remote iCES
                msg, transport = de_queue
                if self.c2c_succeeded == True:
                    asyncio.ensure_future(self.h2h_transaction_continue(msg, transport))
                    self.c2c_q.task_done()
            except Exception as msg:
                self._logger.info("Exception in consuming message from c2c-layer")
    
    def resource_cleanup(self):
        """ Deletes the CETPclient instance towards r_cesid, cancels the pending tasks, and gracefully issues DNS NXDOMAIN (if pending_h2h_queries < N in size) """
        
        # DNS response to pending host-DNS queries is sent, if such queries are below threshold
        if self.client_q.qsize() < self.DNS_Cleanup_Threshold:
            try:
                queued_data = self.client_q.get_nowait()
                (naptr_rr, cb_args) = queued_data
                asyncio.ensure_future(self.dns_nxdomain_callback(cb_args))
            except Exception as msg:
                self._logger.info(" Exception in resource cleanup towards {}".format(self.r_cesid))
        
        for tsk in self.pending_tasks:
            self._logger.debug("Cleaning the pending task")
            tsk.cancel()
        
        self.cetp_mgr.remove_local_endpoint(self.r_cesid)
        del(self)
    
    
    """  
    def __del__(self):
        -- Performs cleanup activity when connection or c2c-negotiation with remote end fails --
        self._logger.info("Deleting the pending tasks")
        #for it in self.task_list:
        #    it.cancel()
            
        self._logger.info("Deleting CETPClient and C2C instance")
        self.cetp_conn_mgr.remove_local_endpoint(self.r_cesid)
        del(self.c2c)
        del(self)
        # How to kill the pending tasks? 
    """


class oCES2CESLayer:
    """
    Instantiates client CETP Transports towards remote CES, based on the NAPTR records.
    Manages, registers/unregisters the CETP Transports, AND performs resource cleanup on CES-to-CES connectivity loss.
    Timely negotiation of the CES-to-CES policies, AND forwards C2C-level CETP message to corresponding C2CTransaction, in post-c2c-negotiation phase.
    After CES-to-CES is negotiated, it forwards H2H-CETP Transactions to/from the upper layer. 
    
    TBD: Management of CETPTransport failover, Transparent to H2H-layer.
    """
    def __init__(self, loop, naptr_list=[], cetp_client=None, l_cesid=None, r_cesid=None, cetp_state_mgr=None, policy_mgr=None, policy_client=None, ces_params=None, name="oCES2CESLayer"):
        self._loop                      = loop
        self.naptr_list                 = naptr_list
        self.cetp_client                = cetp_client            # H2H layer manager for remote-cesid 
        self.l_cesid                    = l_cesid
        self.r_cesid                    = r_cesid
        self.cetp_state_mgr             = cetp_state_mgr
        self.policy_client              = policy_client
        self.policy_mgr                 = policy_mgr
        self.ces_params                 = ces_params
        self.transport_c2c_binding      = {}
        self.c2c_transaction_list       = []
        self.pending_tasks              = []                     # oCESC2CLayer specific
        
        self.q                          = asyncio.Queue()        # Enqueues the CETP message from CETP Transport
        self.c2c_negotiated             = False
        self._logger                    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oCES2CESLayer)
        self._logger.info("Initiating oCES2CESLayer towards cesid '{}'".format(r_cesid) )
        self._initiate()
        self.get_cetp_transport(naptr_list)

    def _initiate(self):
        tsk = asyncio.ensure_future(self.consume_transport_message())
        self.pending_tasks.append(tsk)

    def get_cetp_transport(self, naptr_list):
        self.transport_layer = oCESTransportMgr(naptr_list = naptr_list, c2clayer= self, r_cesid= self.r_cesid, loop=self._loop, ces_params=self.ces_params) 

    def send_cetp(self, msg):
        self.transport_layer.send_cetp(msg)

    def enqueue_transport_message_nowait(self, msg):
        self.q.put_nowait(msg)

    @asyncio.coroutine
    def enqueue_transport_message(self, msg):
        yield from self.q.put(msg)

    def forward_to_h2h_layer(self, msg):
        self.cetp_client.enqueue_message_from_c2c_nowait(msg)

    def _pre_process(self, msg):
        """ Checks whether inbound message conform to CETP packet format. """
        try:
            cetp_msg = json.loads(msg)
            inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
            sstag, dstag    = inbound_dstag, inbound_sstag
        except Exception as msg:
            self._logger.error(" Exception in parsing the received message.")
            return False
        
        if sstag==0 & dstag ==0:
            self._logger.info(" Both SST & DST cannot be zero")
            return False
        return True
    
    @asyncio.coroutine
    def consume_transport_message(self):
        """ Consumes CETP messages queued by the CETP Transport. """
        while True:
            de_queue = yield from self.q.get()
            msg, transport = de_queue
            if not self._pre_process(msg):
                self.q.task_done()
                continue                        # For repeated non-CETP packets, shall we terminate the connection?
            
            cetp_msg = json.loads(msg)
            inbound_sst, inbound_dst = cetp_msg['SST'], cetp_msg['DST']
            sstag, dstag = inbound_dst, inbound_sst

            if self.c2c_negotiated == False:
                self._logger.debug(" C2C-policy is not negotiated with remote-cesid '{}'".format(self.r_cesid))
                asyncio.ensure_future(self.process_c2c(cetp_msg, transport))
                self.q.task_done()
            else:
                if self.is_c2c_transaction(sstag, dstag):
                    self._logger.debug(" Message on a connected or ongoing C2C-transaction.")       # For C2C-level feedback or keepalive etc.
                    asyncio.ensure_future(self.process_c2c(cetp_msg, transport))
                    self.q.task_done()
                else:
                    self._logger.debug(" Forwarding packet to H2H-layer")
                    self.forward_to_h2h_layer(de_queue)
                    self.q.task_done()
            

    def is_c2c_transaction(self, sstag, dstag):
        """ Checks whether CETP message meets an ongoing or completed C2C Transaction initiated by this C2C layer """
        
        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if (c_sst == sstag) & (c_dst == dstag):
                return True

        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if ( (c_sst == sstag) and (c_dst==0) and (dstag!=0) ):
                self._logger.debug(" C2CTransaction is completed by iCES, but is not completed at oCES yet")
                return True
            
        return False
    
    @asyncio.coroutine            
    def process_c2c(self, cetp_msg, transport):
        """ Calls corresponding C2CTransaction method, depending on whether its an ongoing or completed C2C Transaction. """
        inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dstag, inbound_sstag
    
        if self.cetp_state_mgr.has( (sstag, 0) ):
            self._logger.info(" Continue resolving c2c-transaction (SST={}, DST={})".format(sstag, dstag))
            o_c2c = self.cetp_state_mgr.get( (sstag, 0) )
            result = o_c2c.continue_c2c_negotiation(cetp_msg, transport)
            (status, cetp_resp) = result
            
            if status == True:
                self.c2c_negotiated = True
                transport.report_c2c_status(status)
                self.cetp_client.c2c_negotiation_status(status=True)
                self.transport_layer.register_c2c_to_transport(o_c2c, transport)
                
            elif status == False:
                if len(cetp_resp) > 0:  self.send(cetp_resp)
                self.cetp_client.c2c_negotiation_status(status=False)
                self._logger.debug(" Closing the transport endpoint towards {}.".format(self.r_cesid))
                self.transport_layer.unregister_c2c_to_transport(transport)
                transport.close()
                
            elif status == None:
                self._logger.info(" CES-to-CES is not negotiated yet -> Continue CES-to-CES negotiation ")
                transport.send_cetp(cetp_resp)

        elif self.cetp_state_mgr.has( (sstag, dstag) ):
            self._logger.debug(" CETP Signalling for a negotiated transaction (SST={}, DST={})".format(sstag, dstag))
            o_c2c = self.cetp_state_mgr.get( (sstag, dstag) )
            msg = o_c2c.post_c2c_negotiation(cetp_msg, transport)
            if msg!=None:
                transport.send_cetp(msg)


    def report_connectivity(self, transport_obj, status=True):
        if status == True:
            self._logger.info("CETP Transport is connected -> Exchange the CES-to-CES policies.")
            self.initiate_c2c_transaction(transport_obj)
        else:
            self._logger.info("CETP Transport is disconnected.")
            if transport_obj in self.transport_c2c_binding:
                c2c_transaction = self.transport_c2c_binding[transport_obj]
                c2c_transaction.set_terminated()
                self.c2c_transaction_list.remove(c2c_transaction)
                del self.transport_c2c_binding[transport_obj]
            

    def initiate_c2c_transaction(self, transport_obj):
        """ Initiates/Continues CES-to-CES negotiation """
        c2c_transaction  = C2CTransaction.oC2CTransaction(self._loop, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetp_state_mgr=self.cetp_state_mgr, \
                                                           policy_mgr=self.policy_mgr, proto=transport_obj.proto, ces_params=self.ces_params)
        cetp_resp = c2c_transaction.initiate_c2c_negotiation()
        self.transport_c2c_binding[transport_obj] = c2c_transaction
        self.c2c_transaction_list.append(c2c_transaction)
        
        if cetp_resp!=None:
            transport_obj.send_cetp(cetp_resp)


    def resource_cleanup(self):
        """ Shall cancel the pending tasks and delete the object """
        self._logger.info(" Resource cleanup signal received")
        for tsk in self.pending_tasks:
            self._logger.debug("Cleaning the pending task")
            tsk.cancel()
            
        self.cetp_client.resource_cleanup()
        del(self)
        
            

class oCESTransportMgr:
    """
    Initial aim: to lessen burden from C2C layer, and to more efficiently offer services such as:
        # Possibility of managing/hiding the transport-link failures, seemless to the C2C layer?
        # Parallel CETPTransport establishments. (And any value added service therein)
    
    - oCESTransportMgr shall be removed,    if it offers no functionality/support to C2C layer (&) C2C needs direct access to the CETP protocol transports.
        # For packet sending, and resource cleanup etc.
    """
    def __init__(self, naptr_list=[], c2clayer= None, r_cesid= None, loop=None, ces_params=None, name="oCESTransportMgr"):
        self.c2c                    = c2clayer
        self.r_cesid                = r_cesid
        self.initiated_transports   = []
        self.connected_transports   = []
        self.transport_c2c_binding  = {}
        self.ces_params             = ces_params
        self.count                  = 0
        
        
        self._loop                  = loop
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oCESTransportMgr)
        self._logger.info("Initiating oCESTransportMgr towards cesid '{}'".format(r_cesid) )
        self.initiate_cetp_transport(naptr_list)
   
    
    def remote_endpoint_malicious_history(self, r_cesid, ip_addr):
        """ Dummy function, emulating the check that if 'cesid'  or the 'ip-address' has previous history of misbehavior """
        return False
    
    def register_c2c_to_transport(self, c2c_transaction, transport):
        self.transport_c2c_binding[transport] = c2c_transaction
    
    def unregister_c2c_to_transport(self, transport):
        del self.transport_c2c_binding[transport]
    
    def get_c2c_for_transport(self, transport):
        return self.transport_c2c_binding[transport]

    def select_transport(self):
        """ Select the outgoing CETP-transport based on: 1) load_balancing and 2): a) active health indicator; 2) Lowest-RTT (best health); 3) OR based on priority field in the inbound NAPTR """ 
        total_transports = len(self.connected_transports)
        index = random.randint(0, total_transports-1)
        transport = self.connected_transports[index]
        if total_transports==1:
            return transport
        
        oc2c = self.get_c2c_for_transport(transport)
        if oc2c.health_report:
            (ip, port) = transport.peername
            if port==50001:
                self.count +=1
                print("self.count: ", self.count)

            return transport
        
        print()
        print('#'*30)
        print("Unresponsive transport {}".format(transport.peername))


        for transport in self.connected_transports:
            oc2c = self.get_c2c_for_transport(transport)
            if oc2c.health_report:                          # Select the next transport with good health
                print("New transport {}".format(transport.peername))
                return transport

        # If all transports have bad health, Then return any connected transport.        
        transport = self.connected_transports[index]
        return transport
    

    def send_cetp(self, msg):
        current_transport = self.select_transport()
        current_transport.send_cetp(msg)

    
    def register_connected_transports(self, transport):
        """ Registers the connected CETP Transport """
        self.connected_transports.append(transport)
        if transport in self.initiated_transports:
            self._logger.debug("Removes the transport from list of initiated transport connections, when connectivity succeeds")            
            self.initiated_transports.remove(transport)
            
    def unregister_transport(self, transport):
        """ Unregisters the CETP Transport -- And launches resource cleanup if all CETPtransport are down """
        if transport in self.connected_transports:
            self.connected_transports.remove(transport)
            
        if transport in self.initiated_transports:
            self._logger.debug(" Removes the transport from list of initiated transport connections, when connectivity fails")
            self.initiated_transports.remove(transport)
            
        if (len(self.initiated_transports) ==0) & (len(self.connected_transports) ==0):
            self._logger.info(" No ongoing or in-progress CETP transport towards {}".format(self.r_cesid))
            self._logger.info(" Close CETP-C2C and CETPClient layer")
            self.c2c.resource_cleanup()
    
    def initiate_cetp_transport(self, naptr_list):
        """ Intiates CETP Transports towards remote endpoints (for each 'naptr' record in the naptr_list) """
        for naptr_rec in naptr_list:
            dst_id, r_cesid, ip_addr, port, proto = naptr_rec
            if self.remote_endpoint_malicious_history(r_cesid, ip_addr):
                self._logger.info("CESID '{}' has history of misbehavior ".format(r_cesid))
                break
            else:
                asyncio.ensure_future(self.initiate_transport(proto, ip_addr, port))
    
    @asyncio.coroutine
    def initiate_transport(self, proto, ip_addr, port):
        """ Description """
        if proto == 'tcp' or proto=="tls":
            self._logger.debug(" Initiating CETPTransport towards cesid '{}' @({}, {})".format(self.r_cesid, ip_addr, port))
            transport_instance = oCESTransportTCP(self, proto, self.r_cesid, loop=self._loop)
            
            if proto == "tls":
                self.ces_certificate_path   = self.ces_params['certificate']
                self.ces_privatekey_path    = self.ces_params['private_key']
                self.ca_certificate_path    = self.ces_params['ca_certificate']

                sc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sc.verify_mode = ssl.CERT_REQUIRED
                sc.load_cert_chain(self.ces_certificate_path, self.ces_privatekey_path)
                sc.load_verify_locations(self.ca_certificate_path)
                #sc.check_hostname = True
            
                try:
                    coro = self._loop.create_connection(lambda: transport_instance, ip_addr, port, ssl=sc)
                    yield from asyncio.ensure_future(coro)
                    self.initiated_transports.append(transport_instance)
                except Exception as ex:
                    self._logger.info("Exception in {} connection towards {}".format(proto, self.r_cesid))                  # ex.errno == 111 -- means connection RST received
                    self.unregister_transport(transport_instance)
                    #print(ex)

            elif proto == "tcp":
                try:
                    coro = self._loop.create_connection(lambda: transport_instance, ip_addr, port)
                    connect_task = asyncio.ensure_future(coro)
                    yield from connect_task
                    self.initiated_transports.append(transport_instance)
                except Exception as ex:
                    self._logger.info("Exception in {} connection towards {}".format(proto, self.r_cesid))
                    self.unregister_transport(transport_instance)
                    #print(ex)


    def report_connectivity(self, transport_obj, status=True):
        """ Gets connectivity report from CETPTransport and forwards it to CETP-C2C layer """
        if status==True:
            self.register_connected_transports(transport_obj)
        else:
            self.unregister_transport(transport_obj)
        self.c2c.report_connectivity(transport_obj, status)

    def data_from_transport(self, msg, transport):
        """ Method to forward data from CETPTransport to CETPC2C layer """
        self.c2c.enqueue_transport_message_nowait((msg, transport))

    def close(self):
        self._logger.info("Close all the connected CETP transports")

    """
    Asyncio-related learning:
    # You can't simply initiate a task and expect that exception will be handled automatically. Instead you need to wait on the task.
    
    async def main(loop):
        coro = loop.create_connection(lambda: EchoClientProtocol(message, loop),'127.0.0.1', 49001)
        try:
            t = asyncio.ensure_future(coro)
            await t
        except Exception as ex:
            #print(ex.errno == 111)
            print(ex)
    
    asyncio.ensure_future(main(loop))
    """

CETP_MSG_LEN = 2    

class oCESTransportTCP(asyncio.Protocol):
    def __init__(self, transport_mgr, proto, r_cesid, loop=None, name="oCESTransport"):
        self.t_mgr                  = transport_mgr
        self.r_cesid                = r_cesid 
        self._loop                  = loop
        self.transport              = None
        self.proto                  = proto
        self.name                   = name+proto
        self._logger                = logging.getLogger(name)
        self._start_time            = self._loop.time()
        self.is_connected           = False
        self.c2c_negotiation        = False
        self.data_buffer            = b''
        self.c2c_negotiation_threshold = 2                        # In seconds
        self._logger.setLevel(LOGLEVEL_oCESTransportTCP)
        self._loop.call_later(self.c2c_negotiation_threshold, self.is_c2c_negotiated)
        

    def connection_made(self, transport):
        current_time = self._loop.time()
        time_lapsed  = current_time - self._start_time
        
        if (time_lapsed) > self.c2c_negotiation_threshold:
            self._logger.info(" Closing, as transport connection took > (To={})".format(str(self.c2c_negotiation_threshold)))
            self.close()
        else:
            self.transport = transport
            self.peername = transport.get_extra_info('peername')
            self._logger.info('Connected to {}'.format(self.peername))
            self.is_connected = True
            self.t_mgr.report_connectivity(self)                 # Reporting the connectivity to upper layer.

    def report_c2c_status(self, status):
        """ Used by CETP-C2C layer to notify if the c2c-negotiation succeeded """
        self.c2c_negotiation = status

    def is_c2c_negotiated(self):
        """ Prevents the TCPClient from waiting (for t>To) for connection completion, and for failure/success of C2C negotiation """
        if (self.transport != None) and (self.c2c_negotiation == False):
            self._logger.info(" Closing connection, as C2C negotiation did not complete in To={}".format(str(self.c2c_negotiation_threshold)))
            self.close()

    def send_cetp(self, msg):
        to_send = self.message_framing(msg)
        self.transport.write(to_send)

    def message_framing(self, msg):
        self._logger.debug("Message to send: {!r}".format(msg))
        cetp_msg = msg.encode()
        msg_length = len(cetp_msg)                                                   # Instead of binary encoding - what could be the fastest encoding of length field.
        len_bytes = (msg_length).to_bytes(CETP_MSG_LEN, byteorder="big")             # Time-it the pyhton's binary encoding.
        #self._logger.debug("msg_length: {}".format(msg_length))
        to_send = len_bytes + cetp_msg
        return to_send

    def data_received(self, data):
        """Asyncio coroutine to receive data"""
        self.buffer_and_parse_stream(data)
    
    def buffer_and_parse_stream(self, data):
        """ 
        1. Appends new data from the wire to a buffer;  2. Parses the stream into CETP messages; 
        3. invokes CETP process to handle message;      4. Removes processed data from the buffer.
        """
        self.data_buffer = self.data_buffer+data
        while True:
            if len(self.data_buffer) < CETP_MSG_LEN:
                break
            
            len_field = self.data_buffer[0:CETP_MSG_LEN]                                            # Possible to read length field in the buffered data
            msg_length = int.from_bytes(len_field, byteorder='big')
                        
            if len(self.data_buffer) >= (CETP_MSG_LEN + msg_length):
                self._logger.debug(" Reading CETP message from streamed data.")
                cetp_data = self.data_buffer[CETP_MSG_LEN:CETP_MSG_LEN+msg_length]
                cetp_msg = cetp_data.decode()
                #self._logger.debug('Data received: {!r}'.format(cetp_msg))
                self.data_buffer = self.data_buffer[CETP_MSG_LEN+msg_length:]           # Moving ahead in the buffered data
                self.t_mgr.data_from_transport(cetp_msg, self)
            else:
                break
    
    def connection_lost(self, exc):
        if self.is_connected == True:                                # To prevent reporting the connection closure twice, at sending & receiving of FIN/ACK
            self._logger.info('The CETPServer transport closed the connection')
            self.t_mgr.report_connectivity(self, status=False)
            self.is_connected=False
        # process exc

    def close(self):
        """ Closes the connection with the remote CES """
        self._logger.info('Closing the client CETP Transport towards {}'.format(self.r_cesid))
        self.transport.close()
        if self.is_connected == True:
            self.t_mgr.report_connectivity(self, status=False)
            self.is_connected=False

