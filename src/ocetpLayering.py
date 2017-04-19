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

CETP_MSG_LEN_FIELD              = 2         # in bytes


class CETPClient:
    def __init__(self, loop=None, l_cesid= None, r_cesid=None, cb_func=None, cetp_state_mgr= None, policy_client=None, policy_mgr=None, ocetp_mgr=None, ces_params=None, name="CETPClient"):
        self._loop                      = loop
        self.l_cesid                    = l_cesid
        self.r_cesid                    = r_cesid
        self.cb_func                    = cb_func
        self.cetp_state_mgr             = cetp_state_mgr
        self.policy_client              = policy_client
        self.policy_mgr                 = policy_mgr
        self.ces_params                 = ces_params
        self.cetp_mgr                   = ocetp_mgr
        self._closure_signal            = False
        
        self.client_q                   = asyncio.Queue()           # Enqueues the naptr responses triggered by private hosts (served by CES)
        self.c2c_q                      = asyncio.Queue()           # Enqueues the response from remote peer (iCES), to H2H transactions
        self.DNS_Cleanup_Threshold      = 5                         # No. of DNS queries gracefully handled in case of C2C termination 
        self.c2c_succeeded              = False
        self.pending_tasks              = []
        self._logger                    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPClient)

    def create_cetp_c2c_layer(self, naptr_list):
        """ Initiates CETPc2clayer between two CES nodes """
        self.c2c = oCES2CESLayer(self._loop, naptr_list=naptr_list, cetp_client=self, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetp_state_mgr= self.cetp_state_mgr, \
                                 policy_mgr=self.policy_mgr, policy_client=self.policy_client, ces_params=self.ces_params)      # Can c2clayer be obtained from CETPManager as an object for 'r_cesid'? 

    def enqueue_h2h_requests_nowait(self, naptr_records, cb_args):
        """ This method enqueues the naptr responses triggered by private hosts. """
        self._logger.debug("Enqueuing the naptr response in CETPClient")
        queue_msg = (naptr_records, cb_args)
        self.client_q.put_nowait(queue_msg)               # Possible exception: If the queue is full, [It will simply drop the message (without waiting for space to be available in the queue]

    @asyncio.coroutine
    def enqueue_h2h_requests(self, msg):
        yield from self.client_q.put(msg)                 # If the queue is full, the call doesn't return until the queue has space to store this message  -can be triggered via asyncio.ensure_future(enqueue) 

    @asyncio.coroutine
    def consume_h2h_requests(self):
        """ To consume NAPTR-response triggered by the private hosts """
        while True:
            try:
                queued_data = yield from self.client_q.get()
                (naptr_rr, cb_args) = queued_data                                       # Whether the list of naptr records is handled well?    
                                                                                        # Can they be used to reconnect to a terminated endpoint.
                for naptr in naptr_rr:
                    dest_id, r_cesid, r_ip, r_port, r_transport = naptr
                
                asyncio.ensure_future(self.h2h_transaction_start(cb_args, dest_id))     # Shall the created task have an exception handler too?
                self.client_q.task_done()

            except Exception as msg:
                self._logger.info(" Exception in CETPClient queue towards {}".format(self.r_cesid))
                if self._closure_signal: break
                self.client_q.task_done()
            
    def c2c_negotiation_status(self, status=True):
        """ Reports that c2c-negotiation completed and whether it Succeeded/Failed """
        if (self.c2c_succeeded == False) and (status == True):
            self.c2c_succeeded  = status
            t1=asyncio.ensure_future(self.consume_h2h_requests())                       # Task for consuming naptr-response records triggered by private hosts
            self.pending_tasks.append(t1)
            t2=asyncio.ensure_future(self.consume_message_from_c2c())                   # Task for consuming message from c2c-layer 
            self.pending_tasks.append(t2)
    
    def close_pending_tasks(self):
        for tsk in self.pending_tasks:
            if not tsk.cancelled():
                self._logger.debug("Cleaning the pending tasks")
                tsk.cancel()
        
    def dns_nxdomain_callback(self, cb_args):
        """ Executes callback upon H2H-Policy negotiation success or failure """
        (query, addr) = cb_args
        self.cb_func(query, addr, success=False)

    @asyncio.coroutine
    def h2h_transaction_start(self, cb_args, dst_id):
        dns_q, addr = cb_args
        h2h = H2HTransaction.H2HTransactionOutbound(loop=self._loop, dns_q=dns_q, local_addr=addr, src_id="", dst_id=dst_id, l_cesid=self.l_cesid, r_cesid=self.r_cesid, \
                                                        policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetp_state_mgr, dns_callback=self.cb_func)
        cetp_packet = yield from h2h.start_cetp_processing()
        self._logger.debug(" Message from h2h_transaction_start() ")
        self.send(cetp_packet)

    @asyncio.coroutine
    def h2h_transaction_continue(self, cetp_packet, transport):
        o_transaction = None
        yield from asyncio.sleep(0.01)
        
        cetp_msg = json.loads(cetp_packet)
        inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dstag, inbound_sstag
        
        if self.cetp_state_mgr.has( (sstag, 0) ):
            self._logger.info(" Continue resolving H2H-transaction (SST={} -> DST={})".format(sstag, dstag))
            o_h2h = self.cetp_state_mgr.get( (sstag, 0) )
            msg = o_h2h.continue_cetp_processing(cetp_msg)
            if msg!=None:
                self.send(msg)

        elif self.cetp_state_mgr.has( (sstag, dstag) ):
            self._logger.info(" CETP message for a negotiated transaction (SST={} -> DST={})".format(sstag, dstag))
            o_h2h = self.cetp_state_mgr.get( (sstag, dstag) )
            msg = o_h2h.post_c2c_negotiation(cetp_msg, transport)
            if msg!=None:
                self.send(msg)
        
    def send(self, msg):
        """ Forwards the message to CETP c2c layer"""
        self.c2c.send_cetp(msg)

    def enqueue_message_from_c2c_nowait(self, msg):
        self.c2c_q.put_nowait(msg)                          # Enqueues the CETP message from iCES, forwarded by CETPTransport layer

    @asyncio.coroutine
    def enqueue_message_from_c2c(self, msg):
        yield from self.c2c_q.put(msg)                      # More safe way.

    @asyncio.coroutine
    def consume_message_from_c2c(self):
        """ Consumes the message from C2CLayer for H2H processing """
        while True:
            try:
                de_queue = yield from self.c2c_q.get()                                      # De-queues the enqueued message.
                msg, transport = de_queue
                asyncio.ensure_future(self.h2h_transaction_continue(msg, transport))        # Handling exception raised within task? Shall use the returned task object?
                self.c2c_q.task_done()
            except Exception as msg:
                self._logger.info(" Exception in consuming message from c2c-layer")
                if self._closure_signal: break
                self.c2c_q.task_done()
                # What could be this exception? What does it mean? And how to prevent it from happening? Look in above algo.

    def set_closure_signal(self):
        self._closure_signal = True
    
    def resource_cleanup(self):
        """ Deletes the CETPClient instance towards r_cesid, cancels the pending tasks, and handles the pending <H2H DNS-NAPTR responses. """
        pending_dns_queries = self.client_q.qsize()
        if (pending_dns_queries>0) and (pending_dns_queries < self.DNS_Cleanup_Threshold):          # Issues DNS NXDOMAIN (if pending H2H-DNS queries < N in size)
            try:
                queued_data = self.client_q.get_nowait()
                (naptr_rr, cb_args) = queued_data
                self.dns_nxdomain_callback(cb_args)
            except Exception as msg:
                self._logger.info(" Exception in resource cleanup towards {}".format(self.r_cesid))
                print(msg)
        
        self.set_closure_signal()
        self.close_pending_tasks()
        self.cetp_mgr.remove_local_endpoint(self.r_cesid)               # This ordering is important 
        del(self)


    def interrupt_handler(self):
        """ Deletes the CETPClient instance towards r_cesid, cancels the pending tasks, and handles the pending <H2H DNS-NAPTR responses. """
        self.set_closure_signal()
        self.c2c.interrupt_handler()
        self.close_pending_tasks()
        


class oCES2CESLayer:
    """
    Instantiates client CETP Transports towards remote CES, based on the NAPTR records.
    Manages, registers/unregisters the CETP Transports, AND performs resource cleanup on CES-to-CES connectivity loss.
    Timely negotiation of the CES-to-CES policies, AND forwards C2C-level CETP message to corresponding C2CTransaction, in post-c2c-negotiation phase.
    After CES-to-CES is negotiated, it forwards H2H-CETP Transactions to/from the upper layer. 
    Management of CETPTransport failover, Transparent to H2H-layer.
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
        self.pending_tasks              = []                     # oCESC2CLayer specific
        self.initiated_transports       = []
        self.connected_transports       = []
        self.transport_c2c_binding      = {}
        self.c2c_transaction_list       = []
        
        self.q                          = asyncio.Queue()        # Enqueues the CETP message from CETP Transport
        self.c2c_negotiated             = False
        self._closure_signal            = False
        self._logger                    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oCES2CESLayer)
        self._logger.info("Initiating outbound CES2CESLayer towards cesid '{}'".format(r_cesid) )
        self._initiate()
        self.initiate_cetp_transport(naptr_list)

    def _initiate(self):
        tsk = asyncio.ensure_future(self.consume_transport_message())
        self.pending_tasks.append(tsk)

    def enqueue_transport_message_nowait(self, msg):
        self.q.put_nowait(msg)

    @asyncio.coroutine
    def enqueue_transport_message(self, msg):
        yield from self.q.put(msg)

    def forward_to_h2h_layer(self, msg):
        self.cetp_client.enqueue_message_from_c2c_nowait(msg)

    def _pre_process(self, msg):
        """ Checks whether inbound message conforms to CETP packet format. """
        try:
            cetp_msg = json.loads(msg)
            inbound_sstag, inbound_dstag, ver = cetp_msg['SST'], cetp_msg['DST'], cetp_msg['VER']
            sstag, dstag    = inbound_dstag, inbound_sstag
            
            if ( (sstag==0) and (dstag ==0)) or (sstag < 0) or (dstag < 0):
                self._logger.info(" Session tag values are not acceptable")
                return False
            
            if ver!=1:
                self._logger.info(" The CETP version is not supported.")
                return False

        except Exception as msg:
            self._logger.error(" Exception in pre-processing the received message.")
            return False
        
        return True
    
    @asyncio.coroutine
    def consume_transport_message(self):
        """ Consumes CETP messages queued by the CETP Transport. """
        while True:
            try:
                de_queue = yield from self.q.get()
                msg, transport = de_queue
                if not self._pre_process(msg):
                    self.q.task_done()
                    continue                        # For repeated non-CETP packets, shall we terminate the connection?
                
                cetp_msg = json.loads(msg)
                inbound_sst, inbound_dst = cetp_msg['SST'], cetp_msg['DST']
                sstag, dstag = inbound_dst, inbound_sst
    
                if not self.c2c_negotiated:
                    self._logger.debug(" C2C-policy is not negotiated with remote-cesid '{}'".format(self.r_cesid))
                    asyncio.ensure_future(self.process_c2c(cetp_msg, transport))
                    self.q.task_done()
                else:
                    if self.is_c2c_transaction(sstag, dstag):
                        asyncio.ensure_future(self.process_c2c(cetp_msg, transport))
                        self.q.task_done()
                    else:
                        self._logger.debug(" Forwarding packet to H2H-layer")
                        self.forward_to_h2h_layer(de_queue)
                        self.q.task_done()
            except Exception as msg:
                self._logger.info("Exception in task for consuming messages from CETP Transport ")
                if self._closure_signal: 
                    break
            

    def is_c2c_transaction(self, sstag, dstag):
        """ Checks whether CETP message meets an ongoing or completed C2C Transaction initiated by this C2C layer """
        
        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if (c_sst == sstag) & (c_dst == dstag):
                self._logger.debug(" CETP message for a connected transaction ")        # For CES-to-CES feedback & keepalives etc.
                return True

        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if ( (c_sst == sstag) and (c_dst==0) and (dstag!=0) ):
                self._logger.debug(" CETP message for an ongoing C2CTransaction ")      # completed at iCES, but in-complete at oCES yet
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
                transport.report_c2c_negotiation(status)
                self.cetp_client.c2c_negotiation_status(status=True)
                
            elif status == False:
                if len(cetp_resp) > 0:  self.send(cetp_resp)
                self._logger.debug(" Close the transport endpoint towards {}.".format(self.r_cesid))
                self.unregister_c2c_to_transport(transport)
                transport.close()
                
            elif status == None:
                self._logger.info(" CES-to-CES is not negotiated yet.")
                transport.send_cetp(cetp_resp)

        elif self.cetp_state_mgr.has( (sstag, dstag) ):
            self._logger.debug(" CETP for a negotiated transaction (SST={}, DST={})".format(sstag, dstag))
            o_c2c = self.cetp_state_mgr.get( (sstag, dstag) )
            resp = o_c2c.post_c2c_negotiation(cetp_msg, transport)
            if resp!=None:
                transport.send_cetp(resp)


    def initiate_c2c_transaction(self, transport_obj):
        """ Initiates/Continues CES-to-CES negotiation """
        c2c_transaction  = C2CTransaction.oC2CTransaction(self._loop, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetp_state_mgr=self.cetp_state_mgr, \
                                                           policy_mgr=self.policy_mgr, proto=transport_obj.proto, ces_params=self.ces_params)
        
        self.register_c2c_to_transport(c2c_transaction, transport_obj)
        self.c2c_transaction_list.append(c2c_transaction)
        cetp_resp = c2c_transaction.initiate_c2c_negotiation()
        
        if cetp_resp!=None:
            transport_obj.send_cetp(cetp_resp)


    """ Functions for managing transport-layer connectivity b/w CES nodes """ 
    def report_connectivity(self, transport_obj, status=True):
        if status == True:
            self._logger.info(" CETP Transport is connected -> Exchange the CES-to-CES policies.")
            self.register_connected_transports(transport_obj)
            self.initiate_c2c_transaction(transport_obj)
        else:
            self._logger.info(" CETP Transport is disconnected.")
            self.unregister_transport(transport_obj)

            if transport_obj in self.transport_c2c_binding:
                c2c_transaction = self.get_c2c_transaction(transport_obj)
                self.c2c_transaction_list.remove(c2c_transaction)
                c2c_transaction.set_terminated()
                del self.transport_c2c_binding[transport_obj]

            
    def register_connected_transports(self, transport):
        """ Registers the connected CETP Transport """
        self.connected_transports.append(transport)
        if transport in self.initiated_transports:
            self._logger.debug("Remove the connected transport from list of initiated transports.")            
            self.initiated_transports.remove(transport)
            
    def unregister_transport(self, transport):
        """ Unregisters the CETP Transport AND launches resource cleanup if all CETPtransport are down """
        if transport in self.connected_transports:
            self.connected_transports.remove(transport)
        
        if transport in self.initiated_transports:
            self._logger.debug(" Removes the transport from list of initiated transport connections, when connectivity fails")
            self.initiated_transports.remove(transport)
        
        if (len(self.initiated_transports) ==0) & (len(self.connected_transports) ==0):
            self._logger.info(" No ongoing or in-progress CETP transport towards {}".format(self.r_cesid))
            self._logger.info(" Close CETP-C2C and CETPClient layer")
            self.resource_cleanup()
    
    def cancel_pending_tasks(self):
        for tsk in self.pending_tasks:
            if not tsk.cancelled():
                self._logger.debug("Canceling the pending task")
                tsk.cancel()
        
    def interrupt_handler(self):
        self.set_closure_signal()
        self.cancel_pending_tasks()
    
    def resource_cleanup(self):
        """ Cancels the pending tasks and delete the object """
        self.interrupt_handler()
        self.cetp_client.resource_cleanup()
        del(self)
        
    def set_closure_signal(self):
        self._closure_signal = True
           
    def register_c2c_to_transport(self, c2c_transaction, transport):
        self.transport_c2c_binding[transport] = c2c_transaction
    
    def unregister_c2c_to_transport(self, transport):
        del self.transport_c2c_binding[transport]
    
    def get_c2c_transaction(self, transport):
        return self.transport_c2c_binding[transport]

    def remote_endpoint_malicious_history(self, r_cesid, ip_addr):
        """ Dummy function, emulating the check that if 'cesid'  or the 'ip-address' has previous history of misbehavior """
        return False

    def send_cetp(self, msg):
        transport = self.select_transport()
        transport.send_cetp(msg)

    def select_transport(self):
        """ Selects the outgoing CETP-transport based on: 1) load_balancing (due to random selection of transports) AND:
             a) good health indicator;                             (measured by timely response to C2C-keepalives)
             b) Lowest-RTT (best health);                          (based on smallest-rtt, observed by sending/receiving the C2C-keepalive) 
             c) OR based on priority field in the inbound NAPTR    (Not implemented: ___ )
        """ 
        total_transports = len(self.connected_transports)
        index = random.randint(0, total_transports-1)
        transport = self.connected_transports[index]
        if total_transports==1:
            return transport
        else:
            oc2c = self.get_c2c_transaction(transport)
            if oc2c.health_report:
                return transport
        
        for transport in self.connected_transports:
            oc2c = self.get_c2c_transaction(transport)
            if oc2c.health_report:
                self._logger.debug(" Selecting a 'healthy' transport, connected to {}".format(transport.peername))
                return transport

        # If all transports have bad health, Then return any connected transport.        
        transport = self.connected_transports[index]
        return transport
    

    def data_from_transport(self, msg, transport):
        """ Forward data from CETPTransport to CETPC2C layer """
        self.enqueue_transport_message_nowait((msg, transport))

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
            transport_instance = oCESTransportTCP(self, proto, self.r_cesid, self.ces_params, loop=self._loop)
            
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

class oCESTransportTCP(asyncio.Protocol):
    def __init__(self, c2c_layer, proto, r_cesid, ces_params, loop=None, name="oCESTransport"):
        self.ces_layer                  = c2c_layer
        self.proto                      = proto
        self.r_cesid                    = r_cesid
        self.ces_params                 = ces_params
        self._loop                      = loop
        self.name                       = name+proto
        self._logger                    = logging.getLogger(name)
        self._start_time                = self._loop.time()
        self.transport                  = None
        self.is_connected               = False
        self.c2c_negotiation            = False
        self.data_buffer                = b''
        self.c2c_negotiation_threshold  = ces_params['max_c2c_negotiation_duration']           # In seconds
        self._logger.setLevel(LOGLEVEL_oCESTransportTCP)
        self._loop.call_later(self.c2c_negotiation_threshold, self.is_c2c_negotiated)
        

    def connection_made(self, transport):
        current_time = self._loop.time()
        time_lapsed  = current_time - self._start_time
        
        if (time_lapsed) > self.c2c_negotiation_threshold:
            self._logger.info(" CETPTransport connection established in > (To={})".format(str(self.c2c_negotiation_threshold)))
            self.close()
        else:
            self.transport = transport
            self.peername = transport.get_extra_info('peername')
            self._logger.info('Connected to {}'.format(self.peername))
            self.is_connected = True
            self.ces_layer.report_connectivity(self)                 # Reporting the connectivity to upper layer.

    def report_c2c_negotiation(self, status):
        """ Used by the C2C layer to notify if the c2c-negotiation succeeded """
        self.c2c_negotiation = status

    def is_c2c_negotiated(self):
        """ Closes CETPTransport, if C2C-negotiation is not completed in 'To' """
        if (self.transport != None) and (self.c2c_negotiation == False):
            self._logger.info(" C2C negotiation did not complete in To={} seconds".format(str(self.c2c_negotiation_threshold)))
            self.close()

    def send_cetp(self, msg):
        #self._logger.debug("Message to send: {!r}".format(msg))
        to_send = self.message_framing(msg)
        self.transport.write(to_send)

    def message_framing(self, msg):
        """ Appends length field to the message """
        cetp_msg = msg.encode()
        msg_length = len(cetp_msg)
        len_bytes = (msg_length).to_bytes(CETP_MSG_LEN_FIELD, byteorder="big")
        to_send = len_bytes + cetp_msg
        return to_send

    def data_received(self, data):
        """Asyncio coroutine for received data"""
        self.buffer_and_parse_stream(data)
    
    def buffer_and_parse_stream(self, data):
        """ 
        1. Appends received data to a buffer;          2. Parses the stream into CETP messages, based on length field;
        3. invokes CETP process to handle message;     4. Removes processed data from the buffer.
        """
        self.data_buffer = self.data_buffer+data
        while True:
            if len(self.data_buffer) < CETP_MSG_LEN_FIELD:
                break
            
            len_field = self.data_buffer[0:CETP_MSG_LEN_FIELD]                                      # Reading length field in buffered data
            msg_length = int.from_bytes(len_field, byteorder='big')
                        
            if len(self.data_buffer) >= (CETP_MSG_LEN_FIELD + msg_length):
                cetp_data = self.data_buffer[CETP_MSG_LEN_FIELD:CETP_MSG_LEN_FIELD+msg_length]
                self.data_buffer = self.data_buffer[CETP_MSG_LEN_FIELD+msg_length:]                 # Moving ahead in the buffered data
                cetp_msg = cetp_data.decode()
                self.ces_layer.data_from_transport(cetp_msg, self)
            else:
                break
    
    def connection_lost(self, exc):
        if self.is_connected:                                # Prevents reporting the connection closure twice, at sending & receiving of FIN/ACK
            self._logger.info(' CETPServer transport closed the connection')
            self.ces_layer.report_connectivity(self, status=False)
            self.is_connected=False
        # process exc

    def close(self):
        """ Closes the connection towards remote CES """
        self._logger.info(' Closing the client CETP Transport towards {}'.format(self.r_cesid))
        self.transport.close()
        if self.is_connected:
            self.ces_layer.report_connectivity(self, status=False)
            self.is_connected=False

