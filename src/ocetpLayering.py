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
        
        self.client_q           = asyncio.Queue()           # Enqueues the naptr responses triggered by private hosts (served by CES)
        self.c2c_q              = asyncio.Queue()           # Enqueues the response from remote peer (iCES), to H2H transactions
        self.c2c_completed      = False
        self.c2c_succeeded      = False
        self.c2c_completed_timely = True
        self.task_list          = []
        
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPClient)
        self.C2C_Negotiation_Threshold = 3.0
        self.initiate_coroutines()

    def initiate_coroutines(self):
        t1=asyncio.ensure_future(self.consume_h2h_requests())
        self.store_pending_tasks(t1)
        self._logger.info("consume_h2h_requests() task is initiated")           # Triggers task for consuming naptr_records (and initiates h2h transactions)
        t2=asyncio.ensure_future(self.consume_message_from_c2c())
        self.store_pending_tasks(t2)
        self._logger.info("consume_message_from_c2c() task is initiated")
        
    def store_pending_tasks(self, t):
        self.task_list.append(t)

    def get_cetp_c2c(self, naptr_list):
        """ Initiates CETPc2clayer between two CES nodes """
        self.c2c = oCES2CESLayer(self._loop, naptr_list=naptr_list, cetp_client=self, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetp_state_mgr= self.cetp_state_mgr, \
                                 policy_mgr=self.policy_mgr, policy_client=self.policy_client, ces_params=self.ces_params)
        
        asyncio.ensure_future(self.c2c.consume_transport_message())
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
                        self.dns_nxdomain_callback(cb_args)
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
        self.cetp_conn_mgr.remove_local_endpoint(self.r_cesid)
        
        
    def __del__(self):
        """ Performs cleanup activity when connection or c2c-negotiation with remote end fails """
        self._logger.info("Deleting the pending tasks")
        #for it in self.task_list:
        #    it.cancel()
            
        self._logger.info("Deleting CETPClient and C2C instance")
        self.cetp_conn_mgr.remove_local_endpoint(self.r_cesid)
        del(self.c2c)
        del(self)
        # How to kill the pending tasks? 

    @asyncio.coroutine
    def dns_nxdomain_callback(self, cb_args):
        """ Executes callback upon DNS success or failure """
        yield from asyncio.sleep(0.001)
        (query, addr) = cb_args
        self.cb_func(query, addr, success=False)

            
    @asyncio.coroutine
    def h2h_transaction_start(self, cb_args, dst_id):
        dns_q, addr = cb_args
        h2h = cetpTransaction.H2HTransactionOutbound(dns_q=dns_q, local_addr=addr, src_id="", dst_id=dst_id, l_cesid=self.l_cesid, r_cesid=self.r_cesid, \
                                                        policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetp_state_mgr, dns_callback=self.cb_func)
        cetp_packet = yield from h2h.start_cetp_processing()
        self._logger.info(" Sending message from h2h_transaction_start() ")
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




class oCES2CESLayer:
    """
    Expected outcome from class is the timely negotiation of the CES-to-CES policies.
    If c2c doesn't successfully complete in time 'To', this shall be detected and negotiation shall fail in time 'To'.        (Not implemented yet)
    """
    def __init__(self, loop, naptr_list=[], cetp_client=None, l_cesid=None, r_cesid=None, cetp_state_mgr=None, policy_mgr=None, policy_client=None, ces_params=None, name="oCES2CESLayer"):
        self._loop              = loop
        self.naptr_list         = naptr_list
        self.cetp_client        = cetp_client            # H2H layer manager for remote-cesid 
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.cetp_state_mgr     = cetp_state_mgr
        self.policy_client      = policy_client
        self.policy_mgr         = policy_mgr
        self.ces_params         = ces_params
        self.c2c_transaction_list = []
        
        self.q                  = asyncio.Queue()        # Enqueues the CETP message from CETP Transport
        self.c2c_negotiated     = False
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oCES2CESLayer)
        self._logger.info("Initiating oCES2CESLayer towards cesid '{}'".format(r_cesid) )
        self.get_cetp_transport(naptr_list)


    def get_cetp_transport(self, naptr_list):
        self.transport_layer = oCESTransportMgr(naptr_list = naptr_list, c2clayer= self, r_cesid= self.r_cesid, loop=self._loop, ces_params=self.ces_params) 

    def send_cetp(self, msg):
        self.transport_layer.send_cetp(msg)

    def enqueue_transport_message_nowait(self, msg):
        self.q.put_nowait(msg)

    @asyncio.coroutine
    def enqueue_transport_message(self, msg):
        yield from self.q.put(msg)    

    @asyncio.coroutine
    def consume_transport_message(self):
        while True:
            de_queue = yield from self.q.get()
            msg, transport = de_queue
            self._logger.debug("Message from CETPTransportManager: "+ msg)
            
            if self.c2c_negotiated == False:
                self._logger.info(" C2C is not negotiated with remote-cesid '{}' yet.".format(self.r_cesid))
                asyncio.ensure_future(self.process_c2c(msg, transport))        # to exchange ces-policies and security policies.
                self.q.task_done()

            else:
                if self.is_c2c_transaction(msg):
                    # The message for a C2C transaction shall not reach the H2H-layer (i.e. CETPClient).    -- Unlike now.
                    self._logger.debug(" Post-C2C negotiation packet from '{}'.".format(self.r_cesid))       # to get c2c-level feedback or keepalive etc..
                    asyncio.ensure_future(self.process_c2c(msg, transport))
                    self.q.task_done()
                else:
                    self._logger.info(" Forward packet to H2H-layer")
                    self.forward_to_h2h_layer(de_queue)
                    self.q.task_done()

            

    def is_c2c_transaction(self, msg):
        cetp_msg = json.loads(msg)
        inbound_sst, inbound_dst = cetp_msg['SST'], cetp_msg['DST']
        packet_sst, packet_dst = inbound_dst, inbound_sst
        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if (c_sst == packet_sst) & (c_dst == packet_dst):
                return True
        return False
    
    def forward_to_h2h_layer(self, msg):
        self.cetp_client.enqueue_message_from_c2c_nowait(msg)

    @asyncio.coroutine            
    def process_c2c(self, msg, transport):
        #fucntion for -- CES2CES-FSM, security, remote CES feedback, evidence collection, and other indicators.
        #if c2c security FSM negotiation succeeds:     self.forward_to_h2h_layer(”trust_established”)
        # At some point, we gotta use report_host():  OR enforce_ratelimits():        # Invoking these methods to report a misbehaving host to remote CES.
                
        try:
            yield from asyncio.sleep(0.02)
            cetp_msg = json.loads(msg)
            inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
            sstag, dstag    = inbound_dstag, inbound_sstag
        except Exception as msg:
            self._logger.error("Exception in parsing the received message.")
            return
            
        if self.cetp_state_mgr.has( (sstag, 0) ):
            self._logger.debug("Continue resolving c2c-transaction (SST={}, DST={})".format(sstag, dstag))
            o_c2c = self.cetp_state_mgr.get( (sstag, 0) )
            result = o_c2c.continue_c2c_negotiation(cetp_msg, transport)
            (status, cetp_resp) = result
            
            if status == True:
                self.c2c_transaction_list.append(o_c2c)                                                 # Enqueuing the connected C2C transactions.
                self.c2c_negotiated = True
                self.cetp_client.c2c_negotiation_status(status=True)
                
            elif status == False:
                if len(cetp_resp) > 0:  self.send(cetp_resp)
                self.cetp_client.c2c_negotiation_status(status=False)
                self._logger.info("Close the Transport that triggered this CETP-C2C negotiation.")      # If it was the only transport, also clean all the resources towards remote CES.
                transport.close()
                # Also check the number of connected transports towards 'cesid'.. If no one is connected, clean all resources reserved towards 'cesid'
                
            elif status == None:
                self._logger.info(" CES-to-CES is not negotiated yet -> Continuing CES-to-CES negotiation ")
                transport.send_cetp(cetp_resp)


        elif self.cetp_state_mgr.has( (sstag, dstag) ):
            self._logger.debug("CETP Signalling for a negotiated transaction (SST={}, DST={})".format(sstag, dstag))
            o_c2c = self.cetp_state_mgr.get( (sstag, dstag) )
            msg = o_c2c.post_c2c_negotiation(cetp_msg, transport)
            if msg!=None:
                transport.send_cetp(msg)


    def report_connectivity(self, transport_obj, status=True):
        if status == True:
            self._logger.info("CETP Transport is connected -> Exchange the CES-to-CES policies.")
            self.initiate_c2c_transaction(transport_obj)
        else:
            self._logger.info("CETP Transport is disconnected -> Cleanup the resources.")
            

    def initiate_c2c_transaction(self, transport_obj):
        """ Initiates/Continues CES-to-CES negotiation """
        proto = ""
        for naptr_resp in self.naptr_list:
            dest_id, r_cesid, r_ip, r_port, proto = naptr_resp
            
        c2c_transaction  = cetpTransaction.oC2CTransaction(self._loop, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetp_state_mgr=self.cetp_state_mgr, policy_mgr=self.policy_mgr, proto=proto, ces_params=self.ces_params)
        resp = c2c_transaction.initiate_c2c_negotiation()
        if resp!=None:
            transport_obj.send_cetp(resp)
        else:
            self._logger.error(" CES-to-CES negotiation could not be initiated. Why? ")

            
    def __del__(self):
        self._logger.info("Deleting oCES2CESlayer")
        del(self.transport_layer)
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
        self.ces_params             = ces_params
        self.ces_certificate_path   = self.ces_params['certificate']
        self.ces_privatekey_path    = self.ces_params['private_key']
        self.ca_certificate_path    = self.ces_params['ca_certificate']                     
        self._loop                  = loop
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oCESTransportMgr)
        self._logger.info("Initiating oCESTransportMgr towards cesid '{}'".format(r_cesid) )
        self.initiate_cetp_transport(naptr_list)
   
            
    def initiate_cetp_transport(self, naptr_list):
        """ Intiates CETP Transports towards remote endpoints (for each 'naptr' record in the naptr_list) """
        for naptr_rec in naptr_list:
            dst_id, cesid, ip_addr, port, proto = naptr_rec
            asyncio.ensure_future(self.initiate_transport(proto, ip_addr, port))
            """
            # You can't simply initiate a task and expect that exception will be handled automatically. Instead you need to wait on the task.            
            # For RST exception handling its best to use the following code? Test it.

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
            
    @asyncio.coroutine
    def initiate_transport(self, proto, ip_addr, port):
        """ Description """
        if proto == 'tcp' or proto=="tls":
            self._logger.debug(" Initiating CETPTransport towards cesid '{}' @({}, {})".format(self.r_cesid, ip_addr, port))
            transport_instance = oCESTransportTCP(self, proto, self.r_cesid, loop=self._loop)
            
            if proto == "tls":
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
                    print(ex)
                    self._logger.info("Clean the allocated resources for CETPclient: initiated queues, tasks and others ")

            elif proto == "tcp":
                try:
                    coro = self._loop.create_connection(lambda: transport_instance, ip_addr, port)
                    connect_task = asyncio.ensure_future(coro)
                    yield from connect_task
                    self.initiated_transports.append(transport_instance)
                except Exception as ex:
                    self._logger.info("Exception in {} connection towards {}".format(proto, self.r_cesid))
                    print(ex)
                    self._logger.info("Clean the allocated resources for CETPclient: initiated queues, tasks and others ")


    def register_connected_transports(self, transport):
        """ Registered connected CETP Transports """
        self.connected_transports.append(transport)
    
    def select_transport(self):
        # some processing to select current cetp_transport, based on active health indicators of CETP transports
        # self.load_balancing() or self.best_Health(), or self.path_with_smalllest_rtt().            # return cetp_transport
        for transport in self.connected_transports:
            return transport

    def send_cetp(self, msg):
        current_transport = self.select_transport()
        current_transport.send_cetp(msg)

    def report_connectivity(self, transport_obj, status=True):
        if status==True:
            self.register_connected_transports(transport_obj)
        else:
            self.connected_transports.remove(transport_obj)
        self.c2c.report_connectivity(transport_obj, status)

    
    def data_from_transport(self, msg, transport):
        self.c2c.enqueue_transport_message_nowait((msg, transport))

    def close(self):
        self._logger.info("Close all the CETP transports")

    

class oCESTransportTCP(asyncio.Protocol):
    def __init__(self, transport_mgr, proto, r_cesid, loop=None, name="oCESTransport"):
        self.t_mgr          = transport_mgr
        self.r_cesid        = r_cesid 
        self._loop          = loop
        self.name           = name+proto
        self._logger        = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oCESTransportTCP)

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info('peername')
        self._logger.info('Connected to {}'.format(peername))
        self.t_mgr.report_connectivity(self)                 # Reporting the connectivity to upper layer.
        print()
        
    def send_cetp(self, msg):
        framed_msg = self.message_framing(msg)
        self.transport.write(framed_msg.encode())

    def message_framing(self, msg):
        # Some framing
        cetp_frame = msg
        return cetp_frame

    def data_received(self, data):
        """Asyncio coroutine to receive data"""
        data = data.decode()
        cetp_msg = self.unframe(data)
        self.t_mgr.data_from_transport(cetp_msg, self)

    def unframe(self, data):
        cetp_msg = data
        # Some processing.
        return cetp_msg
    
    def connection_lost(self, exc):
        self._logger.info('The server closed the connection')
        self.t_mgr.report_connectivity(self, status=False)
        # process exc

    def close(self):
        """ Closes the connection with the remote CES """
        self.transport.close()

