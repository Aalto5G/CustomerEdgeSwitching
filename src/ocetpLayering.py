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
import cetpTransaction_v2
import icetpLayering
import ocetpLayering


LOGLEVEL_CETPClient             = logging.INFO
LOGLEVEL_oCES2CESLayer          = logging.INFO
LOGLEVEL_oCESTransportMgr       = logging.INFO
LOGLEVEL_oCESTransportTCP       = logging.INFO



class CETPClient:
    def __init__(self, l_cesid= None, r_cesid=None, cb_func=None, cetp_state_mgr= None, policy_client=None, policy_mgr=None, loop=None, name="CETPClient"):
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.cb_func            = cb_func
        self.cetp_state_mgr     = cetp_state_mgr
        self.policy_client      = policy_client
        self.policy_mgr         = policy_mgr
        self._loop              = loop
        
        self.client_q           = asyncio.Queue()           # Enqueues the naptr responses triggered by private hosts (served by CES)
        self.c2c_q              = asyncio.Queue()           # Enqueues the response from remote peer (iCES), to H2H transactions
        self.c2c_negotiated     = False
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPClient)
        

    def get_cetp_c2c(self, naptr_list):
        """ Initiates CETPc2clayer between two CES nodes """
        self.c2c = oCES2CESLayer(naptr_list=naptr_list, cetp_client=self, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetp_state_mgr= self.cetp_state_mgr, \
                                 policy_mgr=self.policy_mgr, policy_client=self.policy_client, loop=self._loop)
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
            if self.c2c_negotiated == False:                    # Prevents processing of h2h, until the c2c-negotiation has completed.
                yield from asyncio.sleep(0.05)                  # 2-to-5 millisecond interval for re-checking if trust established
                if (time.time() - start_time) > 2.0:            # To detect if remote end is unreachable
                    self._logger.error("CETPClient: c2c connection didn't complete in time (To)")
                    self._logger.debug("CETPClient instance, c2cLayer and CETPTransport for this 'cesid' shall be terminated")
                    break
                    # Delete the client instance and any 'naptr' response stored in the queue
                continue
            else:
                try:
                    queued_data = yield from self.client_q.get()
                    (naptr_rr, cb_args) = queued_data                               # Could it be on a list on naptr records? If yes, how to handle it?
                    if naptr_rr == None:
                        self._logger.info("None received to terminate  the CETP client queue towards CETPManager")
                        break

                    for naptr in naptr_rr:
                        dest_id, r_cesid, r_ip, r_port, r_transport = naptr          # Assuming single naptr response here.
                    
                except Exception as msg:
                    self._logger.info("Terminating CETPClient queue towards cesid {}".format(self.r_cesid))
                    break
                #asyncio.ensure_future(self.h2h_transaction(msg) )
                asyncio.ensure_future(self.h2h_transaction_start(cb_args, dest_id))    # On temporary basis.
                self.client_q.task_done()

            
    @asyncio.coroutine
    def h2h_transaction_start(self, cb_args, dst_id):
        dns_q, addr = cb_args
        h2h = cetpTransaction_v2.H2HTransactionOutbound(dns_q=dns_q, local_addr=addr, src_id="", dst_id=dst_id, l_cesid=self.l_cesid, r_cesid=self.r_cesid, \
                                                        policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetp_state_mgr, dns_callback=self.cb_func)
        
        cetp_packet = yield from h2h.start_cetp_processing()
        self.send(cetp_packet)

    @asyncio.coroutine
    def h2h_transaction_continue(self, cetp_data):
        o_transaction = None
        yield from asyncio.sleep(0.01)
        try:
            cetp_msg = json.loads(cetp_data)
            inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
            sstag, dstag    = inbound_dstag, inbound_sstag
            
        except Exception as msg:
            self._logger.error("Exception in parsing the received message.")
            return
            
        if self.cetp_state_mgr.has( (sstag, 0) ):
            self._logger.debug("Continue resolving h2h_transaction (SST={}, DST={})".format(sstag, dstag))
            o_h2h = self.cetp_state_mgr.get( (sstag, 0) )
            msg = o_h2h.continue_cetp_processing(cetp_msg)
            if msg!=None:
                self.send(msg)

        elif self.cetp_state_mgr.has( (sstag, dstag) ):
            self._logger.debug("CETP Signalling for a negotiated transaction (SST={}, DST={})".format(sstag, dstag))
            o_h2h = self.cetp_state_mgr.get( (sstag, dstag) )
            msg = o_h2h.post_establishment(cetp_msg)
            if msg!=None:
                self.send(msg)
        

    def if_c2c_negotiated(self):
        return self.c2c_negotiated
    
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
                msg = yield from self.c2c_q.get()                   # Gets the CETP message sent by iCES            
                if msg == "c2c negotiated":
                    self.c2c_negotiated = True
                    self._logger.info("C2C is negotiated -> Trigger h2h policy negotiations ")
                else:
                    asyncio.ensure_future(self.h2h_transaction_continue(msg))

            except Exception as msg:
                self._logger.debug("Exception in consuming message from c2c-layer")

    @asyncio.coroutine
    def dummy_io_delay_and_dnscallback(self, msg, cb_args):
        yield from asyncio.sleep(1.0)
        self._logger.debug("Message: ", msg)
        (query, addr) = cb_args
        self.cb_func(query, addr)




class oCES2CESLayer:
    """
    Expected outcome from class is the timely negotiation of the CES-to-CES policies.
    If c2c doesn't successfully complete in time 'To', this shall be detected and negotiation shall fail in time 'To'.        (Not implemented yet)
    """
    def __init__(self, naptr_list=[], cetp_client=None, l_cesid=None, r_cesid=None, cetp_state_mgr=None, policy_mgr=None, policy_client=None, loop=None, name="oCES2CESLayer"):
        self.naptr_list     = naptr_list
        self.cetp_client    = cetp_client            # H2H layer manager for remote-cesid 
        self.l_cesid        = l_cesid
        self.r_cesid        = r_cesid
        self.cetp_state_mgr = cetp_state_mgr
        self.policy_client  = policy_client
        self.policy_mgr     = policy_mgr
        self._loop          = loop
        
        self.q              = asyncio.Queue()        # Enqueues the CETP message from CETP Transport
        self.c2c_negotiated = False
        self.get_cetp_transport(naptr_list)
        self._logger        = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oCES2CESLayer)
        self._logger.info("Initiating oCES2CESLayer towards cesid '{}'".format(r_cesid) )


    def get_cetp_transport(self, naptr_list):
        self.transport_layer = oCESTransportMgr(naptr_list = naptr_list, c2clayer= self, r_cesid= self.r_cesid, loop=self._loop) 

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
            msg = yield from self.q.get()
            #print("\nMessage from CETPTransportManager (consume_transport_message(: msg): ", msg)
            if self.c2c_negotiated == False:
                self._logger.info("c2c is not negotiation with remote-cesid ''".format(self.r_cesid))
                asyncio.ensure_future(self.process_c2c(msg))        # to exchange ces-policies and security policies.
                self.q.task_done()

            else:
                self._logger.info(" Forward message to H2H-layer")
                self.forward_to_h2h_layer(msg)            # - Message belongs to H2H layer.
                self.q.task_done()

            """                                                # Commented for testing only, to forward packets to h2h-layer?    - For testing only, need for more logic here
            elif self.c2c_negotiated == True: #AND (sstag, dstag) belong to another c2c:
                asyncio.ensure_future(self.process_c2c(msg))        # to exchange ces-policies and security policies on another naptr.
            elif  self.is_c2c_transaction(msg) & self.c2c_negotiated==True:
                asyncio.ensure_future(self.process_c2c(msg))        # to get c2c-feedback or keepalive or whatever.
                self.q.task_done()
            """
        

    def is_c2c_transaction(msg):
        # Do some processing.
        return False                    # Either return True or return False.
    
    def forward_to_h2h_layer(self, msg):
        self.cetp_client.enqueue_message_from_c2c_nowait(msg)

    @asyncio.coroutine            
    def process_c2c(self, msg):
        #fucntion for -- CES2CES-FSM, security, remote CES feedback, evidence collection, and other indicators.
        #if c2c security FSM negotiation succeeds:     self.forward_to_h2h_layer(”trust_established”)

        yield from asyncio.sleep(0.02)
        
        if msg == "Channel connected":
            self._logger.info("CETP Transport is connected --> Exchange the CES-to-CES policies")
            self.initiate_c2c_transaction()
        else:
            try:
                cetp_msg = json.loads(msg)
                inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
                sstag, dstag    = inbound_dstag, inbound_sstag
            except Exception as msg:
                self._logger.error("Exception in parsing the received message.")
                return
                
            if self.cetp_state_mgr.has( (sstag, 0) ):
                self._logger.debug("Continue resolving c2c-transaction (SST={}, DST={})".format(sstag, dstag))
                o_c2c = self.cetp_state_mgr.get( (sstag, 0) )
                result = o_c2c.continue_c2c_negotiation(cetp_msg)
                (status, cetp_resp) = result
                
                if status == True:
                    self.c2c_negotiated = True
                    self.forward_to_h2h_layer("c2c negotiated")
                elif status == False:
                    if len(cetp_resp) > 0:
                        self.send(cetp_resp)
                    self.forward_to_h2h_layer("c2c negotiation failed")
                    self._logger.info("Close the Transport that triggered this CETP-C2C negotiation.")      # If it was the only transport, also clean all the resources towards remote CES.
                    #self.transport_layer.close()
                    
                elif status == None:
                    self._logger.info(" CES-to-CES is not negotiated yet -> Continuing CES-to-CES negotiation ")
                    self.send(cetp_resp)

    
            elif self.cetp_state_mgr.has( (sstag, dstag) ):
                self._logger.debug("CETP Signalling for a negotiated transaction (SST={}, DST={})".format(sstag, dstag))
                o_c2c = self.cetp_state_mgr.get( (sstag, dstag) )
                msg = o_c2c.post_c2c_negotiation(cetp_msg)
                if msg!=None:
                    self.send(msg)




    def initiate_c2c_transaction(self):
        """ Initiates/Continues CES-to-CES negotiation """
        c2c = cetpTransaction_v2.oC2CTransaction(l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetp_state_mgr=self.cetp_state_mgr, policy_mgr=self.policy_mgr)
        resp = c2c.initiate_c2c_negotiation()
        if resp!=None:
            self.send_cetp(resp)
        else:
            self._logger.error(" CES-to-CES negotiation could not be initiated. Why? ")
            
        #report_host():  OR enforce_ratelimits():        # Invoking these methods to report a misbehaving host to remote CES.



class oCESTransportMgr:
    def __init__(self, naptr_list=[], c2clayer= None, r_cesid= None, loop=None, name="oCESTransportMgr"):
        self.c2c                  = c2clayer
        self.r_cesid              = r_cesid
        self.initiated_transports = []
        self.connected_transports = []
        self._loop                = loop
        self._logger              = logging.getLogger(name)
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
        if proto == 'tcp':
            self._logger.debug(" Initiating CETPTransport towards cesid '{}' @({}, {})".format(self.r_cesid, ip_addr, port))
            transport_instance = oCESTransportTCP(self, proto, self.r_cesid)
            self.initiated_transports.append(transport_instance)
        
        try:
            coro = self._loop.create_connection(lambda: transport_instance, ip_addr, port)
            connect_task = asyncio.ensure_future(coro)
            yield from connect_task
            self.initiated_transports.append(transport_instance)
        except Exception as ex:
            self._logger.info("Exception in connection towards {}".format(self.r_cesid),  ex)                  # ex.errno == 111 -- means connection RST received
            self._logger.info("Clean the allocated resources for CETPclient: initiated queues, tasks and others ")


    def register_connected_transports(self, transport):
        """ Registered connected CETP Transports """
        self.connected_transports.append(transport)
    
    def select_transport(self):
        for transport in self.connected_transports:
            return transport
        # some processing to select current cetp_transport, based on
        # self.load_balancing() or self.best_Health(), or self.path_with_smalllest_rtt().
        # return cetp_transport

    
    def send_cetp(self, msg):
        current_transport = self.select_transport()
        current_transport.send_cetp(msg)

    def data_received_from_transport(self, msg, transport):
        self.transport_layer_specific_processing()        # Last seen timestamp etc.
        if msg == "Channel connected":
            self.register_connected_transports(transport)
        self.c2c.enqueue_transport_message_nowait(msg)
        self._logger.debug(" data_received_from_transport: {}".format(msg))
        #Also manages: 1) transport link failover; 2) keepalive signalling for health-checking of the transport link.

    def transport_layer_specific_processing(self):
        pass

    def close(self):
        self._logger.info("Close all CETP transports")


class oCESTransportTCP(asyncio.Protocol):
    def __init__(self, transport_mgr, proto, r_cesid, name="oCESTransportTCP"):
        self.t_mgr          = transport_mgr
        self.r_cesid        = r_cesid 
        self._logger        = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oCESTransportTCP)

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info('peername')
        self._logger.info('Connected to {}'.format(peername))
        self.t_mgr.data_received_from_transport("Channel connected", self)      # Reporting the connectivity to upper layer.
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
        n_data = data.decode()
        cetp_msg = self.unframe(n_data)
        self.t_mgr.data_received_from_transport(cetp_msg, None)

    def unframe(self, data):
        cetp_msg = data
        # Some processing.
        return cetp_msg
    
    def connection_lost(self, exc):
        self._logger.info('The server closed the connection')
        # process exc

    def close(self):
        """ Closes the connection with the remote CES """
        self.transport.close()


class oCESTransportTLS(asyncio.Protocol):
    def __init__(self, loop, ces_cert, ces_privkey, ca_cert, cetpstate_mgr= None, policy_mgr= None, dns_callback=None, cb_args=None, local_cesid= None, remote_cesid=None, dest_hostid=None):
        self._loop           = loop
        self.transport      = None
        self.cb_func        = dns_callback
        self.initial_args   = cb_args
        self.cetpstate_mgr  = cetpstate_mgr
        self.policy_mgr     = policy_mgr
        self.local_cesid    = local_cesid
        self.remote_cesid   = remote_cesid
        self.dest_hostid    = dest_hostid 
        self.ces_certificate, self.ces_privatekey, self.ca_certificate = ces_cert, ces_privkey, ca_cert
        self.dns_for_sstag = {}                 # {(SSTag, DSTag):__, } 
        self.process_first_dnsreq()

    def process_first_dnsreq(self):
        """ Needed to create first CETP packet based on DNS NAPTR response, on established TCP connection """
        self.initial_dnsQ = self.initial_args[0]

    def connection_made(self, transport):
        self.transport = transport
        self.sockname = transport.get_extra_info('sockname')
        self.peername = transport.get_extra_info('peername')
        print("Connection established from", self.sockname, " to ", self.peername)
        dnsmsg, addr = self.initial_args
        
        src_id  = "hosta1.demo.lte"             # Translation of (IP->FQDN) & (FQDN-policy) missing
        r_cesid = self.remote_cesid
        dst_id  = self.dest_hostid              # src_id, r_cesid, dst_id, Shall come from dnsReq, and dnsMsg
        
        oces_transaction = cetpTransaction_v2.CETPStateful(dnsmsg=dnsmsg, local_addr=self.sockname, remote_addr=self.peername, cetpstate_mgr=self.cetpstate_mgr, policy_mgr=self.policy_mgr, src_id=src_id, l_cesid=self.local_cesid, r_cesid=r_cesid, dst_id=dst_id)
        cetp_packet = oces_transaction.start_transaction()
        sstag, dstag = oces_transaction.sstag, oces_transaction.dstag
        self.dns_for_sstag[(sstag,0)] = self.initial_args
        self.transport.write(cetp_packet.encode())
        
        
    def data_received(self, data):
        """ Uses inbound CETP's (SST & DST) in connectionTable for Existing/Ongoing CETP resolutions """
        inbound_cetp = data.decode()                        # Assuming that other hand replays the message
        cetp_packet = json.loads(inbound_cetp)
        #print('Data received: {!r}'.format(inbound_cetp))
        sstag, dstag = cetp_packet["SST"], cetp_packet["DST"]
        sstag = int(sstag)
        
        if self.cetpstate_mgr.has((dstag, 0)):                                      # i_dstag = o_sstag
            print("The CETP packet belongs to an ongoing CETP transaction")
            cetp_transaction = self.cetpstate_mgr.get((dstag, 0))
            cetp_resp = cetp_transaction.continue_establishing(cetp_packet)
            
            if cetp_resp==True:                             # The resolution succeeds, run the following code as callback
                cb_args = self.dns_for_sstag[(dstag, 0)]
                dnsQ, addr = cb_args
                self.cb_func(dnsQ, addr, success=cetp_resp)
            elif cetp_resp==False:
                #print("CETP resolution failed callback")
                cb_args = self.dns_for_sstag[(dstag, 0)]
                dnsQ, addr = cb_args
                self.cb_func(dnsQ, addr, success=cetp_resp)
                return False
            elif cetp_resp==None:
                print("Malformed packet.. Ignore and silently drop")
                return False
            else:
                print("Return the generated packet")
                self.transport.write(cetp_resp.encode())

        elif self.cetpstate_mgr.has((sstag, dstag)):
            print("The packet belongs to an established CETP Transaction")
            cetp_transaction = self.cetpstate_mgr.get((sstag, dstag))
            cetp_transaction.post_establishment(cetp_packet)
        else:
            print("Silently drop the packet")
            
        
    def process_message(self, r_cesid="", src_hostid="", dst_hostid="", cb_args=None):
        """ Triggers CETPStateful Resolution for resolved NAPTR responses """
        src_id  = "hosta1.demo.lte"             # Policy associated to Host-ip... Host-ip is associated to host-id
        r_cesid = r_cesid
        dst_id  = dst_hostid                    # src_id, r_cesid, dst_id, Shall come from dnsReq, and dnsMsg
        dnsquery = cb_args[0]
        
        oces_transaction = cetpTransaction.CETPStateful(dnsmsg=dnsquery, local_addr=self.sockname, remote_addr=self.peername, cetpstate_mgr=self.cetpstate_mgr, policy_mgr=self.policy_mgr, src_id=src_id, r_cesid=r_cesid, dst_id=dst_id)
        cetp_packet = oces_transaction.start_transaction()
        sstag, dstag = oces_transaction.sstag, oces_transaction.dstag
        self.dns_for_sstag[(sstag,0)] = cb_args
        self.transport.write(cetp_packet.encode())
        
    def connection_lost(self, exc):
        self._logger.info('The server closed the connection')           # Remove it from the list of local_ep, when connection is closed.


