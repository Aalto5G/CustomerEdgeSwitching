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


LOGLEVEL_CETPServer                 = logging.INFO
LOGLEVEL_iCETPC2CLayer              = logging.INFO
LOGLEVEL_iCETPT2TManager            = logging.INFO
LOGLEVEL_iCESServerTransportTCP     = logging.INFO
LOGLEVEL_iCESServerTransportTLS     = logging.INFO

class CETPServer:
    def __init__(self, c2c_layer=None, l_cesid=None, r_cesid=None, loop=None, policy_mgr=None, cetpstate_mgr=None, name="CETPServer"):
        self.c2c_q              = asyncio.Queue()
        self.c2c                = c2c_layer
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self._loop              = loop
        self.policy_mgr         = policy_mgr
        self.cetpstate_mgr      = cetpstate_mgr
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPServer)
        self._logger.info("CETPServer created for cesid {}".format(l_cesid))

    def send(self, msg):
        self.c2c.send_cetp(msg)
 
    def enqueue_c2c_message_nowait(self, data):
        self.c2c_q.put_nowait(data)                     # Enqueues the CETP message from oCES, forwarded by CETPTransport & C2C layer

    @asyncio.coroutine
    def enqueue_c2c_message(self, msg):
        yield from self.c2c_q.put(msg)                  # More safe enqueuing

    @asyncio.coroutine
    def consume_c2c_message(self):
        """ Retrieves the enqueued CETP message for H2H CETP processing """
        while True:
            data = yield from self.c2c_q.get()
            asyncio.ensure_future(self.process_h2h_transaction(data))
            self.c2c_q.task_done()

    @asyncio.coroutine
    def process_h2h_transaction(self, data):
        msg, transport = data
        cetp_msg = json.loads(msg)
        inbound_sst, inbound_dst = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dst, inbound_sst                  # Storage view: (local_sst, local_dst) on sending -->  Thus we must flip the inbound (SST, DST), as SST of the remote-CES is DST of the local-CES. 
        yield from asyncio.sleep(0.01)                              # Simulating the delay upon interaction with the policy management system
        
        if inbound_sst == 0:
            self._logger.error(" Inbound SST cannot be zero")     # Sender must choose an SST
            return
            
        elif inbound_dst == 0:
            self._logger.info(" No prior Outbound H2H-transaction found -> Initiating Inbound H2HTransaction (SST={} -> DST={})".format(inbound_sst, inbound_dst))
            i_h2h = cetpTransaction.H2HTransactionInbound(cetp_msg, sstag=sstag, dstag=sstag, l_cesid=self.l_cesid, r_cesid=self.r_cesid, \
                                                             policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr)
            cetp_resp = i_h2h.start_cetp_processing(cetp_msg)
            if cetp_resp != None:    
                transport.send_cetp(cetp_resp)
            
        elif self.cetpstate_mgr.has((sstag, dstag)):
            oh2h = self.cetpstate_mgr.get((sstag, dstag))
            self._logger.info(" Outbound H2HTransaction found for (SST={}, DST={})".format(inbound_sst, inbound_dst))
            cetp_resp = oh2h.post_cetp_negotiation(cetp_msg)
            if cetp_resp != None:    
                transport.send_cetp(cetp_resp)



class iCETPC2CLayer:
    def __init__(self, r_cesid, icetp_mgr, name="iCETPC2CLayer"):
        self.q                      = asyncio.Queue()               # Enqueues the CETP messages from CETP Transport
        self.connected_transports   = []                            # Used to manager the CETP Transports
        self.c2c_transaction_list   = []
        self.pending_tasks          = []                            # iCETPC2CLayer specific
        self.r_cesid                = r_cesid
        self.icetp_mgr              = icetp_mgr
        self.transport_c2c_binding  = {}
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCETPC2CLayer)
        self._initiate_coroutines()

    def register_transport_c2cTransaction(self, transport, c2c_transaction):
        """ Registers the stateful-inbound c2c-transaction, connected transport, AND their relation """
        self.transport_c2c_binding[transport] = c2c_transaction
        self.add_c2c_transactions(c2c_transaction)
        self.add_connected_transport(transport)

    def _initiate_coroutines(self):
        t = asyncio.ensure_future(self.consume_transport_message())
        self.pending_tasks.append(t)

    def add_c2c_transactions(self, c2c_cetp_transaction):
        self.c2c_transaction_list.append(c2c_cetp_transaction)
    
    def remove_c2c_transactions(self, c2c_cetp_transaction):
        self.c2c_transaction_list.remove(c2c_cetp_transaction)

    def add_connected_transport(self, transport):
        self.connected_transports.append(transport)
        
    def remove_connected_transport(self, transport):
        if transport in self.connected_transports:
            self.connected_transports.remove(transport)
            
    def create_cetp_server(self, r_cesid, loop, policy_mgr, cetpstate_mgr, l_cesid):
        """ Creating the upper layer to handle CETPTransport """
        self.cetp_server = CETPServer(c2c_layer=self, l_cesid=l_cesid, r_cesid=r_cesid, loop=loop, policy_mgr=policy_mgr, cetpstate_mgr=cetpstate_mgr)
        t = asyncio.ensure_future(self.cetp_server.consume_c2c_message())
        self.pending_tasks.append(t)
        
    def report_connectivity(self, transport, connectivity_status=True):
        if connectivity_status == False:
            ic2c_transaction = self.transport_c2c_binding[transport]
            ic2c_transaction.set_terminated()                              # Lead to termination of c2c-transaction AND scheduled tasks.
            self.remove_c2c_transactions(ic2c_transaction)
            self.remove_connected_transport(transport)
            del self.transport_c2c_binding[transport]
            
            if len(self.connected_transports) ==0:
                self._logger.info("No connected transport with remote CES '{}'".format(self.r_cesid))
                self.icetp_mgr.delete_c2c_layer(self.r_cesid)                   # Remove the c2c-layer registered to 'r_cesid'
                
                self._logger.info("Terminating pending tasks for cesid '{}'".format(self.r_cesid))
                for tsk in self.pending_tasks:
                    tsk.cancel()
                    
                self._logger.info("Terminating iCETPC2CLayer and CETPServer instance for cesid '{}'".format(self.r_cesid))
                del(self.cetp_server)                                               # CETPServer's task is already deleted
                del(self)
                
                
    def send_cetp(self, msg):
        """ Useful when initiating a (feedback/evidence/keepalive) message towards oCES """
        for transport in self.connected_transports:
            transport.send_cetp(msg)

    def enqueue_transport_message_nowait(self, data):
        self.q.put_nowait(data)                                 # Needs try except to handle case of full queue

    @asyncio.coroutine
    def enqueue_transport_message(self, msg):
        yield from self.q.put(msg)

    @asyncio.coroutine
    def consume_transport_message(self):
        while True:
            de_queue = yield from self.q.get()
            try:
                data, transport = de_queue
                #self._logger.debug("data: {!r}".format(data))
                cetp_msg = json.loads(data)
                #self._logger.debug("cetp_msg: {!r}".format(cetp_msg))
                inbound_sst, inbound_dst = cetp_msg['SST'], cetp_msg['DST']
            except Exception as msg:
                self._logger.info(" Exception in the received message")
                self.q.task_done()
                continue
            
            if self.is_c2c_transaction(inbound_sst, inbound_dst):
                self._logger.debug(" Inbound packet belongs to an established C2C transaction.")
                self.process_c2c(cetp_msg, transport)
                self.q.task_done()
            else:
                self._logger.debug(" Forward the packet to H2H-layer")
                self.forward_h2h(de_queue)
                self.q.task_done()

    def is_c2c_transaction(self, inbound_sst, inbound_dst):
        """ Checks if the cetp-message has (sst, dst) tags allocated for c2c-transaction  """
        sst, dst = inbound_dst, inbound_sst                                         # Reversing the (SST, DST) order to correspond to the local view of the (SST, DST).
        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if (c_sst == sst) & (c_dst == dst):
                return True
        return False

    def forward_h2h(self, queued_item):
        self.cetp_server.enqueue_c2c_message_nowait(queued_item)
            
    def process_c2c(self, cetp_msg, transport):
        """ Processes C2C-CETP flow in post-c2c negotiation phase """
        c2c_transaction = None
        sst, dst = cetp_msg['DST'], cetp_msg['SST']
        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if (c_sst == sst) & (c_dst == dst):
                ic2c_transaction = c2c_transaction
                break
        
        ic2c_transaction.post_c2c_negotiation(cetp_msg, transport)                  # Shall have logic for security, remote CES feedback, evidence collection etc.


    def feedback(self):
        """ Dummy method: simulating the methods used for reporting a host, or enforcing ratelimits to remote CES """
        pass


CETP_MSG_LEN = 2    


class iCESServerTransportTCP(asyncio.Protocol):
    def __init__(self, loop, c2c_mgr = None, name="iCESServerTransportTCP"):
        self._loop           = loop
        self.proto           = "tcp"
        self.c2c_mgr         = c2c_mgr                  # c2c-Manager handles a newly connected client, and assigns as C2C layer if the c2c-negotiation (trust) establishes.
        self.r_cesid         = None                     # Indicates if iCES knows the remote 'r_cesid' (having negotiated the c2c-policy with remote endpoint).
        self.c2c_layer       = None
        self.is_closed       = False
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESServerTransportTCP)
        self.data_buffer     = b''
        self.c2c_negotiation_threshold = 5              # In seconds
        
    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.peername))
        self.transport = transport
        ip_addr, port = self.peername
        
        if self.c2c_mgr.remote_endpoint_malicious_history(ip_addr) == True:
            self._logger.info("Closing connection, as Remote endpoint has the misbehavior history.")
            self.close()
        else:
            self._loop.call_later(self.c2c_negotiation_threshold, self.is_c2c_negotiated)     # Terminates the CETPTransport with a client, if C2C not negotiated in To.

         
    def is_c2c_negotiated(self):
        """ Prevents the case, where a TCPClient simply connects (for t>To), without ever sending any packet or negotiating C2C policies with CETP-Server Transport. """        
        if self.r_cesid==None and (not self.is_closed):
            self._logger.info(" Closing connection, as remote end did not complete C2C negotiation in To={}".format(str(self.c2c_negotiation_threshold)))
            self.close()

    def set_c2c_details(self, r_cesid, c2c_layer):
        """ Transport gets details about C2Clayer from inbound-C2CManager """
        self.r_cesid = r_cesid
        self.c2c_layer  = c2c_layer

    def send_cetp(self, msg):
        to_send = self.message_framing(msg)
        self.transport.write(to_send)

    def message_framing(self, msg):
        self._logger.debug("Message to send: {!r}".format(msg))
        cetp_msg = msg.encode()
        msg_length = len(cetp_msg)                                                   # Instead of binary encoding - what could be the fastest encoding of length field.
        len_bytes = (msg_length).to_bytes(CETP_MSG_LEN, byteorder="big")        # Time-it the pyhton's binary encoding.
        to_send = len_bytes + cetp_msg
        return to_send
        
    def data_received(self, data):
        self.buffer_and_parse_stream(data)
    
    def buffer_and_parse_stream(self, data):
        """ 
        1. Appends new data from the wire to a buffer;  2. Parses the stream into CETP messages; 
        3. invokes CETP process to handle message;      4. Removes processed data from the buffer.
        """
        
        self.data_buffer = self.data_buffer+data
        #print(self.data_buffer)
        while True:
            if len(self.data_buffer) < CETP_MSG_LEN:
                break
            
            len_field = self.data_buffer[0:CETP_MSG_LEN]                                            # Possible to read length field in the buffered data
            msg_length = int.from_bytes(len_field, byteorder='big')

            if len(self.data_buffer) >= (CETP_MSG_LEN + msg_length):
                #self._logger.debug(" Reading CETP message from streamed data.")
                cetp_data = self.data_buffer[CETP_MSG_LEN:CETP_MSG_LEN+msg_length]
                cetp_msg = cetp_data.decode()
                #self._logger.debug('Data received: {!r}'.format(cetp_msg))
                self.data_buffer = self.data_buffer[CETP_MSG_LEN+msg_length:]           # Moving ahead in the buffered data

                if self.r_cesid is None:
                    self.c2c_mgr.process_inbound_message(cetp_msg, self)                # Forward the message to inbound-c2cmanager for C2C negotiation.
                else:
                    self._logger.debug(" Forward the message to CETP-C2C layer")
                    self.c2c_layer.enqueue_transport_message_nowait((cetp_msg, self))   # Sending the transport alongside the message, for sending reply.
            else:
                break

            
    def connection_lost(self, ex):
        """ Called by asyncio framework """
        self._logger.info("Remote endpoint closed the connection")
        if self.c2c_layer != None:
            self.c2c_layer.report_connectivity(self, connectivity_status=False)
        self.is_closed = True
        
    def close(self):
        """ Closes the connection with the remote CES """
        self._logger.info("Closing connection to remote endpoint")
        self.transport.close()
        if self.c2c_layer != None:
            self.c2c_layer.report_connectivity(self, connectivity_status=False)


class iCESServerTransportTLS(asyncio.Protocol):
    def __init__(self, loop, ces_certificate, ca_certificate, c2c_mgr = None, name="iCESServerTransportTLS"):
        self._loop           = loop
        self.ces_certificate = ces_certificate
        self.ca_certificate  = ca_certificate
        self.proto           = "tls"
        self.c2c_mgr         = c2c_mgr                  # c2c-Manager handles a newly connected client, and assigns as C2C layer if the c2c-negotiation (trust) establishes with remote end.
        self.r_cesid         = None                     # Indicates if iCES knows the remote 'cesid' (having negotiated the c2c-policy with remote endpoint).
        self.c2c_layer       = None
        self.is_closed       = False
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESServerTransportTLS)
        self.data_buffer     = b'' 
        self.c2c_negotiation_threshold  = 5
        
    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.peername))
        self.transport = transport
        ip_addr, port = self.peername

        if self.c2c_mgr.remote_endpoint_malicious_history(ip_addr) == True:
            self._logger.info("Closing: Remote endpoint has the misbehavior history.")
            self.close()
        else:
            self._loop.call_later(self.c2c_negotiation_threshold, self.is_c2c_negotiated)     # Terminates the connection from a client, if C2C not negotiated in To.


    def is_c2c_negotiated(self):
        """ Prevents the case, where a TCPClient simply connects (for t>To), without ever sending any packet or negotiating C2C policies with CETP-Server Transport. """        
        if self.r_cesid==None and (not self.is_closed):
            self._logger.info(" Closing connection, as remote end did not complete C2C negotiation in To={}".format(str(self.c2c_negotiation_threshold)))
            self.close()

    def set_c2c_details(self, r_cesid, c2c_layer):
        """ Transport gets details about C2Clayer from inbound-C2CManager """
        self.r_cesid = r_cesid
        self.c2c_layer  = c2c_layer

    def send_cetp(self, msg):
        to_send = self.message_framing(msg)
        self.transport.write(to_send)

    def message_framing(self, msg):
        self._logger.debug("Message to send: {!r}".format(msg))
        cetp_msg = msg.encode()
        msg_length = len(cetp_msg)                                                   # Instead of binary encoding - what could be the fastest encoding of length field.
        len_bytes = (msg_length).to_bytes(CETP_MSG_LEN, byteorder="big")        # Time-it the pyhton's binary encoding.
        to_send = len_bytes + cetp_msg
        return to_send


    def data_received(self, data):
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
                #self._logger.debug(" Reading CETP message from streamed data.")
                cetp_data = self.data_buffer[CETP_MSG_LEN:CETP_MSG_LEN+msg_length]
                cetp_msg  = cetp_data.decode()
                #self._logger.debug('Data received: {!r}'.format(cetp_msg))
                self.data_buffer = self.data_buffer[CETP_MSG_LEN + msg_length:]           # Moving ahead in the buffered data

                if self.r_cesid is None:
                    self.c2c_mgr.process_inbound_message(cetp_msg, self)                # Forward the message to inbound-c2cmanager for C2C negotiation.
                else:
                    self._logger.info(" Forward the message to CETP-C2C layer")
                    self.c2c_layer.enqueue_transport_message_nowait((cetp_msg, self))   # Sending the transport alongside the message, for sending reply.
            else:
                break

        
    def connection_lost(self, ex):
        self._logger.info("Remote endpoint closed the connection")
        if (self.c2c_layer != None) and (self.is_closed == False):
            self.c2c_layer.report_connectivity(self, connectivity_status=False)
            self.is_closed = True
        
    def close(self):
        """ Closes the connection with the remote CES """
        self._logger.info("Closing connection to remote endpoint")
        self.transport.close()
        if (self.c2c_layer != None) and (self.is_closed == False):
            self.c2c_layer.report_connectivity(self, connectivity_status=False)
            self.is_closed = True

