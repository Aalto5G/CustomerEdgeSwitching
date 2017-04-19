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
        self.count              = 0                             # For debugging
        self._closure_signal    = False
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
            try:
                de_queue = yield from self.c2c_q.get()
                msg, transport = de_queue
                asyncio.ensure_future(self.process_h2h_transaction(msg, transport))
                self.c2c_q.task_done()
            except Exception as msg:
                self._logger.info("Exception in task for consuming c2c message")
                if self._closure_signal: break
                
    def set_closure_signal(self):
        self._closure_signal = True
    
    @asyncio.coroutine
    def process_h2h_transaction(self, msg, transport):
        #self.count += 1
        #self._logger.debug("self.count: {}".format(self.count))
        cetp_msg = json.loads(msg)
        inbound_sst, inbound_dst = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dst, inbound_sst                  # SST of the remote-CES is DST of the local-CES. 
        yield from asyncio.sleep(0.01)                              # Simulating the delay upon interaction with the policy management system
        
        if inbound_dst == 0:
            self._logger.info(" No prior Outbound H2H-transaction found -> Initiating Inbound H2HTransaction (SST={} -> DST={})".format(inbound_sst, inbound_dst))
            i_h2h = H2HTransaction.H2HTransactionInbound(cetp_msg, sstag=sstag, dstag=sstag, l_cesid=self.l_cesid, r_cesid=self.r_cesid, \
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
        self.q                      = asyncio.Queue()               # Enqueues the messages from CETP Transport
        self.connected_transports   = []                            # To manage the connected CETP Transports
        self.c2c_transaction_list   = []
        self.pending_tasks          = []                            # iCETPC2CLayer specific
        self.r_cesid                = r_cesid
        self.icetp_mgr              = icetp_mgr
        self.transport_c2c_binding  = {}
        self._closure_signal        = False
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
    
    def cancel_pending_tasks(self):
        self._logger.info("Terminating pending tasks for cesid '{}'".format(self.r_cesid))
        for tsk in self.pending_tasks:
            self._logger.debug("Cancelling the pending tasks")
            if not tsk.cancelled():
                tsk.cancel()

    def handle_interrupt(self):
        self._closure_signal = True
        self.cetp_server.set_closure_signal()
        self.cancel_pending_tasks()
    
    def report_connection_closure(self, transport):
        """ Removes connected client & checks for C2C-level connectivity """
        ic2c_transaction = self.transport_c2c_binding[transport]
        ic2c_transaction.set_terminated()                              # Leads to termination of tasks scheduled within c2c-transaction.
        self.remove_c2c_transactions(ic2c_transaction)
        self.remove_connected_transport(transport)
        del self.transport_c2c_binding[transport]
        self.handle_interrupt()
        
        if len(self.connected_transports) ==0:
            self._logger.info("No connected transport with remote CES '{}'".format(self.r_cesid))
            self.icetp_mgr.delete_c2c_layer(self.r_cesid)                   # Remove the c2c-layer registered to 'r_cesid'
            self.cancel_pending_tasks()
                
            self._logger.info("Terminating inbound C2C-Layer and CETPServer for cesid '{}'".format(self.r_cesid))
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
            try:
                de_queue = yield from self.q.get()
                msg, transport = de_queue
                if not self._pre_process(msg):
                    self.q.task_done()
                    continue                                        # What to do for repeated failures?
                    
                #self._logger.debug("data: {!r}".format(msg))
                #self._logger.debug("cetp_msg: {!r}".format(cetp_msg))
                cetp_msg = json.loads(msg)
                inbound_sst, inbound_dst = cetp_msg['SST'], cetp_msg['DST']
                sst, dst = inbound_dst, inbound_sst
                
                if self.is_c2c_transaction(sst, dst):
                    self._logger.debug(" Inbound packet belongs to an established C2C transaction.")
                    self.process_c2c(cetp_msg, transport)
                    self.q.task_done()
                else:
                    self._logger.debug(" Forward the packet to H2H-layer")
                    self.forward_h2h(de_queue)
                    self.q.task_done()
            
            except Exception as msg:
                self._logger.info(" Exception in consuming Transport message")
                if self._closure_signal: break

    def _pre_process(self, msg):
        """ Checks whether inbound message conforms to CETP packet format. """
        try:
            cetp_msg = json.loads(msg)
            inbound_sstag, inbound_dstag, ver = cetp_msg['SST'], cetp_msg['DST'], cetp_msg['VER']
            sstag, dstag    = inbound_dstag, inbound_sstag
            
            if ( (sstag==0) and (dstag ==0)) or (sstag < 0) or (dstag < 0) or (inbound_sstag == 0):
                self._logger.info(" Session tag values are not acceptable")
                return False
            
            if ver!=1:
                self._logger.info(" The CETP version is not supported.")
                return False

        except Exception as msg:
            self._logger.error(" Exception in pre-processing the received message.")
            return False
        return True

    
    def is_c2c_transaction(self, sst, dst):
        """ Checks if (SST, DST) of the inbound CETP-message belongs to a C2C-transaction """
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
    def __init__(self, loop, ces_params, c2c_mgr = None, name="iCESServerTransportTCP"):
        self._loop           = loop
        self.proto           = "tcp"
        self.c2c_mgr         = c2c_mgr                  # Inbound c2c-Manager for handling a newly connected client.
        self.c2c_layer       = None                     # CES-to-CES layer assigned by inbound C2CManager on completion of C2C-negotiation
        self.r_cesid         = None
        self.is_connected    = False
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESServerTransportTCP)
        self.data_buffer     = b''
        self.c2c_negotiation_threshold = ces_params['max_c2c_negotiation_duration']              # In seconds
        
    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.peername))
        self.transport = transport
        ip_addr, port = self.peername
        self.is_connected   = True
        
        if self.c2c_mgr.remote_endpoint_malicious_history(ip_addr) == True:
            self._logger.info(" Remote endpoint has misbehavior history.")
            self.close()
        else:
            self._loop.call_later(self.c2c_negotiation_threshold, self.is_c2c_negotiated)     # Schedules a check for C2C-policy negotiation.

         
    def is_c2c_negotiated(self):
        """ Terminates connection with a CETPClient that doesn't complete C2C negotiation in t<To) """        
        if (self.c2c_layer==None) and (self.is_connected):
            self._logger.info(" Remote end did not complete C2C negotiation in To={}".format(str(self.c2c_negotiation_threshold)))
            self.close()

    def set_c2c_details(self, r_cesid, c2c_layer):
        """ Inbound C2C-Manager calls this method to assign c2c-layer """
        self.r_cesid = r_cesid
        self.c2c_layer  = c2c_layer

    def send_cetp(self, msg):
        #self._logger.debug("Message to send: {!r}".format(msg))
        to_send = self.message_framing(msg)
        self.transport.write(to_send)

    def message_framing(self, msg):
        cetp_msg = msg.encode()
        msg_length = len(cetp_msg)
        len_bytes = (msg_length).to_bytes(CETP_MSG_LEN, byteorder="big")
        to_send = len_bytes + cetp_msg
        return to_send
        
    def data_received(self, data):
        self.buffer_and_parse_stream(data)
    
    def buffer_and_parse_stream(self, data):
        """ 
        1. Appends received data to a buffer;          2. Parses the stream into CETP messages, based on length field;
        3. invokes CETP process to handle message;     4. Removes processed data from the buffer.
        """
        self.data_buffer = self.data_buffer+data
        while True:
            if len(self.data_buffer) < CETP_MSG_LEN:
                break
            
            len_field = self.data_buffer[0:CETP_MSG_LEN]
            msg_length = int.from_bytes(len_field, byteorder='big')

            if len(self.data_buffer) >= (CETP_MSG_LEN + msg_length):
                cetp_data = self.data_buffer[CETP_MSG_LEN:CETP_MSG_LEN+msg_length]
                self.data_buffer = self.data_buffer[CETP_MSG_LEN+msg_length:]
                cetp_msg = cetp_data.decode()

                if self.c2c_layer is None:
                    self.c2c_mgr.process_inbound_message(cetp_msg, self)                # Forwards the message to inbound-C2Cmanager for C2C negotiation.
                else:
                    self.c2c_layer.enqueue_transport_message_nowait((cetp_msg, self))   # Forwarding the message to C2C layer, along with the transport for sending reply.
            else:
                break

            
    def connection_lost(self, ex):
        """ Called by asyncio framework """
        self._logger.info(" Remote endpoint closed the connection")
        if (self.c2c_layer != None) and self.is_connected:
            self.c2c_layer.report_connection_closure(self)
            self.is_connected = False

    def close(self):
        """ Closes the connection with the remote CES """
        self._logger.info(" Closing connection to remote endpoint")
        self.transport.close()
        if (self.c2c_layer != None) and self.is_connected:
            self.c2c_layer.report_connection_closure(self)
            self.is_connected = False


class iCESServerTransportTLS(asyncio.Protocol):
    def __init__(self, loop, ces_params, ces_certificate, ca_certificate, c2c_mgr = None, name="iCESServerTransportTLS"):
        self._loop           = loop
        self.ces_certificate = ces_certificate
        self.ca_certificate  = ca_certificate
        self.proto           = "tls"
        self.c2c_mgr         = c2c_mgr                  # Inbound c2c-Manager for handling a newly connected client.
        self.c2c_layer       = None                     # CES-to-CES layer assigned by inbound C2CManager on completion of C2C-negotiation
        self.r_cesid         = None
        self.is_connected    = False
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESServerTransportTLS)
        self.data_buffer     = b''
        self.c2c_negotiation_threshold = ces_params['max_c2c_negotiation_duration']              # In seconds
        
    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.peername))
        self.transport = transport
        ip_addr, port = self.peername
        self.is_connected   = True
        
        if self.c2c_mgr.remote_endpoint_malicious_history(ip_addr) == True:
            self._logger.info(" Remote endpoint has misbehavior history.")
            self.close()
        else:
            self._loop.call_later(self.c2c_negotiation_threshold, self.is_c2c_negotiated)     # Schedules a check for C2C-policy negotiation.


    def is_c2c_negotiated(self):
        """ Terminates connection with a CETPClient that doesn't complete C2C negotiation in t<To) """        
        if (self.c2c_layer==None) and (self.is_connected):
            self._logger.info(" Remote end did not complete C2C negotiation in To={}".format(str(self.c2c_negotiation_threshold)))
            self.close()

    def set_c2c_details(self, r_cesid, c2c_layer):
        """ Inbound C2C-Manager calls this method to assign c2c-layer """
        self.r_cesid = r_cesid
        self.c2c_layer  = c2c_layer

    def send_cetp(self, msg):
        #self._logger.debug("Message to send: {!r}".format(msg))
        to_send = self.message_framing(msg)
        self.transport.write(to_send)

    def message_framing(self, msg):
        cetp_msg = msg.encode()
        msg_length = len(cetp_msg)
        len_bytes = (msg_length).to_bytes(CETP_MSG_LEN, byteorder="big")
        to_send = len_bytes + cetp_msg
        return to_send


    def data_received(self, data):
        self.buffer_and_parse_stream(data)

    def buffer_and_parse_stream(self, data):
        """ 
        1. Appends received data to a buffer;          2. Parses the stream into CETP messages, based on length field;
        3. invokes CETP process to handle message;     4. Removes processed data from the buffer.
        """
        self.data_buffer = self.data_buffer+data
        while True:
            if len(self.data_buffer) < CETP_MSG_LEN:
                break
            
            len_field = self.data_buffer[0:CETP_MSG_LEN]
            msg_length = int.from_bytes(len_field, byteorder='big')

            if len(self.data_buffer) >= (CETP_MSG_LEN + msg_length):
                cetp_data = self.data_buffer[CETP_MSG_LEN:CETP_MSG_LEN+msg_length]
                self.data_buffer = self.data_buffer[CETP_MSG_LEN + msg_length:]
                cetp_msg  = cetp_data.decode()

                if self.c2c_layer is None:
                    self.c2c_mgr.process_inbound_message(cetp_msg, self)                # Forwards the message to inbound-C2Cmanager for C2C negotiation.
                else:
                    self.c2c_layer.enqueue_transport_message_nowait((cetp_msg, self))   # Forwarding the message to C2C layer, along with the transport for sending reply.
            else:
                break

    
    def connection_lost(self, ex):
        """ Called by asyncio framework """
        self._logger.info(" Remote endpoint closed the connection")
        if (self.c2c_layer != None) and self.is_connected:
            self.c2c_layer.report_connection_closure(self)
            self.is_connected = False

    def close(self):
        """ Closes the connection towards the remote CES """
        self._logger.info(" Closing connection to remote endpoint")
        self.transport.close()
        if (self.c2c_layer != None) and self.is_connected:
            self.c2c_layer.report_connection_closure(self)
            self.is_connected = False

