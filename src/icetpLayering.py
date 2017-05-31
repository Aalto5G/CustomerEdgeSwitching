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
import ocetpLayering
import PolicyManager

LOGLEVEL_CETPServer                 = logging.INFO
LOGLEVEL_iCETPC2CLayer              = logging.INFO
LOGLEVEL_iCETPT2TManager            = logging.INFO
LOGLEVEL_iCESServerTransportTCP     = logging.INFO
LOGLEVEL_iCESServerTransportTLS     = logging.INFO


class iCETPC2CLayer:
    def __init__(self, loop, r_cesid="", cetp_mgr=None, name="iCETPC2CLayer"):
        self._loop                  = loop
        self.q                      = asyncio.Queue()               # Enqueues the messages from CETP Transport
        self.connected_transports   = []                            # To manage the connected CETP Transports
        self.c2c_transaction_list   = []
        self.pending_tasks          = []                            # iCETPC2CLayer specific
        self.r_cesid                = r_cesid
        self.cetp_mgr               = cetp_mgr
        self.transport_c2c_binding  = {}
        self.transport_rtt          = {}        
        self._closure_signal        = False
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCETPC2CLayer)

    def register_transport_c2cTransaction(self, transport, c2c_transaction):
        """ Registers the stateful-inbound c2c-transaction, connected transport, AND their relation """
        self.transport_c2c_binding[transport] = c2c_transaction
        self.add_c2c_transactions(c2c_transaction)
        self.add_connected_transport(transport)

    def add_c2c_transactions(self, c2c_cetp_transaction):
        self.c2c_transaction_list.append(c2c_cetp_transaction)
    
    def remove_c2c_transactions(self, c2c_cetp_transaction):
        self.c2c_transaction_list.remove(c2c_cetp_transaction)

    def add_connected_transport(self, transport):
        self.connected_transports.append(transport)
        
    def remove_connected_transport(self, transport):
        if transport in self.connected_transports:
            self.connected_transports.remove(transport)
            
    def create_cetp_server(self, r_cesid, policy_mgr, cetpstate_mgr, l_cesid, ces_params, cetp_security, host_reg):
        """ Creating the upper layer to handle CETPTransport """
        self.cetp_server = ocetpLayering.CETPH2H(c2c_layer=self, l_cesid=l_cesid, r_cesid=r_cesid, policy_mgr=policy_mgr, cetpstate_mgr=cetpstate_mgr, c2c_negotiated=True, \
                                                 host_register=host_reg, loop=self._loop, cetp_mgr=self.cetp_mgr, ces_params=ces_params, cetp_security=cetp_security)
        
        self.cetp_mgr.add_client_endpoint(r_cesid, self.cetp_server)
        t1=asyncio.ensure_future(self.cetp_server.consume_h2h_requests())                       # Task for consuming DNS NAPTR-responses triggered by private hosts
        self.pending_tasks.append(t1)
        return self.cetp_server
    
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
        
    def add_naptr_records(self, naptr_rrs):
        try:
            for naptr_rr in naptr_rrs:
                dst_id, r_cesid, r_ip, r_port, r_transport = naptr_rr                   # Assumption: All NAPTRs point towards one 'r_cesid'.    (Destination domain is reachable via one CES only)
                """
                if (r_ip, r_port, r_transport) not in self.remote_ces_eps:
                    self._logger.info(" Initiating a new CETPTransport")
                    if not self.remote_endpoint_malicious_history(r_cesid, r_ip):
                        asyncio.ensure_future(self.initiate_transport(r_transport, r_ip, r_port))
                """
            return dst_id
        except Exception as ex:
            self._logger.warning("Exception in parsing the NAPTR records: '{}'".format(ex))
            return None

    
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
            self.cetp_mgr.delete_c2c_layer(self.r_cesid)                   # Remove the c2c-layer registered to 'r_cesid'
            self.cancel_pending_tasks()
                
            self._logger.info("Terminating inbound C2C-Layer and CETPServer for cesid '{}'".format(self.r_cesid))
            del(self.cetp_server)                                               # CETPServer's task is already deleted
            del(self)
                
    def report_rtt(self, transport, rtt=None, last_seen=None):
        if rtt != None:
            self.transport_rtt[transport] = rtt
            rtt_list = []
            for trans, rtt_value in self.transport_rtt.items():
                rtt_list.append(rtt_value)
            
            rtt_list.sort()
            smallest_rtt = rtt_list[0]
            #self.last_rtt_evaluation = time.time()
            #self.smallest_rtt = smallest_rtt
            if smallest_rtt == 2**32:
                return
            
            for trans, rtt_value in self.transport_rtt.items():
                if rtt_value==smallest_rtt:
                    self.active_transport = trans
                    return
        else:
            self.transport_lastseen[transport] = last_seen
        

    def select_transport(self):
        """ Selects the outgoing CETP-transport based on: 
            (A) good health indicator - measured by timely arrival of C2C-keepalive response. (B) Lowest-RTT (measured by timing the C2C-keepalive)              
            Other possibilities: Selection based on: 1) load balancing b/w transports; OR 2) priority field in the inbound NAPTR
        """
        if len(self.transport_rtt) < len(self.connected_transports):
            # Packet sending before first keepalive & when local CES doesn't have to send keepalive
            for transport in self.connected_transports:
                oc2c = self.get_c2c_transaction(transport)
                if oc2c.health_report:
                    return transport
                # TBD:  Case where all transports have bad health           # How to detect? and What to do?

        elif len(self.transport_rtt) == len(self.connected_transports):
            return self.active_transport
    
    def send_cetp(self, msg):
        """ Useful when initiating a (feedback/evidence/keepalive) message towards oCES """
        for transport in self.connected_transports:
            transport.send_cetp(msg)

    def consume_transport_message(self, msg, transport):
        try:
            if not self._pre_process(msg):
                return
                
            #self._logger.debug("data: {!r}".format(msg))
            #self._logger.debug("cetp_msg: {!r}".format(cetp_msg))
            cetp_msg = json.loads(msg)
            inbound_sst, inbound_dst = cetp_msg['SST'], cetp_msg['DST']
            sst, dst = inbound_dst, inbound_sst
            
            c2c_transaction = self.transport_c2c_binding[transport]
            c2c_transaction.update_last_seen()


            if self.is_c2c_transaction(sst, dst):
                self._logger.debug(" Inbound packet belongs to an established C2C transaction.")
                self.process_c2c(cetp_msg, transport)
            else:
                self._logger.debug(" Forward the packet to H2H-layer")
                self.forward_h2h(cetp_msg, transport)
        
        except Exception as ex:
            self._logger.info(" Exception in consuming Transport message: {}".format(ex))

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

    
    def is_c2c_transaction(self, sst, dst):
        """ Checks if (SST, DST) of the inbound CETP-message belongs to a C2C-transaction """
        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if (c_sst == sst) & (c_dst == dst):
                return True
        return False

    def forward_h2h(self, cetp_msg, transport):
        self.cetp_server.consume_message_from_c2c(cetp_msg, transport)
            
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
    def __init__(self, loop, ces_params, cetp_mgr = None, name="iCESServerTransportTCP"):
        self._loop           = loop
        self.proto           = "tcp"
        self.cetp_mgr        = cetp_mgr                 # Inbound c2c-Manager for handling a newly connected client.
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
        
        if self.cetp_mgr.remote_endpoint_malicious_history(ip_addr) == True:
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
                    self.cetp_mgr.process_inbound_message(cetp_msg, self)                # Forwards the message to inbound-C2Cmanager for C2C negotiation.
                else:
                    self.c2c_layer.consume_transport_message(cetp_msg, self)   # Forwarding the message to C2C layer, along with the transport for sending reply.
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
    def __init__(self, loop, ces_params, ces_certificate, ca_certificate, cetp_mgr = None, name="iCESServerTransportTLS"):
        self._loop           = loop
        self.ces_certificate = ces_certificate
        self.ca_certificate  = ca_certificate
        self.proto           = "tls"
        self.cetp_mgr        = cetp_mgr                 # Inbound c2c-Manager for handling a newly connected client.
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
        
        if self.cetp_mgr.remote_endpoint_malicious_history(ip_addr) == True:
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
                    self.cetp_mgr.process_inbound_message(cetp_msg, self)                # Forwards the message to inbound-C2Cmanager for C2C negotiation.
                else:
                    self.c2c_layer.consume_transport_message(cetp_msg, self)   # Forwarding the message to C2C layer, along with the transport for sending reply.
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

