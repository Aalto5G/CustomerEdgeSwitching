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
import PolicyManager
import CETPH2H
import CETPC2C
import asyncio

CETP_LEN_FIELD = 2
LOGLEVEL_oCESTCPTransport           = logging.INFO
LOGLEVEL_iCESTLSServerTransport     = logging.INFO
LOGLEVEL_iCESTCPServerTransport     = logging.INFO

class oCESTCPTransport(asyncio.Protocol):
    def __init__(self, c2c_layer, proto, r_cesid, ces_params, remote_addr=None, loop=None, name="oCESTransport"):
        self.ces_layer                  = c2c_layer
        self.proto                      = proto
        self.r_cesid                    = r_cesid
        self.ces_params                 = ces_params
        self._loop                      = loop
        self.name                       = name+proto
        self._logger                    = logging.getLogger(name)
        self.transport                  = None
        self.is_connected               = False
        self.c2c_negotiated             = False
        self.remotepeer                 = remote_addr
        self.data_buffer                = b''
        self.c2c_establishment_t0       = int(ces_params['c2c_establishment_t0'])           # In seconds
        self._logger.setLevel(LOGLEVEL_oCESTCPTransport)

    def connection_made(self, transport):
        self.transport = transport
        self._logger.info('Connected to {}'.format(self.remotepeer))
        self.ces_layer.report_connectivity(self)                        # Reporting the connectivity to C2C layer.
        self.is_connected = True
        
    def report_c2c_negotiation(self, status):
        """ Method used by C2CLayer to report success of C2C-Negotiation """
        self.c2c_negotiated = status

    def send_cetp(self, msg):
        #self._logger.debug("Message to send: {!r}".format(msg))
        to_send = self.message_framing(msg)
        self.transport.write(to_send)

    def message_framing(self, msg):
        """ Appends length field to the message """
        cetp_msg = msg.encode()
        msg_length = len(cetp_msg)
        len_bytes = (msg_length).to_bytes(CETP_LEN_FIELD, byteorder="big")
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
            if len(self.data_buffer) < CETP_LEN_FIELD:
                break
            
            len_field = self.data_buffer[0:CETP_LEN_FIELD]                                      # Reading length field in buffered data
            msg_length = int.from_bytes(len_field, byteorder='big')
                        
            if len(self.data_buffer) >= (CETP_LEN_FIELD + msg_length):
                cetp_data = self.data_buffer[CETP_LEN_FIELD:CETP_LEN_FIELD+msg_length]
                self.data_buffer = self.data_buffer[CETP_LEN_FIELD+msg_length:]                 # Moving ahead in the buffered data
                cetp_msg = cetp_data.decode()
                self.ces_layer.consume_transport_message(cetp_msg, self)
            else:
                break
    
    def connection_lost(self, exc):
        if self.is_connected:                                # Prevents reporting the connection closure twice, at sending & receiving of FIN/ACK
            self._logger.info(" Remote CES '{}'closed the transport connection".format(self.r_cesid))
            self.ces_layer.report_connectivity(self, status=False)
            self.is_connected=False
        # process exc

    def close(self):
        """ Closes the connection towards remote CES """
        self._logger.info(" Closing the client CETP Transport towards '{}'".format(self.r_cesid))
        self.transport.close()
        if self.is_connected:
            self.ces_layer.report_connectivity(self, status=False)
            self.is_connected=False


class iCESServerTCPTransport(asyncio.Protocol):
    def __init__(self, loop, ces_params, cetp_mgr = None, name="iCESServerTransportTCP"):
        self._loop           = loop
        self.proto           = "tcp"
        self.cetp_mgr        = cetp_mgr                 # CETPManager for handling a newly connected client.
        self.cetp_security   = cetp_mgr.cetp_security        
        self.c2c_layer       = None                     # C2C-layer assigned by CETPManager on completion of C2C-negotiation
        self.r_cesid         = None
        self.is_connected    = False
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESTCPServerTransport)
        self.data_buffer     = b''
        self.c2c_negotiation_t0 = 10 #int(ces_params['c2c_establishment_t0'])              # In seconds
        
    def connection_made(self, transport):
        self.transport = transport
        self.remotepeer = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.remotepeer))
        ip_addr, port = self.remotepeer
        self.is_connected   = True
        
        if self.cetp_security.is_unverifiable_cetp_sender(ip_addr):
            self._logger.warning(" Remote address <{}> has misbehavior history.".format(ip_addr))
            self.close()
        else:
            self._loop.call_later(self.c2c_negotiation_t0, self.is_c2c_negotiated)     # Schedules a check for C2C-policy negotiation.

         
    def is_c2c_negotiated(self):
        """ Terminates transport connection if C2C negotiation doesn't complete in t<To """        
        if self.is_connected and (self.c2c_layer==None):
            self._logger.info(" Remote end did not complete C2C negotiation in To={}".format(str(self.c2c_negotiation_t0)))
            ip_addr, port = self.remotepeer
            self.cetp_security.register_unverifiable_cetp_sender(ip_addr)
            self.close()

    def set_c2c_details(self, r_cesid, c2c_layer):
        """ CETPManager uses this method to assign C2C-layer to transport """
        self.r_cesid    = r_cesid
        self.c2c_layer  = c2c_layer

    def send_cetp(self, msg):
        #self._logger.debug("Message to send: {!r}".format(msg))
        to_send = self.message_framing(msg)
        self.transport.write(to_send)

    def message_framing(self, msg):
        cetp_msg = msg.encode()
        msg_length = len(cetp_msg)
        len_bytes = (msg_length).to_bytes(CETP_LEN_FIELD, byteorder="big")
        to_send = len_bytes + cetp_msg
        return to_send
        
    def data_received(self, data):
        self.buffer_and_parse_stream(data)
    
    def buffer_and_parse_stream(self, data):
        """ 
        1. Appends received data to a buffer;          2. Parses the stream into CETP messages, based on length field;
        3. invokes CETP process to handle message;     4. Removes processed data from the buffer.
        """
        try:
            self.data_buffer = self.data_buffer+data
            while True:
                if len(self.data_buffer) < CETP_LEN_FIELD:
                    break
                
                len_field = self.data_buffer[0:CETP_LEN_FIELD]
                msg_length = int.from_bytes(len_field, byteorder='big')
    
                if len(self.data_buffer) >= (CETP_LEN_FIELD+ msg_length):
                    cetp_data = self.data_buffer[CETP_LEN_FIELD:CETP_LEN_FIELD+msg_length]
                    self.data_buffer = self.data_buffer[CETP_LEN_FIELD+msg_length:]
                    cetp_msg = cetp_data.decode()
                    self.forward_to_CETP_c2c(cetp_msg)
                else:
                    break
        except Exception as ex:
            self._logger.info("Exception in received data: {}".format(ex))
            self.close()


    def forward_to_CETP_c2c(self, cetp_msg):
        if self.c2c_layer is None:
            self.cetp_mgr.process_inbound_message(cetp_msg, self)      # Forwards the message to CETPManager for C2C negotiation.
        else:
            self.c2c_layer.consume_transport_message(cetp_msg, self)   # Forwarding the message to C2C layer
    
    def connection_lost(self, ex):
        """ Called by asyncio framework """
        if self.is_connected:
            self._logger.info(" Remote endpoint closed the connection")
            self.clean_resources()

    def close(self):
        """ Closes the connection with the remote CES """
        if self.is_connected:
            self._logger.info(" Closing connection to remote endpoint")
            self.clean_resources()
            
    def clean_resources(self):
        self.transport.close()
        self.is_connected = False
        if self.c2c_layer != None:
            self.c2c_layer.report_connectivity(self, status=False)
            
        


class iCESServerTLSTransport(asyncio.Protocol):
    def __init__(self, loop, ces_params, ces_certificate, ca_certificate, cetp_mgr = None, name="iCESServerTransportTLS"):
        self._loop           = loop
        self.ces_certificate = ces_certificate
        self.ca_certificate  = ca_certificate
        self.proto           = "tls"
        self.cetp_mgr        = cetp_mgr                 # CETPManager for handling a newly connected client.
        self.cetp_security   = cetp_mgr.cetp_security
        self.c2c_layer       = None                     # C2C-layer assigned by CETPManager on completion of C2C-negotiation
        self.r_cesid         = None
        self.is_connected    = False
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESTLSServerTransport)
        self.data_buffer     = b''
        self.c2c_negotiation_t0 = int(ces_params['c2c_establishment_t0'])              # In seconds
        
    def connection_made(self, transport):
        self.transport = transport
        self.remotepeer = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.remotepeer))
        ip_addr, port = self.remotepeer
        self.is_connected   = True
        
        if self.cetp_security.is_unverifiable_cetp_sender(ip_addr):
            self._logger.warning(" Remote endpoint has misbehavior history.")
            self.close()
        else:
            self._loop.call_later(self.c2c_negotiation_t0, self.is_c2c_negotiated)     # Schedules a check for C2C-policy negotiation.


    def is_c2c_negotiated(self):
        """ Terminates transport connection if C2C negotiation doesn't complete in t<To """        
        if (self.c2c_layer==None) and (self.is_connected):
            self._logger.info(" Remote end did not complete C2C negotiation in To={}".format(str(self.c2c_negotiation_t0)))
            ip_addr, port = self.remotepeer
            self.cetp_security.register_unverifiable_cetp_sender(ip_addr)
            self.close()

    def set_c2c_details(self, r_cesid, c2c_layer):
        """ CETPManager uses this method to assign c2c-layer """
        self.r_cesid    = r_cesid
        self.c2c_layer  = c2c_layer

    def send_cetp(self, msg):
        #self._logger.debug("Message to send: {!r}".format(msg))
        to_send = self.message_framing(msg)
        self.transport.write(to_send)

    def message_framing(self, msg):
        cetp_msg = msg.encode()
        msg_length = len(cetp_msg)
        len_bytes = (msg_length).to_bytes(CETP_LEN_FIELD, byteorder="big")
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
            if len(self.data_buffer) < CETP_LEN_FIELD:
                break
            
            len_field = self.data_buffer[0:CETP_LEN_FIELD]
            msg_length = int.from_bytes(len_field, byteorder='big')

            if len(self.data_buffer) >= (CETP_LEN_FIELD+ msg_length):
                cetp_data = self.data_buffer[CETP_LEN_FIELD:CETP_LEN_FIELD+msg_length]
                self.data_buffer = self.data_buffer[CETP_LEN_FIELD+ msg_length:]
                cetp_msg  = cetp_data.decode()
                self.forward_to_CETP_c2c(cetp_msg)
            else:
                break


    def forward_to_CETP_c2c(self, cetp_msg):
        if self.c2c_layer is None:
            self.cetp_mgr.process_inbound_message(cetp_msg, self)      # Forwards the message to CETPManager for C2C negotiation.
        else:
            self.c2c_layer.consume_transport_message(cetp_msg, self)   # Forwarding the message to C2C layer

    def connection_lost(self, ex):
        """ Called by asyncio framework """
        if self.is_connected:
            self._logger.info(" Remote endpoint closed the connection")
            self.clean_resources()

    def close(self):
        """ Closes the connection with the remote CES """
        if self.is_connected:
            self._logger.info(" Closing connection to remote endpoint")
            self.clean_resources()
            
    def clean_resources(self):
        self.transport.close()
        self.is_connected = False
        if self.c2c_layer != None:
            self.c2c_layer.report_connectivity(self, status=False)



@asyncio.coroutine
def test1(loop):
    print(" Initiating CETPTransport towards cesid")
    transport_instance = oCESTCPTransport(None, "tcp", None, None, remote_addr=("10.0.3.103", 49001), loop=loop)
    
    try:
        coro = loop.create_connection(lambda: transport_instance, ip_addr, port)
        connect_task = asyncio.ensure_future(coro)
        yield from connect_task
        
    except Exception as ex:
        print("Exception handled towards r_cesid")

def test_function(loop):
    asyncio.ensure_future(test1(loop))

if __name__=="__main__":
    logging.basicConfig(level=logging.DEBUG)
    loop = asyncio.get_event_loop()
    test_function(loop)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Ctrl+C Handled")
    finally:
        loop.close()
