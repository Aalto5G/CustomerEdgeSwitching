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
        self._start_time                = self._loop.time()
        self.transport                  = None
        self.is_connected               = False
        self.c2c_negotiation            = False
        self.remotepeer                 = remote_addr
        self.data_buffer                = b''
        self.c2c_negotiation_threshold  = int(ces_params['transport_establishment_t0'])           # In seconds
        self._logger.setLevel(LOGLEVEL_oCESTCPTransport)
        self._loop.call_later(self.c2c_negotiation_threshold, self.is_c2c_negotiated)

    def connection_made(self, transport):
        try:
            current_time = self._loop.time()
            time_lapsed  = current_time - self._start_time
            self.transport = transport
            self.peername = transport.get_extra_info('peername')
            self.is_connected = True
            
            if (time_lapsed) > self.c2c_negotiation_threshold:
                self._logger.info(" Transport connection established in > (To={})".format(str(self.c2c_negotiation_threshold)))
                self.close()
            else:
                self._logger.info('Connected to {}'.format(self.peername))
                self.ces_layer.report_connectivity(self)                 # Reporting the connectivity to upper layer.
        except Exception as ex:
            self._logger.error( "Exception in connection_made() '{}'".format(ex))
            
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


class iCESServerTCPTransport(asyncio.Protocol):
    def __init__(self, loop, ces_params, cetp_mgr = None, name="iCESServerTransportTCP"):
        self._loop           = loop
        self.proto           = "tcp"
        self.cetp_mgr        = cetp_mgr                 # Inbound c2c-Manager for handling a newly connected client.
        self.c2c_layer       = None                     # CES-to-CES layer assigned by inbound C2CManager on completion of C2C-negotiation
        self.r_cesid         = None
        self.is_connected    = False
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESTCPServerTransport)
        self.data_buffer     = b''
        self.c2c_negotiation_threshold = int(ces_params['transport_establishment_t0'])              # In seconds
        print("1111")
        
    def connection_made(self, transport):
        print("1111")
        self.remotepeer = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.remotepeer))
        self.transport = transport
        ip_addr, port = self.remotepeer
        self.is_connected   = True
        
        if self.cetp_mgr.remote_endpoint_malicious_history(ip_addr) == True:
            self._logger.info(" Remote endpoint has misbehavior history.")
            self.close()
        else:
            self._loop.call_later(self.c2c_negotiation_threshold, self.is_c2c_negotiated)     # Schedules a check for C2C-policy negotiation.

         
    def is_c2c_negotiated(self):
        """ Terminates connection with a CETPH2H that doesn't complete C2C negotiation in t<To) """        
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
                self.data_buffer = self.data_buffer[CETP_LEN_FIELD+msg_length:]
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
            self.c2c_layer.report_connectivity(self, status=False)
            self.is_connected = False

    def close(self):
        """ Closes the connection with the remote CES """
        self._logger.info(" Closing connection to remote endpoint")
        self.transport.close()
        if (self.c2c_layer != None) and self.is_connected:
            self.c2c_layer.report_connectivity(self, status=False)
            self.is_connected = False


class iCESServerTLSTransport(asyncio.Protocol):
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
        self._logger.setLevel(LOGLEVEL_iCESTLSServerTransport)
        self.data_buffer     = b''
        self.c2c_negotiation_threshold = int(ces_params['transport_establishment_t0'])              # In seconds
        
    def connection_made(self, transport):
        self.remotepeer = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.remotepeer))
        self.transport = transport
        ip_addr, port = self.remotepeer
        self.is_connected   = True
        
        if self.cetp_mgr.remote_endpoint_malicious_history(ip_addr) == True:
            self._logger.info(" Remote endpoint has misbehavior history.")
            self.close()
        else:
            self._loop.call_later(self.c2c_negotiation_threshold, self.is_c2c_negotiated)     # Schedules a check for C2C-policy negotiation.


    def is_c2c_negotiated(self):
        """ Terminates connection with a CETPH2H that doesn't complete C2C negotiation in t<To) """        
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
            self.c2c_layer.report_connectivity(self, status=False)
            self.is_connected = False

    def close(self):
        """ Closes the connection towards the remote CES """
        self._logger.info(" Closing connection to remote endpoint")
        self.transport.close()
        if (self.c2c_layer != None) and self.is_connected:
            self.c2c_layer.report_connectivity(self, status=False)
            self.is_connected = False

