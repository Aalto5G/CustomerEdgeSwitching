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

class CETPTransport(asyncio.Protocol):
    
    def _set_keepalives(self):
        self.socket     = self.transport.get_extra_info('socket')
        after_idle_sec  = int(self.ces_params["keepalive_idle_t0"])
        interval_sec    = int(self.ces_params["keepalive_interval"])
        max_fails       = int(self.ces_params["keepalive_count"])

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)
        
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
        """Asyncio executed callback for received data. We append the received data to a buffer """
        self.data_buffer = self.data_buffer + data
        self._process_data()

    def _extract_message(self):
        """
        1. Parses the data buffer into CETP messages, based on length field.
        2. Removes the processed data from the buffer.
        """
        cetp_msg = None
        len_field = self.data_buffer[0:CETP_LEN_FIELD]                                      # Reading length field in buffered data
        msg_length = int.from_bytes(len_field, byteorder='big')
        
        if len(self.data_buffer) >= (CETP_LEN_FIELD + msg_length):
            cetp_data = self.data_buffer[CETP_LEN_FIELD:CETP_LEN_FIELD+msg_length]
            self.data_buffer = self.data_buffer[CETP_LEN_FIELD+msg_length:]                 # Moving ahead in the buffered data
            cetp_msg = cetp_data.decode()
            
        return cetp_msg

    def _process_data(self):
        """ Invokes C2C method to handle the inbound message """
        while True:
            if len(self.data_buffer) < CETP_LEN_FIELD:
                break

            cetp_msg = self._extract_message()
            if cetp_msg!= None:
                self._to_c2c(cetp_msg)
            else:
                break


    def connection_lost(self, ex):
        """ Called by asyncio framework """
        if self.is_connected:
            self._logger.debug(" Transport connection to remote CES '{}' is closed (or lost)".format(self.r_cesid))
            self._cleanup()
            
            if type(ex) == TimeoutError:
                self._logger.info(" Connection timedout")

    def close(self):
        """ Closes the connection towards remote CES """
        if self.is_connected:
            self._logger.debug(" Closing the client CETP Transport towards '{}'".format(self.r_cesid))
            self._cleanup()
    
    def _cleanup(self):
        self.transport.close()
        self.is_connected = False
        if self.c2c_layer != None:
            self.c2c_layer.report_connectivity(self, status=False)
            del(self.c2c_layer)

    def get_remote_cesid(self):
        if hasattr(self, "r_cesid"):
            return self.r_cesid


class oCESTCPTransport(CETPTransport):
    def __init__(self, c2c_layer, proto, r_cesid, ces_params, remote_addr=None, loop=None, name="oCESTransport"):
        self.c2c_layer                  = c2c_layer
        self.proto                      = proto
        self.r_cesid                    = r_cesid
        self.ces_params                 = ces_params
        self._loop                      = loop
        self.transport                  = None
        self.is_connected               = False
        self.c2c_negotiated             = False
        self.remotepeer                 = remote_addr
        self.data_buffer                = b''
        self.c2c_establishment_t0       = int(ces_params['c2c_establishment_t0'])           # In seconds
        self.name                       = name+proto
        self._logger                    = logging.getLogger(self.name)
        self._logger.setLevel(LOGLEVEL_oCESTCPTransport)

    def connection_made(self, transport):
        self.transport = transport
        self._logger.info('Connected to {}'.format(self.remotepeer))
                
        if self.proto == "tls":
            if not self.verify_identity(self.r_cesid):
                self._logger.info(" SSL certificate failed to verify sender identity {}.".format(self.r_cesid))
                self._cleanup()
                return
        
        self.is_connected = True
        self._set_keepalives()
        self.c2c_layer.report_connectivity(self)                        # Reporting the connectivity to C2C layer.
            
    def get_remotepeer(self):
        if self.transport is not None:
            return self.remotepeer
    
    def verify_identity(self, r_cesid):
        ssl_obj = self.transport.get_extra_info('ssl_object')
        crt = ssl_obj.getpeercert()
        subject_ids = crt.get('subject', ())
        
        for sub in subject_ids:
            for k,v in sub:
                if k == 'commonName':
                    remote_id = v
                    if (remote_id==r_cesid) or (remote_id+'.'==r_cesid):
                        self._logger.debug(" Successful TLS connection to '{}'".format(self.r_cesid))
                        return True
        
    def report_c2c_negotiation(self, status):
        """ Method used by C2CLayer to report success of C2C-Negotiation """
        self.c2c_negotiated = status

    def _to_c2c(self, cetp_msg):
        self.c2c_layer.consume_transport_message(cetp_msg, self)



class iCESServerTCPTransport(CETPTransport):
    def __init__(self, loop, ces_params, cetp_mgr = None, name="iCESServerTransportTCP"):
        self._loop           = loop
        self.proto           = "tcp"
        self.cetp_mgr        = cetp_mgr                 # CETPManager for handling a newly connected client.
        self.cetp_security   = cetp_mgr.cetp_security        
        self.c2c_layer       = None                     # C2C-layer assigned by CETPManager on completion of C2C-negotiation
        self.r_cesid         = None
        self.is_connected    = False
        self.ces_params      = ces_params
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESTCPServerTransport)
        self.data_buffer     = b''
        self.c2c_negotiation_t0 = int(ces_params['c2c_establishment_t0'])              # In seconds
        self.negotiation_pkts= 0

    def connection_made(self, transport):
        self.transport  = transport
        self.remotepeer = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.remotepeer))
        ip_addr, port = self.remotepeer
        
        if self.cetp_security.is_unverifiable_cetp_sender(ip_addr):
            self._logger.warning(" Remote address <{}> has misbehavior history.".format(ip_addr))
            self.transport.close()
            return
        
        self.is_connected   = True
        self._set_keepalives()
        self._cb = self._loop.call_later(self.c2c_negotiation_t0, self.is_c2c_negotiated)     # Schedules a check for C2C-policy negotiation.

    def get_remotepeer(self):
        if self.transport is not None:
            return self.remotepeer
         
    def is_c2c_negotiated(self):
        """ Terminates transport connection if C2C negotiation doesn't complete in t<To """        
        if self.is_connected and (self.c2c_layer is None):
            self._logger.info(" Remote end did not complete C2C negotiation in due time ={} or RTTs.".format(str(self.c2c_negotiation_t0)))
            ip_addr, port = self.remotepeer
            self.cetp_security.register_unverifiable_cetp_sender(ip_addr)
            self.close()

    def set_c2c_details(self, r_cesid, c2c_layer):
        """ CETPManager uses this method to assign C2C-layer to transport """
        self.r_cesid    = r_cesid
        self.c2c_layer  = c2c_layer
    
    def _check_flooding(self):
        if self.negotiation_pkts > 2:
            return True
        else:
            return False

    def _to_c2c(self, cetp_msg):
        if self.c2c_layer is None:
            
            if not self._check_flooding():
                self.negotiation_pkts += 1
                self.cetp_mgr.process_inbound_message(cetp_msg, self)      # Forwards the message to CETPManager for C2C negotiation.
            else:
                self._logger.warning(" Flood of inbound messages on a newly connected transport '{}' of cesid = '{}'".format(self.remotepeer[0], self.r_cesid))
                self._cb.cancel()
                self.is_c2c_negotiated()
        else:
            self.c2c_layer.consume_transport_message(cetp_msg, self)   # Forwarding the message to C2C layer
    
            
class iCESServerTLSTransport(iCESServerTCPTransport):
        
    def connection_made(self, transport):
        self.proto      = "tls"
        self.transport  = transport
        self.remotepeer = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.remotepeer))
        ip_addr, port = self.remotepeer
        
        if self.cetp_security.is_unverifiable_cetp_sender(ip_addr):
            self._logger.warning(" Remote IP <{}> has misbehavior history.".format(ip_addr))
            self.transport.close()
            return
        
        remote_id = self._get_remote_id()
        if remote_id is None:
            self.transport.close()
            return
        
        self.r_cesid        = remote_id
        self._set_keepalives()
        self.is_connected   = True
        self._loop.call_later(self.c2c_negotiation_t0, self.is_c2c_negotiated)      # Schedules a check for C2C-policy negotiation.
        self.cetp_mgr.report_connected_transport(self, self.r_cesid)


    def _get_remote_id(self):
        ssl_obj = self.transport.get_extra_info('ssl_object')
        crt = ssl_obj.getpeercert()
        subject_ids = crt.get('subject', ())
        
        for sub in subject_ids:
            for k,v in sub:
                if k == 'commonName':
                    remote_id = v+'.'
                    return remote_id
        return None
