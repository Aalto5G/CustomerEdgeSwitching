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
        self.set_keepalive_params()
        self._logger.info('Connected to {}'.format(self.remotepeer))
        self.ces_layer.report_connectivity(self)                        # Reporting the connectivity to C2C layer.
        self.is_connected = True
        if self.proto == "tls":
            verified = self.verify_identity(self.r_cesid)
            if not verified:
                print("Failed to verify identity")
                self.close()
                
    def set_keepalive_params(self):
        self.socket = self.transport.get_extra_info('socket')
        after_idle_sec  = int(self.ces_params["keepalive_idle_t0"])
        interval_sec    = int(self.ces_params["keepalive_count"])
        max_fails       = int(self.ces_params["keepalive_interval"])

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)
        
    def verify_identity(self, r_cesid):
        ssl_obj = self.transport.get_extra_info('ssl_object')
        crt = ssl_obj.getpeercert()
        subject_ids = crt.get('subject', ())
        
        for sub in subject_ids:
            for k,v in sub:
                if k == 'commonName':
                    remote_id = v
                    if (remote_id==r_cesid) or (remote_id+'.'==r_cesid):
                        print(" Successful TLS connection to '{}'".format(self.r_cesid))
                        return True                    
        
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
        """Asyncio executed callback for received data. We append the received data to a buffer """
        self.data_buffer = self.data_buffer + data
        self._process_data(data)

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

    def _process_data(self, data):
        """ Invokes C2C method to handle the inbound message """
        while True:
            if len(self.data_buffer) < CETP_LEN_FIELD:
                break

            cetp_msg = self._extract_message()
            if cetp_msg!= None:
                self.ces_layer.consume_transport_message(cetp_msg, self)
            else:
                break
    
    def connection_lost(self, exc):
        if self.is_connected:                                # To prevent reporting the connection closure twice, at sending & receiving of FIN/ACK
            self._logger.info(" Remote CES '{}'closed the transport connection".format(self.r_cesid))
            self._clear_resources()
            if type(exc) == TimeoutError:
                print("Connection timedout")

    def close(self):
        """ Closes the connection towards remote CES """
        if self.is_connected:
            self._logger.info(" Closing the client CETP Transport towards '{}'".format(self.r_cesid))
            self._clear_resources()

    def _clear_resources(self):
        self.transport.close()
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
        self.ces_params      = ces_params
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESTCPServerTransport)
        self.data_buffer     = b''
        self.c2c_negotiation_t0 = int(ces_params['c2c_establishment_t0'])              # In seconds
        
    def connection_made(self, transport):
        self.transport = transport
        self.set_keepalive_params()
        self.remotepeer = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.remotepeer))
        ip_addr, port = self.remotepeer
        self.is_connected   = True
        
        if self.cetp_security.is_unverifiable_cetp_sender(ip_addr):
            self._logger.warning(" Remote address <{}> has misbehavior history.".format(ip_addr))
            self.close()
        else:
            self._loop.call_later(self.c2c_negotiation_t0, self.is_c2c_negotiated)     # Schedules a check for C2C-policy negotiation.

    def set_keepalive_params(self):
        self.socket = self.transport.get_extra_info('socket')
        after_idle_sec  = int(self.ces_params["keepalive_idle_t0"])
        interval_sec    = int(self.ces_params["keepalive_count"])
        max_fails       = int(self.ces_params["keepalive_interval"])

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)

         
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
        """Asyncio executed callback for received data. We append the received data to a buffer """
        self.data_buffer = self.data_buffer + data
        self._process_data(data)

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
    
    def _process_data(self, data):
        """ Invokes C2C method to handle the inbound message """
        while True:
            if len(self.data_buffer) < CETP_LEN_FIELD:
                break

            cetp_msg = self._extract_message()
            if cetp_msg!= None:
                self._to_c2c(cetp_msg)
            else:
                break
            
    def _to_c2c(self, cetp_msg):
        if self.c2c_layer is None:
            self.cetp_mgr.process_inbound_message(cetp_msg, self)      # Forwards the message to CETPManager for C2C negotiation.
        else:
            self.c2c_layer.consume_transport_message(cetp_msg, self)   # Forwarding the message to C2C layer
    
    def connection_lost(self, ex):
        """ Called by asyncio framework """
        if self.is_connected:
            self._logger.info(" Remote endpoint closed the connection")
            self._clean_resources()
            
            if type(ex) == TimeoutError:
                print("Connection timedout")


    def close(self):
        """ Closes the connection with the remote CES """
        if self.is_connected:
            self._logger.info(" Closing connection to remote endpoint")
            self._clean_resources()
            
    def _clean_resources(self):
        self.transport.close()
        self.is_connected = False
        if self.c2c_layer != None:
            self.c2c_layer.report_connectivity(self, status=False)
            
        


class iCESServerTLSTransport(iCESServerTCPTransport):
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
        self.ces_params      = ces_params
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESTLSServerTransport)
        self.data_buffer     = b''
        self.c2c_negotiation_t0 = int(ces_params['c2c_establishment_t0'])              # In seconds
        
    def connection_made(self, transport):
        self.transport = transport
        self.set_keepalive_params()
        self.remotepeer = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.remotepeer))
        ip_addr, port = self.remotepeer
        self.is_connected   = True
        
        if self.cetp_security.is_unverifiable_cetp_sender(ip_addr):
            self._logger.warning(" Remote endpoint has misbehavior history.")
            self.close()
        else:
            self._loop.call_later(self.c2c_negotiation_t0, self.is_c2c_negotiated)     # Schedules a check for C2C-policy negotiation.
        
        remote_id = self.get_remote_id()
        if remote_id is None:
            self.close()
            return
        else:
            self.r_cesid = remote_id
            self.cetp_mgr.report_connected_transport(self, self.r_cesid)                # What are possible return values, and how you handle them

    def set_keepalive_params(self):
        self.socket = self.transport.get_extra_info('socket')
        after_idle_sec  = int(self.ces_params["keepalive_idle_t0"])
        interval_sec    = int(self.ces_params["keepalive_count"])
        max_fails       = int(self.ces_params["keepalive_interval"])

        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)

    def get_remote_id(self):
        ssl_obj = self.transport.get_extra_info('ssl_object')
        crt = ssl_obj.getpeercert()
        subject_ids = crt.get('subject', ())
        
        for sub in subject_ids:
            for k,v in sub:
                if k == 'commonName':
                    remote_id = v+'.'
                    return remote_id
        return None



class MockC2C:
    def report_connectivity(self, t, status=True):
        print("Conn status: ", status)
        
    def consume_transport_message(self, cetp_msg, t):
        print("Message size:", len(cetp_msg))
        print(cetp_msg)

@asyncio.coroutine
def test_connection(loop):
    ip_addr, port = "10.0.2.15", 5000
    remote_addr=(ip_addr, port)
    c2c_layer = MockC2C()
    print("Initiating CETPTransport towards ".format(remote_addr))
    ces_params={}
    ces_params["c2c_establishment_t0"] = 2
    ces_params["keepalive_idle_t0"] = 10
    ces_params["keepalive_count"] = 3
    ces_params["keepalive_interval"] = 2
    #CETPC2C.CETPC2CLayer
        
    try:
        t = oCESTCPTransport(c2c_layer, "tcp", "cesb.lte.", ces_params, remote_addr=remote_addr, loop=loop)
        coro = loop.create_connection(lambda: t, ip_addr, port)
        connect_task = asyncio.ensure_future(coro)
        timeout = 2
        yield from asyncio.wait_for(connect_task, timeout)
        
    except Exception as ex:
        print("Exception '{}' towards r_cesid".format(ex))

@asyncio.coroutine
def test_unreachable_ep(loop):
    try:
        import os
        port_n = 5000
        ip_addr = "10.0.2.15"
        ipt_cmd = "sudo iptables -A INPUT -p tcp --dport {} -j DROP".format(port_n)
        os.popen(ipt_cmd)
        yield from asyncio.sleep(0.2)
        yield from test_connection(loop)
        
    except:
        print("Exception in test_unreachable_ep() ")
    finally:
        ipt_cmd = "sudo iptables -D INPUT -p tcp --dport {} -j DROP".format(port_n)
        os.popen(ipt_cmd)

def test_msg_framing(loop):
    ip_addr, port = "10.0.2.15", 5000
    remote_addr=(ip_addr, port)
    c2c_layer = MockC2C()
    print("Initiating CETPTransport towards ".format(remote_addr))
    ces_params={}
    ces_params["c2c_establishment_t0"] = 2
    
    msg="Take5 CETPv2"
    t = oCESTCPTransport(c2c_layer, "tcp", "cesb.lte.", ces_params, remote_addr=remote_addr, loop=loop)
    to_send = t.message_framing(msg)
    t.process_received_data(to_send)
    print("Message size:", len(msg))

@asyncio.coroutine
def test_keepalive_t0(loop):
    try:
        import os
        yield from test_connection(loop)
        port_n = 5000
        ip_addr = "10.0.2.15"
        ipt_cmd = "sudo iptables -A INPUT -p tcp --dport {} -j DROP".format(port_n)
        os.popen(ipt_cmd)
        
    except:
        print("Exception in test_unreachable_ep() ")
    finally:
        yield from asyncio.sleep(20)
        ipt_cmd = "sudo iptables -D INPUT -p tcp --dport {} -j DROP".format(port_n)
        os.popen(ipt_cmd)

def test_function(loop):
    asyncio.ensure_future(test_connection(loop))
    #asyncio.ensure_future(test_unreachable_ep(loop))
    #asyncio.ensure_future(test_keepalive_t0(loop))
    #test_msg_framing(loop)
    
if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.get_event_loop()
    test_function(loop)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Ctrl+C Handled")
    finally:
        loop.close()
