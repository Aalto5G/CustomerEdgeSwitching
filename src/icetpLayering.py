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


LOGLEVEL_CETPServer                 = logging.INFO
LOGLEVEL_iCETPC2CLayer              = logging.INFO
LOGLEVEL_iCETPT2TManager            = logging.INFO
LOGLEVEL_iCESServerTransportTCP     = logging.INFO


class CETPServer:
    def __init__(self, c2c_layer=None, r_cesid=None, loop=None, policy_mgr=None, cetpstate_mgr=None, l_cesid=None, name="CETPServer"):
        self.c2c_q              = asyncio.Queue()
        self.c2c                = c2c_layer
        self.r_cesid            = r_cesid
        self._loop              = loop
        self.policy_mgr         = policy_mgr
        self.cetpstate_mgr      = cetpstate_mgr
        self.l_cesid            = l_cesid
        
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPServer)
        self._logger.info("CETPServer created for cesid {}".format(l_cesid))

    def send(self, msg):
        self.c2c.send_cetp(msg)
        #print("c2cLayer sends message: ", msg)
 
    def enqueue_c2c_message_nowait(self, msg):
        self.c2c_q.put_nowait(msg)                      # Enqueues the CETP message from oCES, forwarded by CETPTransport layer

    @asyncio.coroutine
    def enqueue_c2c_message(self, msg):
        yield from self.c2c_q.put(msg)                  # Enqueues the CETP message from oCES, forwarded by CETPTransport layer

    @asyncio.coroutine
    def consume_c2c_message(self):
        while True:
            msg = yield from self.c2c_q.get()           # Retrieves the CETP message from oCES
            self._logger.info(" receives a message")
            asyncio.ensure_future(self.process_h2h_transaction(msg))
            self.c2c_q.task_done()

    @asyncio.coroutine
    def process_h2h_transaction(self, msg):
        cetp_msg = json.loads(msg)
        inbound_sst, inbound_dst = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dst, inbound_sst                  # Storage view: (local_sst, local_dst) on sending -->  Thus we must flip the inbound (SST, DST), as SST of the remote-CES is DST of the local-CES. 
        yield from asyncio.sleep(0.01)                              # Simulating the delay upon interaction with the policy management system
        
        if inbound_sst == 0:
            self._logger.error("Inbound SST shall not be zero")     # As this would mean that sender has not choosen any SST, and upon negotiation completion cetp-session state would be (0, DST)
            return
            
        if self.cetpstate_mgr.has((sstag, dstag)):
            oh2h = self.cetpstate_mgr.get((sstag, dstag))
            self._logger.info("Outbound H2HTransaction found for (SST={}, DST={})".format(inbound_sst, inbound_dst))
            cetp_resp = oh2h.post_cetp_negotiation(cetp_msg)
            if cetp_resp != None:    
                self.send(cetp_resp)
        
        elif inbound_dst == 0:
            self._logger.info("No prior Outbound H2H-transaction found... Initiating H2HTransactionInbound with (SST={}, DST={})".format(inbound_sst, inbound_dst))
            i_h2h = cetpTransaction_v2.H2HTransactionInbound(cetp_msg, sstag=sstag, dstag=sstag, l_cesid=self.l_cesid, r_cesid=self.r_cesid, \
                                                             policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr)
            cetp_resp = i_h2h.start_cetp_processing(cetp_msg)
            if cetp_resp != None:    
                self.send(cetp_resp)
            
        
        



class iCETPC2CLayer:
    def __init__(self, cesid, c2c_cetp_transaction, t2t_mgr, name="iCETPC2CLayer"):
        self.q                      = asyncio.Queue()               # Enqueues the CETP messages from CETP Transport
        self.t                      = t2t_mgr                       # This shall be transport layer manager
        self.c2c_cetp_transaction   = c2c_cetp_transaction
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCETPC2CLayer)

    def send_cetp(self, msg):
        self.t.send_cetp(msg)

    def enqueue_transport_message_nowait(self, msg):
        self.q.put_nowait(msg)

    @asyncio.coroutine
    def enqueue_transport_message(self, msg):
        yield from self.q.put(msg)

    @asyncio.coroutine
    def consume_transport_message(self):
        while True:
            msg = yield from  self.q.get()
            if self.is_c2c_transaction(msg):
                self._logger.info("Received CETPc2c transaction")
                #process_c2c(msg)
            else:
                self._logger.info("Received h2h-transaction")
                self.forward_h2h(msg)
            self.q.task_done()

    def forward_h2h(self, msg):
        self.cetp_server.enqueue_c2c_message_nowait(msg)
            
    def process_c2c(self, msg):
        #function for -- security, remote CES feedback, evidence collection, and other indicators.
        #This is the CETP message received with (cetp.csst, cetp.cdst) session tags.
        pass

    def report_host(self):          
        #(or def enforce_ratelimits():)
        # These methods are invoked to report a misbehaving host to remote CES.
        pass

    def create_cetp_server(self, r_cesid, loop, policy_mgr, cetpstate_mgr, l_cesid):
        """ Creating the upper layer to handle CETPTransport"""
        self.cetp_server = CETPServer(c2c_layer=self, r_cesid=r_cesid, loop=loop, policy_mgr=policy_mgr, cetpstate_mgr=cetpstate_mgr, l_cesid=l_cesid)
        asyncio.ensure_future(self.cetp_server.consume_c2c_message())
        
    def is_c2c_transaction(self, msg):
        """ Shall check if the cetp-transaction bears (sst, dst) tags allocated for c2c-transaction  """
        # c_sst, c_dst = self.c2c_cetp_transaction.sst, self.c2c_cetp_transaction.dst
        # if msg.sst, msg.dst == c_sst, c_dst:        return True
        return False



class iCETPT2TManager:
    def __init__(self, cesid, name="iCETPT2TManager"):
        self.cesid                  = cesid
        self.c2c_layer              = None
        self.current_transport      = None
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCETPT2TManager)

    
    def assign_c2c(self, c2c_layer):
        self.c2c_layer = c2c_layer
        
    def select_transport(self):
        # some processing to select current cetp_transport, based on
        # load_balancing() or best_Health(), or smalllest_rtt().
        return cetp_transport
    
    def send_cetp(self, msg):
        #current_transport = self.select_transport()
        #current_transport.send_cetp(msg)
        self.current_transport.send_cetp(msg)           # Temporarily. Ideally it should be stream on which packet is received.
       # self._logger.info("Send Message: ", msg)
        
    def data_received_from_transport(self, msg, transport):
        #self.transport_layer_specific_processing()        # Last seen timestamp etc.
        #self.c2c_layer.enqueue_cetp(msg)
        self.c2c_layer.enqueue_transport_message_nowait(msg)
        self._logger.info("Data from CETPTransport is enqueued")

    #Objective: 
    #1) absorb unexpected connection closure due to RST attack or due to NW.    (And how it is handled).
    #2) Make CETPC2C independent of CETPT2T                - currently it is dependent.



class iCESServerTransportTCP(asyncio.Protocol):
    def __init__(self, ces_certificate, ces_privatekey, ca_certificate, policy_mgr=None, cetpstate_mgr=None, c2c_mgr = None, name="iCESServerTransportTCP"):
        self.ces_certificate = ces_certificate
        self.ces_privatekey  = ces_privatekey
        self.ca_certificate  = ca_certificate
        self.policy_mgr      = policy_mgr
        self.cetpstate_mgr   = cetpstate_mgr
        self.cesid           = None                     # Indicates if we trustworthly know the remote 'cesid' (having negotiated the c2c-policy with remote endpoint).
        self.c2c_mgr         = c2c_mgr                  # c2c-Manager handles a newly connected client, until the c2c-negotiation (trust) is established.
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESServerTransportTCP)
                                                        # Once trust is established
        
        self.data_buffer     = b'' 
        
    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        self._logger.info('Connection from {}'.format(self.peername))
        self.transport = transport
        ip_addr, port = self.peername
        
        if self.c2c_mgr.remote_endpoint_malicious_history(ip_addr) == True:
            self._logger.info("Closing: Remote endpoint has exceed the misbehavior threshold ")
            self.transport.close()                 # is it correct way of closing connection?
    
    def set_cesid(self, cesid):
        self.cesid = cesid
    
    def assign_c2c(self, c2c_layer):               # Triggered by ’c2c-manager’
        self.c2c = c2c_layer                       # To load an existing c2c layer for ’cesid’
        self.cesid = True

    def assign_t2t_manager(self, t2t_mgr):         # Triggered by ’c2c-manager’
        self.t2t = t2t_mgr                         # To load an existing c2c layer for ’cesid’
        self.t2t.current_transport = self

    def send_cetp(self, msg):
        msg = self.message_framing(msg)
        #print("Message sent: ", msg)
        self.transport.write(msg)

    def message_framing(self, msg):
        #cetp_frame = some_processing(msg)
        cetp_frame = msg.encode()
        return cetp_frame

    def data_received(self, data):
        msg = data.decode()
        self._logger.debug('Data received: {!r}'.format(msg))
        cetp_msg = self.unframe(msg)
        
        if self.cesid is not None:
            self._logger.info("Forward the message to CETP-c2c layer")
            self.t2t.data_received_from_transport(msg, self)                            # In future, I might need to send the transport alongside the message, for sending reply.
        else:
            self.c2c_mgr.process_new_sender(cetp_msg, self)      # Forwarding message to c2cmanager for ces-ces policy negotiation.

    def unframe(self, data):
        # After some processing on data
        cetp_msg = data
        return cetp_msg 
    
    def connection_lost(self, ex):
        self._logger.info("CETPClient terminated the connection")



LOGLEVEL_iCESServerTransportTLS     = logging.INFO


class iCESServerTransportTLS(asyncio.Protocol):
    def __init__(self, ces_cert, ces_privkey, ca_cert, policy_mgr=None, cetpstate_mgr=None, name="iCESServerTransportTLS"):
        self._loop          = loop
        self.policy_mgr     = policy_mgr
        self.cetpstate_mgr  = cetpstate_mgr
        self.ces_certificate, self.ces_privatekey, self.ca_certificate = ces_cert, ces_privkey, ca_cert
        self._logger         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCESServerTransportTLS)


    def connection_made(self, transport):
        self.transport  = transport
        self.sockname   = self.transport.get_extra_info('sockname')
        self.peername   = self.transport.get_extra_info('peername')
        print('Connection from {}'.format(self.peername))

    def data_received(self, data):
        """CETPStateless module processes inbound CETP packets """
        inbound_cetp = data.decode()
        cetp_packet = json.loads(inbound_cetp)
        #print('Data received: {!r}'.format(cetp_packet))
        sstag, dstag = cetp_packet["SST"], cetp_packet["DST"]
        sstag = int(sstag)

        if self.cetpstate_mgr.has((sstag, dstag)):
            print("The packet belongs to an ongoing transaction")
            cetp_transaction = self.cetpstate_mgr.get((sstag, dstag))
            cetp_transaction.post_establishment()
        else:
            print("New iCES transaction")
            ices_transaction = cetpTransaction.CETPStateless(cetp_packet, local_addr=self.sockname, remote_addr=self.peername, policy_mgr= self.policy_mgr, cetpstate_mgr= self.cetpstate_mgr)
            cetp_packet = ices_transaction.start_transaction()
            if cetp_packet == None:
                return
        
        #print('Send: {!r}'.format(message))
        self.transport.write(cetp_packet.encode())

    def connection_lost(self, ex):
        print("CETPClient terminated the connection")



