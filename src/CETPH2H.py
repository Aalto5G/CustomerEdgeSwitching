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
import CETPC2C

LOGLEVEL_CETPH2H             = logging.INFO


class CETPH2H:
    def __init__(self, loop=None, l_cesid="", r_cesid="", cetpstate_mgr= None, policy_client=None, policy_mgr=None, cetp_mgr=None, ces_params=None, cetp_security=None, \
                 host_register= None, c2c_negotiated=False, c2c_layer=None, name="CETPH2H"):
        self._loop                      = loop
        self.l_cesid                    = l_cesid
        self.r_cesid                    = r_cesid
        self.cetpstate_mgr              = cetpstate_mgr
        self.policy_client              = policy_client
        self.policy_mgr                 = policy_mgr
        self.ces_params                 = ces_params
        self.cetp_mgr                   = cetp_mgr
        self.cetp_security              = cetp_security
        self.host_register              = host_register
        self.c2c                        = c2c_layer
        self._closure_signal            = False
        self.ongoing_h2h_transactions   = 0
        self.max_session_limit          = 20                        # Dummy value for now, In reality the value shall come from C2C negotiation with remote CES.
        self.h2h_q                      = asyncio.Queue()           # Enqueues the NAPTR responses triggered by the private hosts.
        self.DNS_Cleanup_Threshold      = 5                         # No. of pending DNS queries gracefully handled in case of C2C termination. 
        self.c2c_negotiated              = c2c_negotiated
        self.pending_tasks              = []
        self._logger                    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPH2H)
        self._logger.info("CETPH2H layer created for cesid '{}'".format(r_cesid))
        
        """
        From iCES:
            self.c2c_q              = asyncio.Queue()
            self.c2c                = c2c_layer
            self.count              = 0                             # For debugging
        """


    def create_cetp_c2c_layer(self, naptr_list):
        """ Initiates CETPc2clayer between two CES nodes """
        self.c2c = CETPC2C.CETPC2CLayer(self._loop, cetp_h2h=self, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetpstate_mgr= self.cetpstate_mgr, \
                                 policy_mgr=self.policy_mgr, cetp_mgr=self.cetp_mgr, ces_params=self.ces_params, cetp_security=self.cetp_security)      # Shall c2clayer be obtained from CETPManager for 'r_cesid'? 
        self.c2c.initiate_cetp_transport(naptr_list)
        
    def enqueue_h2h_requests_nowait(self, naptr_records, cb):
        """ This method enqueues the naptr responses triggered by private hosts. """
        queue_msg = (naptr_records, cb)
        self.h2h_q.put_nowait(queue_msg)               # Possible exception: If the queue is full, [It will simply drop the message (without waiting for space to be available in the queue]

    @asyncio.coroutine
    def enqueue_h2h_requests(self, msg):
        yield from self.h2h_q.put(msg)                 # More safe enqueuing, if the queue is full, the call doesn't return until the queue has space to store this message - can be triggered via asyncio.ensure_future(enqueue) 

    @asyncio.coroutine
    def consume_h2h_requests(self):
        """ To consume NAPTR-response triggered by the private hosts """
        while True:
            try:
                queued_data = yield from self.h2h_q.get()
                (naptr_rr, cb) = queued_data
                dst_id = self.c2c.add_naptr_records(naptr_rr)                      # TBD: Use NAPTR records as trigger for re-connecting to a terminated endpoint, or a new transport-endpoint. 
                                                                                   # If already connected, discard naptr records.
                if dst_id !=None:
                    if self.ongoing_h2h_transactions < self.max_session_limit:
                        asyncio.ensure_future(self.h2h_transaction_start(cb, dst_id))     # Enable "try, except" within task to locally consume a task-raised exception
                    else:
                        self._logger.info(" Number of Ongoing transactions have exceeded the C2C limit.")
                
                self.h2h_q.task_done()

            except Exception as ex:
                if self._closure_signal: break
                self._logger.info(" Exception '{}' in consuming H2H request towards {}".format(ex, self.r_cesid))
                self.h2h_q.task_done()
            
    def c2c_negotiation_status(self, status=True):
        """ Reports that c2c-negotiation completed and whether it Succeeded/Failed """
        if (self.c2c_negotiated == False) and (status == True):
            self.c2c_negotiated  = status
            t1=asyncio.ensure_future(self.consume_h2h_requests())                       # Task for consuming naptr-response records triggered by private hosts
            self.pending_tasks.append(t1)
            
    def close_pending_tasks(self):
        for tsk in self.pending_tasks:
            if not tsk.cancelled():
                self._logger.debug("Cleaning the pending tasks")
                tsk.cancel()
        
    @asyncio.coroutine
    def h2h_transaction_start(self, cb, dst_id):
        (cb_func, cb_args) = cb
        dns_q, addr = cb_args
        ip_addr, port = addr
        h2h = H2HTransaction.H2HTransactionOutbound(loop=self._loop, cb=cb, host_ip=ip_addr, src_id="", dst_id=dst_id, l_cesid=self.l_cesid, r_cesid=self.r_cesid, \
                                                    ces_params=self.ces_params, policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr, host_register=self.host_register, cetp_h2h=self)
        cetp_packet = yield from h2h.start_cetp_processing()
        if cetp_packet != None:
            self._logger.debug(" H2H transaction started.")
            self.send(cetp_packet)

    def process_h2h_transaction(self, cetp_msg, transport):
        #self.count += 1
        #self._logger.debug("self.count: {}".format(self.count))
        o_transaction = None
        inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dstag, inbound_sstag
        
        if inbound_dstag == 0:
            self._logger.info(" No prior H2H-transaction found -> Initiating Inbound H2HTransaction (SST={} -> DST={})".format(inbound_sstag, inbound_dstag))
            i_h2h = H2HTransaction.H2HTransactionInbound(sstag=sstag, dstag=sstag, l_cesid=self.l_cesid, r_cesid=self.r_cesid, policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr)
            asyncio.ensure_future(i_h2h.start_cetp_processing(cetp_msg, transport))
            
        elif self.cetpstate_mgr.has_initiated_transaction( (sstag, 0) ):
            self._logger.debug(" Continue resolving H2H-transaction (SST={} -> DST={})".format(sstag, 0))
            o_h2h = self.cetpstate_mgr.get_initiated_transaction( (sstag, 0) )
            o_h2h.continue_cetp_processing(cetp_msg, transport)
            
        elif self.cetpstate_mgr.has_established_transaction( (sstag, dstag) ):
            self._logger.info(" CETP message for a negotiated transaction (SST={} -> DST={})".format(sstag, dstag))
            o_h2h = self.cetpstate_mgr.get_established_transaction( (sstag, dstag) )
            o_h2h.post_h2h_negotiation(cetp_msg, transport)
        
        # Add try, except?
        
    def send(self, msg):
        """ Forwards the message to CETP c2c layer"""
        self.c2c.send_cetp(msg)

    def consume_message_from_c2c(self, cetp_msg, transport):
        """ Consumes the message from C2CLayer for H2H processing """
        try:
            if self.c2c_negotiated:
                self.process_h2h_transaction(cetp_msg, transport)        

        except Exception as ex:
            self._logger.info(" Exception in consuming message from c2c-layer: '{}'".format(ex))

    def update_H2H_transaction_count(self, initiated=True):
        """ To limit the number of H2H transaction to limit agreed in C2C Negotiation """
        if initiated:
            self.ongoing_h2h_transactions += 1
        else:
            self.ongoing_h2h_transactions -= 1

    def set_closure_signal(self):
        self._closure_signal = True
    
    def resource_cleanup(self):
        """ Deletes the CETPClient instance towards r_cesid, cancels the pending tasks, and handles the pending <H2H DNS-NAPTR responses. """
        pending_dns_queries = self.h2h_q.qsize()
        if (pending_dns_queries>0) and (pending_dns_queries < self.DNS_Cleanup_Threshold):          # Issues DNS NXDOMAIN (if pending H2H-DNS queries < N in size)
            try:
                queued_data = self.h2h_q.get_nowait()
                (naptr_rr, cb) = queued_data
                (cb_func, cb_args) = cb
                (dns_q, addr) = cb_args
                cb_func(dns_q, addr, success=False)
            except Exception as ex:
                self._logger.info(" Exception '{}' in resource cleanup towards {}".format(ex, self.r_cesid))
        
        self.set_closure_signal()
        self.close_pending_tasks()
        self.cetp_mgr.remove_cetp_endpoint(self.r_cesid)               # This ordering is important 
        del(self)


    def handle_interrupt(self):
        """ Deletes the CETPClient instance, C2CLayer and pending tasks towards remote CES nodes """
        self.set_closure_signal()
        self.c2c.handle_interrupt()
        self.close_pending_tasks()

