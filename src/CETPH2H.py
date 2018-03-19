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
import host

LOGLEVEL_CETPH2H             = logging.INFO
LOGLEVEL_CETPH2HLocal        = logging.INFO

class CETPH2H:
    def __init__(self, loop=None, l_cesid="", r_cesid="", cetpstate_mgr= None, policy_client=None, policy_mgr=None, cetp_mgr=None, ces_params=None, cetp_security=None, \
                 host_table=None, pool_table=None, c2c_negotiated=False, interfaces=None, c2c_layer=None, conn_table=None, name="CETPH2H"):
        self._loop                      = loop
        self.l_cesid                    = l_cesid
        self.r_cesid                    = r_cesid
        self.cetpstate_mgr              = cetpstate_mgr
        self.policy_client              = policy_client
        self.policy_mgr                 = policy_mgr
        self.ces_params                 = ces_params
        self.cetp_mgr                   = cetp_mgr
        self.cetp_security              = cetp_security
        self.host_table                 = host_table
        self.pool_table                 = pool_table
        self.c2c                        = c2c_layer
        self.interfaces                 = interfaces
        self.conn_table                 = conn_table
        self.h2h_q                      = asyncio.Queue()           # Enqueues the NAPTR responses triggered by the private hosts, while C2Clayer is established.
        self.c2c_connectivity           = c2c_negotiated
        self.max_session_limit          = 500                       # Dummy value for now, In reality the value shall come from C2C negotiation with remote CES.
        self.nxdomain_resp_threshold    = 3                         # No. of pending DNS queries gracefully handled in case of C2C termination. 
        self.ongoing_h2h_transactions   = 0
        self.count                      = 0
        self._closure_signal            = False
        self.h2h_queue_task             = None
        self.pending_tasks              = []
        self.rtt_measurement            = []                        # For experimentation only. Shall be removed in final version.
        self._logger                    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPH2H)
        self._logger.info("CETPH2H layer created for cesid '{}'".format(r_cesid))

    def get_cetp_c2c_layer(self):
        """ Initiates CETPc2clayer between two CES nodes """
        self.c2c = self.cetp_mgr.create_c2c_layer(cetp_h2h=self, r_cesid=self.r_cesid)
        
    def _isConnected(self):
        return self.c2c_connectivity
    
    def process_naptrs(self, dst_id, naptr_rrs, cb):
        """ This method enqueues the naptr responses triggered by private hosts. """
        self.c2c.process_naptrs(naptr_rrs)
        if self._isConnected():
            self.trigger_h2h_negotiation(dst_id, naptr_rrs, cb)
        else:
            queue_msg = (dst_id, naptr_rrs, cb)
            self.h2h_q.put_nowait(queue_msg)               # Possible exception: If the queue is full, [It will simply drop the message (without waiting for space to be available in the queue]
        
    @asyncio.coroutine
    def enqueue_naptrs_task(self, dst_id, naptr_records, cb):
        yield from self.h2h_q.put(msg)                 # More safe enqueuing, if the queue is full, the call doesn't return until the queue has space to store this message - can be triggered via asyncio.ensure_future(enqueue) 

    @asyncio.coroutine
    def _consume_h2h_requests(self):
        """ To consume the enqueued NAPTR-responses, triggered by the private hosts """
        while True:
            try:
                queued_data = yield from self.h2h_q.get()
            except Exception as ex:
                if not self._closure_signal:
                    self._logger.error(" Exception '{}' in reading H2H-queue towards '{}'".format(ex, self.r_cesid))
                break
            
            dst_id, naptr_rr, cb = queued_data
            self.trigger_h2h_negotiation(dst_id, naptr_rr, cb, from_queue=True)
    
    def trigger_h2h_negotiation(self, dst_id, naptr_rr, cb, from_queue=False):
        try:
            #if self.ongoing_h2h_transactions < self.max_session_limit:              # Number of simultaneous H2H-transactions are below the upper limit  
            asyncio.ensure_future( self.h2h_transaction_start(cb, dst_id) )       # "try, except" within task can consume a task-related exception
            if from_queue:  self.h2h_q.task_done()
            #else:
            #    self._logger.error(" Number of simultaneous connections to remote CES '<%s>' exceeded limit.".format(self.r_cesid))
            #    self.h2h_q.task_done()

        except Exception as ex:
            self._logger.error(" Exception '{}' in consuming H2H request towards {}".format(ex, self.r_cesid))
            if from_queue:  self.h2h_q.task_done()
    
    def start_h2h_consumption(self):
        """ Triggers the task for consuming naptr responses from queue """
        self._logger.info(" Initiating the task for consuming NAPTR-responses triggered by private hosts.")
        self.h2h_queue_task = asyncio.ensure_future(self._consume_h2h_requests())
        self.pending_tasks.append(self.h2h_queue_task)
    
    def suspend_h2h_consumption(self):
        """ Suspends the task for consuming naptr responses from queue """
        if not self.h2h_queue_task.cancelled():
            self._logger.debug("Closing the task of consuming H2H requests.")
            self.h2h_queue_task.cancel()
            self.pending_tasks.remove(self.h2h_queue_task)
    
    def c2c_connectivity_report(self, connected=True):
        """ Reports the success/failure of C2C-negotiation """
        self.c2c_connectivity = connected
        if connected:       self.start_h2h_consumption()
        else:               self.suspend_h2h_consumption()
            
    @asyncio.coroutine
    def h2h_transaction_start(self, cb, dst_id):
        (cb_func, cb_args) = cb
        dns_q, addr = cb_args
        ip_addr, port = addr
        
        key      = (host.KEY_HOST_IPV4, ip_addr)
        host_obj = self.host_table.get(key)
        src_id   = host_obj.fqdn
        self._logger.info("Initiating H2H policy negotiation between '{}' -> '{}'".format(src_id, dst_id))

        h2h = H2HTransaction.H2HTransactionOutbound(loop=self._loop, cb=cb, host_ip=ip_addr, src_id=src_id, dst_id=dst_id, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetp_h2h=self, \
                                                    ces_params=self.ces_params, policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr, host_table=self.host_table, \
                                                    conn_table=self.conn_table, interfaces=self.interfaces, cetp_security=self.cetp_security, pool_table=self.pool_table, rtt_time=self.rtt_measurement)
        cetp_message = yield from h2h.start_cetp_processing()
        if cetp_message != None:
            #self._logger.info(" H2H transaction started.")
            self.send(cetp_message)

    def process_h2h_transaction(self, cetp_msg):
        self.count += 1
        #self._logger.debug("self.count: {}".format(self.count))
        inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dstag, inbound_sstag
        
        if self.cetpstate_mgr.has( (H2HTransaction.KEY_ESTABLISHED_TAGS, sstag, dstag) ):
            self._logger.info(" CETP message for a negotiated transaction (SST={} -> DST={})".format(sstag, dstag))
            o_h2h = self.cetpstate_mgr.get( (H2HTransaction.KEY_ESTABLISHED_TAGS, sstag, dstag) )
            
            if o_h2h.get_remote_cesid() == self.r_cesid:
                o_h2h.post_h2h_negotiation(cetp_msg)

        elif self.cetpstate_mgr.has( (H2HTransaction.KEY_INITIATED_TAGS, sstag, 0) ):
            self._logger.debug(" Continue resolving H2H-transaction (SST={} -> DST={})".format(sstag, 0))
            o_h2h = self.cetpstate_mgr.get( (H2HTransaction.KEY_INITIATED_TAGS, sstag, 0) )
            
            if o_h2h.get_remote_cesid() == self.r_cesid:
                cetp_resp = o_h2h.continue_cetp_processing(cetp_msg)
                if cetp_resp is not None:
                    self.send(cetp_resp)
            
        elif inbound_dstag == 0:
            #self._logger.info(" No prior H2H-transaction found -> Initiating Inbound H2HTransaction (SST={} -> DST={})".format(inbound_sstag, inbound_dstag))
            ih2h = H2HTransaction.H2HTransactionInbound(sstag=sstag, dstag=dstag, l_cesid=self.l_cesid, r_cesid=self.r_cesid, policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr, \
                                                         interfaces=self.interfaces, conn_table=self.conn_table, cetp_h2h=self, cetp_security=self.cetp_security, \
                                                         ces_params=self.ces_params, host_table=self.host_table, pool_table=self.pool_table)

            asyncio.ensure_future(self.process_inbound_transaction(ih2h, cetp_msg))
            
        # Add try, except?
        
    @asyncio.coroutine
    def process_inbound_transaction(self, ih2h, cetp_msg):
        cetp_resp = yield from ih2h.start_cetp_processing(cetp_msg)
        if cetp_resp is not None:
            self.send(cetp_resp)
        
    def send(self, msg):
        """ Forwards the message to CETP c2c layer"""
        self.c2c.send_cetp(msg)

    def consume_message_from_c2c(self, cetp_msg):
        """ Consumes the message from C2CLayer for H2H processing """
        try:
            if self._isConnected():
                self.process_h2h_transaction(cetp_msg)

        except Exception as ex:
            self._logger.info(" Exception in consuming message from c2c-layer: '{}'".format(ex))
            traceback.print_exc(file=sys.stdout)

    def _close_pending_tasks(self):
        for tsk in self.pending_tasks:
            if not tsk.cancelled():
                self._logger.debug("Cleaning the pending tasks")
                tsk.cancel()

    def set_closure_signal(self):
        self._closure_signal = True
        self.resource_cleanup()
        self._close_pending_tasks()
        self.cetp_mgr.remove_cetp_endpoint(self.r_cesid)        # Remove the endpoint after cleanup.
        print("Count", self.count)
        del(self)
        #self.show_measuremnt_results()
    
    def resource_cleanup(self):
        """ Deletes the CETPH2H instance towards r_cesid, cancels the pending tasks, and handles the pending <H2H DNS-NAPTR responses. """
        try:
            pending_dns_queries = self.h2h_q.qsize()
            # Issues DNS NXDOMAIN, if the queued NAPTR responses are less than N in size
            if pending_dns_queries < self.nxdomain_resp_threshold:
                self._logger.info(" Executing DNS NXDOMAIN on the pending h2h-transactions.")
                queued_data = self.h2h_q.get_nowait()               # Could it be just one or many records ?
                (dst_id, naptr_rr, cb) = queued_data
                (cb_func, cb_args) = cb
                (dns_q, addr) = cb_args
                cb_func(dns_q, addr, success=False)
                
        except Exception as ex:
            self._logger.debug(" Exception '{}' in resource cleanup towards {}".format(ex, self.r_cesid))
    
    def handle_interrupt(self):
        """ Deletes the CETPH2H instance, C2CLayer and pending tasks towards remote CES nodes """
        self.c2c.handle_interrupt()
        self.set_closure_signal()

    def update_H2H_transaction_count(self, initiated=True):
        """ To limit the number of H2H transaction to limit agreed in C2C Negotiation """
        if initiated:
            self.ongoing_h2h_transactions += 1
        else:
            self.ongoing_h2h_transactions -= 1

    def show_measuremnt_results(self):
        """ Function displaying results of benchmarking or testing -- To be Removed finally """
        if len(self.rtt_measurement)>0:
            avg = sum(self.rtt_measurement)/len(self.rtt_measurement)
            print("Min: ", min(self.rtt_measurement)*1000,"ms\t", "Max: ", max(self.rtt_measurement)*1000,"ms")
            print("Average: ", avg*1000,"ms")
            

class CETPH2HLocal:
    def __init__(self, loop=None, l_cesid="", cetpstate_mgr= None, policy_mgr=None, cetp_mgr=None, ces_params=None, cetp_security=None, host_table= None, \
                 conn_table=None, pool_table=None, name="CETPH2H"):
        self._loop                      = loop
        self.l_cesid                    = l_cesid
        self.cetpstate_mgr              = cetpstate_mgr
        self.policy_mgr                 = policy_mgr
        self.ces_params                 = ces_params
        self.cetp_mgr                   = cetp_mgr
        self.cetp_security              = cetp_security
        self.host_table                 = host_table
        self.conn_table                 = conn_table
        self._closure_signal            = False
        self.pool_table                 = pool_table
        self.pending_tasks              = []
        self.count                      = 0
        self._logger                    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPH2H)
        self._logger.info("Initiated CETPH2HLocal for localCETP resolution")
        
    def resolve_cetp(self, dst_id, cb):
        """ To consume NAPTR-response triggered by the private hosts """
        try:
            if not self._closure_signal:
                t = asyncio.ensure_future(self._start_cetp_negotiation(cb, dst_id))     # Enable "try, except" within task to locally consume a task-raised exception
                #self.pending_tasks.append(t)
        except Exception as ex:
            self._logger.error(" Exception '{}' in triggering LocalH2HTransaction ".format(ex))
        
    @asyncio.coroutine
    def _start_cetp_negotiation(self, cb, dst_id):
        (cb_func, cb_args) = cb
        dns_q, addr   = cb_args
        ip_addr, port = addr
        key           = (host.KEY_HOST_IPV4, ip_addr)

        if not self.host_table.has(key):
            self._logger.info("Sender IP '{}' is not a registered host".format(ip_addr))
            return
        
        host_obj = self.host_table.get(key)
        src_id   = host_obj.fqdn
        
        h2h = H2HTransaction.H2HTransactionLocal(loop=self._loop, cb=cb, host_ip=ip_addr, src_id=src_id, dst_id=dst_id, policy_mgr=self.policy_mgr, cetp_h2h=self, \
                                                 cetpstate_mgr=self.cetpstate_mgr, cetp_security= self.cetp_security, host_table=self.host_table, pool_table=self.pool_table, \
                                                 conn_table=self.conn_table)
        result = yield from h2h.start_cetp_processing()     # Returns True or False
        self.count +=1
        #if result == True:
        #    self._logger.info("OK")
        #else:
        #    self._logger.info("NOK")

    def set_closure_signal(self):
        self._closure_signal = True
        #print("self.count: ", self.count)
        for t in self.pending_tasks:
            if not t.cancelled():   
                t.cancel()
