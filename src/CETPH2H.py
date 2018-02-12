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
LOGLEVEL_CETPH2HLocal        = logging.INFO

class CETPH2H:
    def __init__(self, loop=None, l_cesid="", r_cesid="", cetpstate_mgr= None, policy_client=None, policy_mgr=None, cetp_mgr=None, ces_params=None, cetp_security=None, \
                 host_register= None, c2c_negotiated=False, interfaces=None, c2c_layer=None, conn_table=None, name="CETPH2H"):
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
            #print("Via tasks")
            #if self.ongoing_h2h_transactions < self.max_session_limit:              # Number of simultaneous H2H-transactions are below the upper limit  
            asyncio.ensure_future(self.h2h_transaction_start(cb, dst_id))       # "try, except" within task can consume a task-related exception
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
        h2h = H2HTransaction.H2HTransactionOutbound(loop=self._loop, cb=cb, host_ip=ip_addr, src_id="", dst_id=dst_id, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetp_h2h=self, \
                                                    ces_params=self.ces_params, policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr, host_register=self.host_register, \
                                                    conn_table=self.conn_table, interfaces=self.interfaces, cetp_security=self.cetp_security, rtt_time=self.rtt_measurement)
        cetp_message = yield from h2h.start_cetp_processing()
        if cetp_message != None:
            #self._logger.info(" H2H transaction started.")
            self.send(cetp_message)

    def process_h2h_transaction(self, cetp_msg):
        self.count += 1
        #self._logger.debug("self.count: {}".format(self.count))
        o_transaction = None
        inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dstag, inbound_sstag
        
        if self.cetpstate_mgr.has_established_transaction( (sstag, dstag) ):
            self._logger.info(" CETP message for a negotiated transaction (SST={} -> DST={})".format(sstag, dstag))
            o_h2h = self.cetpstate_mgr.get_established_transaction( (sstag, dstag) )
            o_h2h.post_h2h_negotiation(cetp_msg)

        elif self.cetpstate_mgr.has_initiated_transaction( (sstag, 0) ):
            self._logger.debug(" Continue resolving H2H-transaction (SST={} -> DST={})".format(sstag, 0))
            o_h2h = self.cetpstate_mgr.get_initiated_transaction( (sstag, 0) )
            resp = o_h2h.continue_cetp_processing(cetp_msg)
            (ret, cetp_message) = resp
            if len(cetp_message) != 0:
                self.send(cetp_message)
            
        elif inbound_dstag == 0:
            #self._logger.info(" No prior H2H-transaction found -> Initiating Inbound H2HTransaction (SST={} -> DST={})".format(inbound_sstag, inbound_dstag))
            ih2h = H2HTransaction.H2HTransactionInbound(sstag=sstag, dstag=sstag, l_cesid=self.l_cesid, r_cesid=self.r_cesid, policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr, \
                                                         interfaces=self.interfaces, conn_table=self.conn_table, cetp_h2h=self, cetp_security=self.cetp_security, ces_params=self.ces_params)
            #asyncio.ensure_future(i_h2h.start_cetp_processing(cetp_msg))
            asyncio.ensure_future(self.process_inbound_transaction(ih2h, cetp_msg))
            
        # Add try, except?
        
    @asyncio.coroutine
    def process_inbound_transaction(self, ih2h, cetp_msg):
        res = yield from ih2h.start_cetp_processing(cetp_msg)
        (negotiation_status, cetp_message) = res
        if cetp_message != None:
            self.send(cetp_message)
        
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
    def __init__(self, loop=None, l_cesid="", cetpstate_mgr= None, policy_mgr=None, cetp_mgr=None, ces_params=None, cetp_security=None, host_register= None, \
                 conn_table=None, name="CETPH2H"):
        self._loop                      = loop
        self.l_cesid                    = l_cesid
        self.cetpstate_mgr              = cetpstate_mgr
        self.policy_mgr                 = policy_mgr
        self.ces_params                 = ces_params
        self.cetp_mgr                   = cetp_mgr
        self.cetp_security              = cetp_security
        self.host_register              = host_register
        self.conn_table                 = conn_table
        self._closure_signal            = False
        self.pending_tasks              = []
        self.count = 0
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
        dns_q, addr = cb_args
        ip_addr, port = addr
        h2h = H2HTransaction.H2HTransactionLocal(loop=self._loop, cb=cb, host_ip=ip_addr, src_id="", dst_id=dst_id, policy_mgr=self.policy_mgr, cetp_h2h=self, \
                                                 cetpstate_mgr=self.cetpstate_mgr, cetp_security= self.cetp_security, host_register=self.host_register, conn_table=self.conn_table)
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


class MockCETPManager:
    def remove_c2c_layer(self, r_cesid):        pass
    def remove_cetp_endpoint(self, r_cesid):    pass

def getLocalCETP(loop):
    import yaml, CETPSecurity, ConnectionTable, PolicyManager

    cesid                  = "cesa.lte."
    cetp_policies          = "config_cesa/cetp_policies.json"
    filename               = "config_cesa/config_cesa_ct.yaml"
    config_file            = open(filename)
    ces_conf               = yaml.load(config_file)
    ces_params             = ces_conf['CESParameters']
    conn_table             = ConnectionTable.ConnectionTable()
    cetpstate_mgr          = ConnectionTable.CETPStateTable()                                       # Records the established CETP transactions (both H2H & C2C). Required for preventing the re-allocation already in-use SST & DST (in CETP transaction).
    cetp_security          = CETPSecurity.CETPSecurity(loop, conn_table, ces_params)
    interfaces             = PolicyManager.FakeInterfaceDefinition(cesid)
    policy_mgr             = PolicyManager.PolicyManager(cesid, policy_file=cetp_policies)          # Shall ideally fetch the policies from Policy Management System (of Hassaan)    - And will be called, policy_sys_agent
    host_register          = PolicyManager.HostRegister()
    #cetp_mgr               = cetpManager.CETPManager(cetp_policies, cesid, ces_params, loop=loop)
    cetp_mgr               = MockCETPManager()
    local_h2h              = CETPH2HLocal(l_cesid=cesid, cetpstate_mgr=cetpstate_mgr, policy_mgr=policy_mgr, cetp_mgr=cetp_mgr, \
                                         cetp_security=cetp_security, host_register=host_register, conn_table=conn_table)
    return local_h2h

@asyncio.coroutine
def testing_Localoutput(h):
    h.set_closure_signal()

@asyncio.coroutine
def test_singleAQuery(h):    
    dst_id = 'srv1.hosta1.cesa.lte.'
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb = (test_cb, cb_args)
    
    h.resolve_cetp(dst_id, cb)
    yield from asyncio.sleep(2)

    asyncio.ensure_future(testing_Localoutput(h))
    yield from asyncio.sleep(2)

@asyncio.coroutine
def test_FloodAQuery(h):
    # Also find maximum limit of H2H queries handled locally.
    dst_id = 'srv1.hosta1.cesa.lte.'
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb = (test_cb, cb_args)

    for it in range(0, 1000):
        h.resolve_cetp(dst_id, cb) 
        if it % 100 == 0:
            yield from asyncio.sleep(0.5)
    
    yield from asyncio.sleep(4)
    asyncio.ensure_future(testing_Localoutput(h))
    yield from asyncio.sleep(2)

def set_closed(h):
    h.set_closure_signal()

@asyncio.coroutine
def test_ratelimit(h, loop):
    # Also find maximum limit of H2H queries handled locally.
    dst_id = 'srv1.hosta1.cesa.lte.'
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb = (test_cb, cb_args)
    loop.call_later(1.0, set_closed, h)
    num = 7000
    
    for it in range(0, num):
        if h._closure_signal == True:
            break
        h.resolve_cetp(dst_id, cb)
        yield from asyncio.sleep(0.000001)
    
    yield from asyncio.sleep(4)
    asyncio.ensure_future(testing_Localoutput(h))
    yield from asyncio.sleep(2)


def get_h2hLayer(loop):
    import yaml, CETPSecurity, ConnectionTable, PolicyManager
    
    cesid                  = "cesa.lte."
    r_cesid                = "cesb.lte."
    cetp_policies          = "config_cesa/cetp_policies.json"
    filename               = "config_cesa/config_cesa_ct.yaml"
    config_file            = open(filename)
    ces_conf               = yaml.load(config_file)
    ces_params             = ces_conf['CESParameters']
    ces_params["max_c2c_transports"] = 2
    conn_table             = ConnectionTable.ConnectionTable()
    cetpstate_mgr          = ConnectionTable.CETPStateTable()                                       # Records the established CETP transactions (both H2H & C2C). Required for preventing the re-allocation already in-use SST & DST (in CETP transaction).
    cetp_security          = CETPSecurity.CETPSecurity(loop, conn_table, ces_params)
    interfaces             = PolicyManager.FakeInterfaceDefinition(cesid)
    policy_mgr             = PolicyManager.PolicyManager(cesid, policy_file=cetp_policies)          # Shall ideally fetch the policies from Policy Management System (of Hassaan)    - And will be called, policy_sys_agent
    host_register          = PolicyManager.HostRegister()
    #cetp_mgr               = cetpManager.CETPManager(cetp_policies, cesid, ces_params, loop=loop)
    cetp_mgr               = MockCETPManager()
    h                      = CETPH2H(l_cesid = cesid, r_cesid = r_cesid, cetpstate_mgr= cetpstate_mgr, policy_mgr=policy_mgr, policy_client=None, \
                                     loop=loop, cetp_mgr=cetp_mgr, ces_params=ces_params, cetp_security=cetp_security, host_register=host_register, \
                                     interfaces=interfaces, conn_table=conn_table)
    
    c2c = CETPC2C.CETPC2CLayer(loop, l_cesid=cesid, r_cesid=r_cesid, cetpstate_mgr= cetpstate_mgr, policy_mgr=policy_mgr, conn_table=conn_table, \
                               ces_params=ces_params, cetp_security=cetp_security, cetp_mgr=cetp_mgr, cetp_h2h=h, interfaces=interfaces)
    h.c2c = c2c
    return h

def test_cb(a,b,r_addr=None, success=False):
    if success: 
        pass
        #print("H2H Success")
    else: 
        pass       
        #print("H2H failed")

@asyncio.coroutine
def test_naptrResponse(h):
    naptr_rrs = []
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'))
    #naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49004', 'tls'))
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls'))
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49003', 'tls'))
    
    dst_id = 'srv1.hostb1.cesb.lte.'
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb = (test_cb, cb_args)
    
    h.process_naptrs(dst_id, naptr_rrs, cb)
    yield from asyncio.sleep(2)

    for it in range(0, 1000):
        h.process_naptrs(dst_id, naptr_rrs, cb) 
        if it % 100 == 0:
            yield from asyncio.sleep(0.5)
    
    asyncio.ensure_future(testing_output(h))
    yield from asyncio.sleep(2)

@asyncio.coroutine
def test_naptrFlood(h):
    """ A NAPTR flood """
    naptr_rrs = []
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'))
    #naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49004', 'tls'))
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls'))
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49003', 'tls'))
    
    dst_id = 'srv1.hostb1.cesb.lte.'
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb = (test_cb, cb_args)

    for it in range(0, 1000):
        h.process_naptrs(dst_id, naptr_rrs, cb) 
        if it % 100 == 0:
            yield from asyncio.sleep(0.5)
        
    yield from asyncio.sleep(8)
    asyncio.ensure_future(testing_output(h))
    yield from asyncio.sleep(2)


@asyncio.coroutine
def testing_output(h):
    print("------- Test completed ----")
    print("C2C connected: ", h._isConnected())
    yield from test_resourceCleanup(h)

@asyncio.coroutine
def test_resourceCleanup(h):
    h.handle_interrupt()
    yield from asyncio.sleep(1)

@asyncio.coroutine
def test_transportFailover(h):
    try:
        import os
        naptr_rrs = []
        naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'))
        #naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49004', 'tls'))
        naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls'))
        
        dst_id = 'srv1.hostb1.cesb.lte.'
        cb_args = ("SomeQ", ("10.0.3.111", 55443))
        cb = (test_cb, cb_args)
        
        dport = 49002
        ipt_cmd = "sudo iptables -A OUTPUT -p tcp --dport {} -j DROP".format(dport)
        os.popen(ipt_cmd)
        yield from asyncio.sleep(0.2)
    
        for it in range(0, 1000):
            h.process_naptrs(dst_id, naptr_rrs, cb) 
            if it % 100 == 0:
                yield from asyncio.sleep(0.5)
        
        yield from asyncio.sleep(4)
        asyncio.ensure_future(testing_output(h))
        yield from asyncio.sleep(2)
        
    except Exception as ex:
        print("test_transportFailover", ex)
    finally:
        dport = 49002
        ipt_cmd = "sudo iptables -D OUTPUT -p tcp --dport {} -j DROP".format(dport)
        os.popen(ipt_cmd)
        yield from asyncio.sleep(0.2)

@asyncio.coroutine
def test_forbiddenSender(h):
    import CETPSecurity
    h.cetp_security.register_filtered_domains(CETPSecurity.KEY_BlacklistedLHosts, "hosta1.cesa.lte.")
    yield from asyncio.sleep(0.1)
    yield from test_singleAQuery(h)

@asyncio.coroutine
def test_forbiddenDestination(h):
    import CETPSecurity
    h.cetp_security.register_filtered_domains(CETPSecurity.KEY_LocalHosts_Inbound_Disabled, "srv1.hosta1.cesa.lte.")
    yield from asyncio.sleep(0.1)
    yield from test_singleAQuery(h)

           
def test_functions(h, loop):
    #For H2H-CETP
    #asyncio.ensure_future(test_naptrResponse(h))
    #asyncio.ensure_future(test_naptrFlood(h))
    #asyncio.ensure_future(test_transportFailover(h))
    #asyncio.ensure_future(test_resourceCleanup(h))
    
    #For LocalH2H-CETP
    #asyncio.ensure_future(test_singleAQuery(h))
    #asyncio.ensure_future(test_FloodAQuery(h))
    #asyncio.ensure_future(test_forbiddenSender(h))
    #asyncio.ensure_future(test_forbiddenDestination(h))
    asyncio.ensure_future(test_ratelimit(h, loop))
    
if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.get_event_loop()
    h = getLocalCETP(loop)
    #h = get_h2hLayer(loop)
    
    try:
        test_functions(h, loop)
        loop.run_forever()
    except KeyboardInterrupt:
        print("Ctrl+C Handled")
        #loop.run_until_complete(testing_Localoutput2(h, loop))
    except Exception as ex:
        print(ex)
    finally:
        loop.close()

