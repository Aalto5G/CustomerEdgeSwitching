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
import icetpLayering
import ocetpLayering


LOGLEVEL_CETPClient             = logging.INFO
LOGLEVEL_oCES2CESLayer          = logging.INFO
LOGLEVEL_oCESTransportMgr       = logging.INFO
LOGLEVEL_oCESTransportTCP       = logging.INFO

CETP_MSG_LEN_FIELD              = 2         # in bytes



class CETPH2H:
    def __init__(self, loop=None, l_cesid="", r_cesid="", cetpstate_mgr= None, policy_client=None, policy_mgr=None, cetp_mgr=None, \
                 ces_params=None, cetp_security=None, host_register= None, c2c_negotiated=False, c2c_layer=None, name="CETPH2H"):
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
        self.client_q                   = asyncio.Queue()           # Enqueues the NAPTR responses triggered by the private hosts.
        self.DNS_Cleanup_Threshold      = 5                         # No. of pending DNS queries gracefully handled in case of C2C termination. 
        self.c2c_negotiated              = c2c_negotiated
        self.pending_tasks              = []
        self._logger                    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPClient)
        self._logger.info("CETPH2H layer created for cesid '{}'".format(r_cesid))
        
        """
        From iCES:
            self.c2c_q              = asyncio.Queue()
            self.c2c                = c2c_layer
            self.count              = 0                             # For debugging
        """


    def create_cetp_c2c_layer(self, naptr_list):
        """ Initiates CETPc2clayer between two CES nodes """
        self.c2c = oCES2CESLayer(self._loop, naptr_list=naptr_list, cetp_client=self, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetpstate_mgr= self.cetpstate_mgr, \
                                 policy_mgr=self.policy_mgr, policy_client=self.policy_client, ces_params=self.ces_params, cetp_security=self.cetp_security)      # Shall c2clayer be obtained from CETPManager for 'r_cesid'? 

    def enqueue_h2h_requests_nowait(self, naptr_records, cb_args):
        """ This method enqueues the naptr responses triggered by private hosts. """
        queue_msg = (naptr_records, cb_args)
        self.client_q.put_nowait(queue_msg)               # Possible exception: If the queue is full, [It will simply drop the message (without waiting for space to be available in the queue]

    @asyncio.coroutine
    def enqueue_h2h_requests(self, msg):
        yield from self.client_q.put(msg)                 # More safe enqueuing, if the queue is full, the call doesn't return until the queue has space to store this message - can be triggered via asyncio.ensure_future(enqueue) 

    @asyncio.coroutine
    def consume_h2h_requests(self):
        """ To consume NAPTR-response triggered by the private hosts """
        while True:
            try:
                queued_data = yield from self.client_q.get()
                (naptr_rr, cb) = queued_data
                dst_id = self.c2c.add_naptr_records(naptr_rr)                      # TBD: Use NAPTR records as trigger for re-connecting to a terminated endpoint, or a new transport-endpoint. 
                                                                                    # If already connected, discard naptr records.
                if self.ongoing_h2h_transactions < self.max_session_limit:
                    asyncio.ensure_future(self.h2h_transaction_start(cb, dst_id))     # Enable "try, except" within task to locally consume a task-raised exception
                else:
                    self._logger.info(" Number of Ongoing transactions have exceeded the C2C limit.")
                
                self.client_q.task_done()

            except Exception as ex:
                if self._closure_signal: break
                self._logger.info(" Exception '{}' in consuming H2H request towards {}".format(ex, self.r_cesid))
                self.client_q.task_done()
            
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
        
    def dns_nxdomain_callback(self, cb_args):
        """ Executes callback upon H2H-Policy negotiation success or failure """
        (query, addr) = cb_args
        self.cb_func(query, addr, success=False)

    @asyncio.coroutine
    def h2h_transaction_start(self, cb, dst_id):
        (cb_args, cb_func) = cb
        dns_q, addr = cb_args
        ip_addr, port = addr
        h2h = H2HTransaction.H2HTransactionOutbound(loop=self._loop, cb=cb, host_ip=ip_addr, src_id="", dst_id=dst_id, l_cesid=self.l_cesid, r_cesid=self.r_cesid, \
                                                    ces_params=self.ces_params, policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr, host_register=self.host_register, cetp_cleint=self)
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
        pending_dns_queries = self.client_q.qsize()
        if (pending_dns_queries>0) and (pending_dns_queries < self.DNS_Cleanup_Threshold):          # Issues DNS NXDOMAIN (if pending H2H-DNS queries < N in size)
            try:
                queued_data = self.client_q.get_nowait()
                (naptr_rr, cb) = queued_data
                (cb_func, cb_args) = cb
                (dns_q, addr) = cb_args
                cb_func(dns_q, addr, success=False)
            except Exception as msg:
                self._logger.info(" Exception in resource cleanup towards {}".format(self.r_cesid))
                self._logger.info(msg)
        
        self.set_closure_signal()
        self.close_pending_tasks()
        self.cetp_mgr.remove_client_endpoint(self.r_cesid)               # This ordering is important 
        del(self)


    def handle_interrupt(self):
        """ Deletes the CETPClient instance, C2CLayer and pending tasks towards remote CES nodes """
        self.set_closure_signal()
        self.c2c.handle_interrupt()
        self.close_pending_tasks()
        


class oCES2CESLayer:
    """
    Instantiates client CETP Transports towards remote CES, based on the NAPTR records.
    Manages, registers/unregisters the CETP Transports, AND performs resource cleanup on CES-to-CES connectivity loss.
    Timely negotiation of the CES-to-CES policies, AND forwards C2C-level CETP message to corresponding C2CTransaction, in post-c2c-negotiation phase.
    After CES-to-CES is negotiated, it forwards H2H-CETP Transactions to/from the upper layer. 
    Management of CETPTransport failover, seemless to H2H-layer.
    """
    def __init__(self, loop, naptr_list=[], cetp_client=None, l_cesid=None, r_cesid=None, cetpstate_mgr=None, policy_mgr=None, policy_client=None, ces_params=None, \
                 cetp_security=None, name="oCES2CESLayer"):
        self._loop                      = loop
        self.naptr_list                 = naptr_list
        self.cetp_client                = cetp_client            # H2H layer manager for remote-cesid 
        self.l_cesid                    = l_cesid
        self.r_cesid                    = r_cesid
        self.cetpstate_mgr              = cetpstate_mgr
        self.policy_client              = policy_client
        self.policy_mgr                 = policy_mgr
        self.ces_params                 = ces_params
        self.cetp_security              = cetp_security
        self.pending_tasks              = []                     # oCESC2CLayer specific
        self.initiated_transports       = []
        self.connected_transports       = []
        self.remote_ces_eps             = []                     # Registers ip, port, and protocol info of remote ep.
        self.transport_c2c_binding      = {}
        self.c2c_transaction_list       = []
        self.transport_rtt              = {}
        self.transport_lastseen         = {}
        self.c2c_negotiated             = False
        self._closure_signal            = False
        self._logger                    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oCES2CESLayer)
        self._logger.info("Initiating outbound CES2CESLayer towards cesid '{}'".format(r_cesid) )
        self.initiate_cetp_transport(naptr_list)

    def add_naptr_records(self, naptr_rrs):
        try:
            for naptr_rr in naptr_rrs:
                dst_id, r_cesid, r_ip, r_port, r_transport = naptr_rr                   # Assumption: All NAPTRs point towards one 'r_cesid'.    (Destination domain is reachable via one CES only)
                if (r_ip, r_port, r_transport) not in self.remote_ces_eps:
                    self._logger.info(" Initiating a new CETPTransport")
                    if not self.remote_endpoint_malicious_history(r_cesid, r_ip):
                        asyncio.ensure_future(self.initiate_transport(r_transport, r_ip, r_port))

            return dst_id
        except Exception as ex:
            self._logger.warning("Exception in parsing the NAPTR records: '{}'".format(ex))
            return None
        
        
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
            return True

        except Exception as msg:
            self._logger.error(" Exception in pre-processing the received message.")
            return False
        
    
    def consume_transport_message(self, msg, transport):
        """ Consumes CETP messages queued by the CETP Transport. """
        try:
            if not self._pre_process(msg):
                return                        # For repeated non-CETP packets, shall we terminate the connection?
            
            cetp_msg = json.loads(msg)
            inbound_sst, inbound_dst = cetp_msg['SST'], cetp_msg['DST']
            sstag, dstag = inbound_dst, inbound_sst
            
            c2c_transaction = self.transport_c2c_binding[transport]
            c2c_transaction.update_last_seen()

            if not self.c2c_negotiated:
                self._logger.debug(" C2C-policy is not negotiated with remote-cesid '{}'".format(self.r_cesid))
                asyncio.ensure_future(self.process_c2c(cetp_msg, transport))
            else:
                if self.is_c2c_transaction(sstag, dstag):
                    asyncio.ensure_future(self.process_c2c(cetp_msg, transport))
                else:
                    self._logger.debug(" Forwarding packet to H2H-layer")
                    self.cetp_client.consume_message_from_c2c(cetp_msg, transport)
                    
        except Exception as ex:
            self._logger.info("Exception in consuming messages from CETP Transport: {}".format(ex))
            

    def is_c2c_transaction(self, sstag, dstag):
        """ Checks whether CETP message meets an ongoing or completed C2C Transaction initiated by this C2C layer """
        
        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if (c_sst == sstag) & (c_dst == dstag):
                self._logger.debug(" CETP message for a connected transaction ")        # For CES-to-CES feedback & keepalives etc.
                return True

        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if ( (c_sst == sstag) and (c_dst==0) and (dstag!=0) ):
                self._logger.debug(" CETP message for an ongoing C2CTransaction ")      # completed at iCES, but in-complete at oCES yet
                return True
            
        return False
    
    @asyncio.coroutine            
    def process_c2c(self, cetp_msg, transport):
        """ Calls corresponding C2CTransaction method, depending on whether its an ongoing or completed C2C Transaction. """
        inbound_sstag, inbound_dstag = cetp_msg['SST'], cetp_msg['DST']
        sstag, dstag    = inbound_dstag, inbound_sstag
        
        if self.cetpstate_mgr.has_initiated_transaction( (sstag, 0) ):
            self._logger.info(" Continue resolving c2c-transaction (SST={}, DST={})".format(sstag, 0))
            o_c2c = self.cetpstate_mgr.get_initiated_transaction( (sstag, 0) )
            result = o_c2c.continue_c2c_negotiation(cetp_msg, transport)
            (status, cetp_resp) = result
            
            if status == True:
                self.c2c_negotiated = True
                transport.report_c2c_negotiation(status)
                self.cetp_client.c2c_negotiation_status(status=True)
                
            elif status == False:
                if len(cetp_resp) > 0:  transport.send_cetp(cetp_resp)
                self._logger.debug(" Close the transport endpoint towards {}.".format(self.r_cesid))
                self.unregister_c2c_to_transport(transport)
                transport.close()
                
            elif status == None:
                if len(cetp_resp) > 0:
                    self._logger.info(" CES-to-CES is not negotiated yet.")
                    transport.send_cetp(cetp_resp)

        elif self.cetpstate_mgr.has_established_transaction( (sstag, dstag) ):
            self._logger.debug(" CETP for a negotiated transaction (SST={}, DST={})".format(sstag, dstag))
            o_c2c = self.cetpstate_mgr.get_established_transaction( (sstag, dstag) )
            o_c2c.post_c2c_negotiation(cetp_msg, transport)


    def initiate_c2c_transaction(self, transport_obj):
        """ Initiates/Continues CES-to-CES negotiation """
        c2c_transaction  = C2CTransaction.oC2CTransaction(self._loop, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetpstate_mgr=self.cetpstate_mgr, \
                                                           transport=transport_obj, policy_mgr=self.policy_mgr, proto=transport_obj.proto, ces_params=self.ces_params, \
                                                           cetp_security=self.cetp_security, c2c_layer=self)
        
        self.register_c2c_to_transport(c2c_transaction, transport_obj)
        self.c2c_transaction_list.append(c2c_transaction)
        cetp_resp = c2c_transaction.initiate_c2c_negotiation()
        
        if cetp_resp!=None:
            transport_obj.send_cetp(cetp_resp)


    """ Functions for managing transport-layer connectivity b/w CES nodes """ 
    def report_connectivity(self, transport_obj, status=True):
        if status == True:
            #if len(self.connected_transports)==0:
            #    self._logger.debug("Initiating task to consume messages from CETPTransport, on first connected transport.")
            #    self._initiate_task()
            self._logger.info(" CETP Transport is connected -> Exchange the CES-to-CES policies.")
            self.register_connected_transports(transport_obj)
            self.initiate_c2c_transaction(transport_obj)
        else:
            self._logger.info(" CETP Transport is disconnected.")
            self.unregister_transport(transport_obj)
            ip_addr, port = transport_obj.remotepeer
            proto = transport_obj.proto
            self.remote_ces_eps.remove((ip_addr, port, proto))

            if transport_obj in self.transport_c2c_binding:
                c2c_transaction = self.get_c2c_transaction(transport_obj)
                self.c2c_transaction_list.remove(c2c_transaction)
                c2c_transaction.set_terminated()
                del self.transport_c2c_binding[transport_obj]

            
    def register_connected_transports(self, transport):
        """ Registers the connected CETP Transport """
        self.connected_transports.append(transport)
        if transport in self.initiated_transports:
            self._logger.debug("Remove the connected transport from list of initiated transports.")            
            self.initiated_transports.remove(transport)
            
    def unregister_transport(self, transport):
        """ Unregisters the CETP Transport AND launches resource cleanup if all CETPtransport are down """
        if transport in self.connected_transports:
            self.connected_transports.remove(transport)
        
        if transport in self.initiated_transports:
            self._logger.debug(" Removes the transport from list of initiated transport connections, when connectivity fails")
            self.initiated_transports.remove(transport)
        
        if (len(self.initiated_transports) ==0) & (len(self.connected_transports) ==0):
            self._logger.info(" No ongoing or in-progress CETP transport towards {}".format(self.r_cesid))
            self._logger.info(" Close CETP-C2C and CETPClient layer")
            self.resource_cleanup()

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
                self._logger.info("All the links have bad health ")
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
            selected = None
            for transport in self.connected_transports:
                oc2c = self.get_c2c_transaction(transport)
                if oc2c.health_report:
                    selected = transport
                    return selected
                
            if selected == None:
                self._logger.info("All the links have bad health ")
                # TBD:  Case where all transports have bad health           # What to do?

        elif len(self.transport_rtt) == len(self.connected_transports):
            return self.active_transport

        
    def cancel_pending_tasks(self):
        for tsk in self.pending_tasks:
            if not tsk.cancelled():
                self._logger.debug("Canceling the pending task")
                tsk.cancel()
        
    def handle_interrupt(self):
        self.set_closure_signal()
        self.cancel_pending_tasks()
    
    def resource_cleanup(self):
        """ Cancels the pending tasks and deletes the object """
        self.handle_interrupt()
        self.cetp_client.resource_cleanup()
        del(self)
        
    def set_closure_signal(self):
        self._closure_signal = True
           
    def register_c2c_to_transport(self, c2c_transaction, transport):
        self.transport_c2c_binding[transport] = c2c_transaction
    
    def unregister_c2c_to_transport(self, transport):
        del self.transport_c2c_binding[transport]
    
    def get_c2c_transaction(self, transport):
        return self.transport_c2c_binding[transport]

    def remote_endpoint_malicious_history(self, r_cesid, ip_addr):
        """ Dummy function, emulating the check that if 'cesid'  or the 'ip-address' has previous history of misbehavior """
        return False

    def send_cetp(self, msg):
        transport = self.select_transport()
        transport.send_cetp(msg)

    def initiate_cetp_transport(self, naptr_list):
        """ Intiates CETP Transports towards remote endpoints (for each 'naptr' record in the naptr_list) """
        for naptr_rec in naptr_list:
            dst_id, r_cesid, ip_addr, port, proto = naptr_rec
            if self.remote_endpoint_malicious_history(r_cesid, ip_addr):
                self._logger.info("CESID '{}' has history of misbehavior ".format(r_cesid))
                break
            else:
                asyncio.ensure_future(self.initiate_transport(proto, ip_addr, port))

    @asyncio.coroutine
    def initiate_transport(self, proto, ip_addr, port):
        """ Description """
        if proto == 'tcp' or proto=="tls":
            self._logger.info(" Initiating CETPTransport towards cesid '{}' @({}, {})".format(self.r_cesid, ip_addr, port))
            transport_instance = oCESTransportTCP(self, proto, self.r_cesid, self.ces_params, remote_addr=(ip_addr, port), loop=self._loop)
            
            if proto == "tls":
                self.ces_certificate_path   = self.ces_params['certificate']
                self.ces_privatekey_path    = self.ces_params['private_key']
                self.ca_certificate_path    = self.ces_params['ca_certificate']

                sc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sc.verify_mode = ssl.CERT_REQUIRED
                sc.load_cert_chain(self.ces_certificate_path, self.ces_privatekey_path)
                sc.load_verify_locations(self.ca_certificate_path)
                #sc.check_hostname = True
            
                try:
                    self.remote_ces_eps.append( (ip, port, proto) )
                    coro = self._loop.create_connection(lambda: transport_instance, ip_addr, port, ssl=sc)
                    self.initiated_transports.append(transport_instance)
                    yield from asyncio.ensure_future(coro)
                except Exception as ex:
                    self.remote_ces_eps.remove( (ip, port, proto) )
                    self._logger.info("Exception in {} transport towards {}: '{}'".format(proto, self.r_cesid, ex))                  # ex.errno == 111 -- means connection RST received
                    self.unregister_transport(transport_instance)

            elif proto == "tcp":
                try:
                    self.remote_ces_eps.append( (ip_addr, port, proto) )
                    coro = self._loop.create_connection(lambda: transport_instance, ip_addr, port)
                    self.initiated_transports.append(transport_instance)
                    connect_task = asyncio.ensure_future(coro)
                    yield from connect_task
                except Exception as ex:
                    self.remote_ces_eps.remove( (ip_addr, port, proto) )
                    self._logger.info("Exception in {} transport towards {}: '{}'".format(proto, self.r_cesid, ex))
                    self.unregister_transport(transport_instance)




class oCESTransportTCP(asyncio.Protocol):
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
        self.c2c_negotiation_threshold  = ces_params['max_c2c_negotiation_duration']           # In seconds
        self._logger.setLevel(LOGLEVEL_oCESTransportTCP)
        self._loop.call_later(self.c2c_negotiation_threshold, self.is_c2c_negotiated)

    def connection_made(self, transport):
        current_time = self._loop.time()
        time_lapsed  = current_time - self._start_time
        
        if (time_lapsed) > self.c2c_negotiation_threshold:
            self._logger.info(" CETPTransport connection established in > (To={})".format(str(self.c2c_negotiation_threshold)))
            self.close()
        else:
            self.transport = transport
            self.peername = transport.get_extra_info('peername')
            self._logger.info('Connected to {}'.format(self.peername))
            self.is_connected = True
            self.ces_layer.report_connectivity(self)                 # Reporting the connectivity to upper layer.
            
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
        len_bytes = (msg_length).to_bytes(CETP_MSG_LEN_FIELD, byteorder="big")
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
            if len(self.data_buffer) < CETP_MSG_LEN_FIELD:
                break
            
            len_field = self.data_buffer[0:CETP_MSG_LEN_FIELD]                                      # Reading length field in buffered data
            msg_length = int.from_bytes(len_field, byteorder='big')
                        
            if len(self.data_buffer) >= (CETP_MSG_LEN_FIELD + msg_length):
                cetp_data = self.data_buffer[CETP_MSG_LEN_FIELD:CETP_MSG_LEN_FIELD+msg_length]
                self.data_buffer = self.data_buffer[CETP_MSG_LEN_FIELD+msg_length:]                 # Moving ahead in the buffered data
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

