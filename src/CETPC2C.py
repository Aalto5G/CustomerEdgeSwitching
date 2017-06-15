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
import CETPH2H
import CETPTransports

LOGLEVEL_CETPC2CLayer          = logging.INFO

class CETPC2CLayer:
    """
    For outbound C2C:
        Instantiates client CETP Transports towards remote CES, based on the NAPTR records.
        Manages, registers/unregisters the CETP Transports, AND performs resource cleanup on CES-to-CES connectivity loss.
        Timely negotiation of the CES-to-CES policies, AND forwards C2C-level CETP message to corresponding C2CTransaction, in post-c2c-negotiation phase.
        After CES-to-CES is negotiated, it forwards H2H-CETP Transactions to/from the upper layer. 
        Management of CETPTransport failover, seemless to H2H-layer.
    """
    def __init__(self, loop, naptr_list=[], cetp_h2h=None, l_cesid=None, r_cesid=None, cetpstate_mgr=None, policy_mgr=None, policy_client=None, ces_params=None, \
                 cetp_security=None, cetp_mgr=None, name="CETPC2CLayer"):
        self._loop                      = loop
        self.naptr_list                 = naptr_list
        self.cetp_h2h                   = cetp_h2h               # H2H layer manager for remote-cesid 
        self.l_cesid                    = l_cesid
        self.r_cesid                    = r_cesid
        self.cetpstate_mgr              = cetpstate_mgr
        self.policy_client              = policy_client
        self.policy_mgr                 = policy_mgr
        self.ces_params                 = ces_params
        self.cetp_security              = cetp_security
        self.cetp_mgr                   = cetp_mgr
        self.q                          = asyncio.Queue()        # Enqueues the messages from CETP Transport
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
        self.active_transport           = None
        self._logger                    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPC2CLayer)
        self._logger.info("Initiating outbound CES2CESLayer towards cesid '{}'".format(r_cesid) )

    def add_naptr_records(self, naptr_rrs):
        try:
            for naptr_rr in naptr_rrs:
                dst_id, r_cesid, r_ip, r_port, r_transport = naptr_rr                   # Assumption: All NAPTRs point towards one 'r_cesid'.    (Destination domain is reachable via one CES only)
                if (r_ip, r_port, r_transport) not in self.remote_ces_eps:
                    self._logger.info(" Initiating a new CETPTransport")
                    if not self.remote_endpoint_malicious_history(r_cesid, r_ip):
                        asyncio.ensure_future(self.initiate_transport(r_transport, r_ip, r_port, delay=0.1))        # Delay parameter prevents H2H negotiation from suffering delay due to triggering of transport/C2C-negotiation
                        
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
                self._logger.error(" Session tag values are invalid")
                return False
            
            if ver!=1:
                self._logger.info(" CETP version is not supported.")
                return False
            
            return (sstag, dstag, cetp_msg)

        except Exception as ex:
            self._logger.error(" Exception '{}' in pre-processing the received message.".format(ex))
            return False
        
    
    def consume_transport_message(self, msg, transport):
        """ Consumes CETP messages queued by the CETP Transport. """
        try:
            outcome = self._pre_process(msg)
            if not outcome:     return                        # For repeated non-CETP packets, shall we terminate the connection?
            sstag, dstag, cetp_msg = outcome
            self.update_transport(transport)

            if not self.c2c_negotiated:
                self._logger.debug(" C2C-policy is not negotiated with remote CES '{}'".format(self.r_cesid))
                self.process_c2c(sstag, dstag, cetp_msg, transport)
            else:
                if self.is_c2c_transaction(sstag, dstag):
                    self._logger.debug(" Inbound packet belongs to a C2C transaction.")
                    self.process_c2c(sstag, dstag, cetp_msg, transport)
                else:
                    self.forward_h2h(cetp_msg, transport)                       # Forwarding packet to H2H-layer
                    
        except Exception as ex:
            self._logger.info("Exception in consuming messages from CETP Transport: {}".format(ex))
            

    def forward_h2h(self, cetp_msg, transport):
        self.cetp_h2h.consume_message_from_c2c(cetp_msg, transport)
        
    def is_c2c_transaction(self, sstag, dstag):
        """ Determines whether CETP message belongs to an ongoing or completed C2C Transaction of this C2C layer 
        """
        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if (c_sst == sstag) & (c_dst == dstag):                                 # CETP message on a connected transaction, i.e. for C2C feedback & keepalive etc.
                return True                                                         # TBD - searching in a list of C2CTransaction, than an iterating for loop.

        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if ( (c_sst == sstag) and (c_dst==0) and (dstag!=0) ):                  # Ongoing C2CTransaction - completed at iCES, but still in-complete at oCES
                return True
        return False

    
    def process_c2c(self, sstag, dstag, cetp_msg, transport):
        """ Calls corresponding C2CTransaction method, depending on whether its an ongoing or completed C2C Transaction. """
        
        # For safety: # To improve: Don't check this if len(connected_transports)==len(c2c_transaction_list) - to prevent opening an H2HTransaction as C2CTransaction.
        if self.cetpstate_mgr.has_initiated_transaction( (sstag, 0) ):
            self._logger.info(" Continue resolving c2c-transaction (SST={}, DST={})".format(sstag, 0))
            o_c2c = self.cetpstate_mgr.get_initiated_transaction( (sstag, 0) )
            result = o_c2c.continue_c2c_negotiation(cetp_msg, transport)
            (status, cetp_resp) = result
            
            if status == True:
                self.c2c_negotiated = True
                transport.report_c2c_negotiation(status)
                self.cetp_h2h.c2c_negotiation_status(status=True)
                
            elif status == False:
                if len(cetp_resp) > 0:  transport.send_cetp(cetp_resp)
                self._logger.debug(" Close the transport endpoint towards {}.".format(self.r_cesid))
                self.unregister_c2c_transport(transport)
                transport.close()
                
            elif status == None:
                if len(cetp_resp) > 0:
                    self._logger.info(" CES-to-CES is not negotiated yet.")
                    transport.send_cetp(cetp_resp)

        elif self.cetpstate_mgr.has_established_transaction( (sstag, dstag) ):
            self._logger.debug(" CETP for a negotiated C2C transaction (SST={}, DST={})".format(sstag, dstag))
            o_c2c = self.cetpstate_mgr.get_established_transaction( (sstag, dstag) )
            o_c2c.post_c2c_negotiation(cetp_msg, transport)


    def update_transport(self, transport):
        c2c_transaction = self.get_c2c_transaction(transport)
        c2c_transaction.update_last_seen()
        
    def report_evidence(self, h_sstag, h_dstag, r_hostid, r_cesid, misbehavior_evidence):
        """ Reports misbehavior evidence observed in (h_sstag, h_dstag) to the remote CES """
        trans = self.select_transport()                             # Check to ensure that message is sent on a (recently) active transport connection
        c2c_transaction = self.get_c2c_transaction(trans)
        c2c_transaction.report_misbehavior_evidence(h_sstag, h_dstag, r_hostid, misbehavior_evidence)
        self.cetp_security.record_misbehavior_evidence(r_cesid, r_hostid, misbehavior_evidence)

    @asyncio.coroutine
    def initiate_c2c_transaction(self, transport_obj):
        """ Initiates/Continues CES-to-CES negotiation """
        c2c_transaction  = C2CTransaction.oC2CTransaction(self._loop, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetpstate_mgr=self.cetpstate_mgr, transport=transport_obj, \
                                                          policy_mgr=self.policy_mgr, proto=transport_obj.proto, ces_params=self.ces_params, cetp_security=self.cetp_security, c2c_layer=self)
        self._add_c2c_transport_binding(c2c_transaction, transport_obj)
        self._add_c2c_transactions(c2c_transaction)
        cetp_resp = yield from c2c_transaction.initiate_c2c_negotiation()          # Shall be a coroutine.
        
        if cetp_resp!=None:
            transport_obj.send_cetp(cetp_resp)
        
    
    def report_connectivity(self, transport, status=True):
        """ Triggers next function (on transport connection success) OR resouce-cleanup (on transport connection termination) """ 
        if status == True:
            self._logger.debug(" CETP Transport is connected -> Exchange C2C policies.")
            self.register_connected_transports(transport)
            asyncio.ensure_future(self.initiate_c2c_transaction(transport))
        else:
            self._logger.info(" CETP Transport is disconnected.")
            self.unregister_c2c_transport(transport)
            self.unregister_transport(transport)

    def _add_connected_transport(self, transport):
        self.connected_transports.append(transport)
        
    def _remove_connected_transport(self, transport):
        if transport in self.connected_transports:
            self.connected_transports.remove(transport)
            
    def register_connected_transports(self, transport):
        """ Registers the connected CETP Transport """
        self._add_connected_transport(transport)
        if transport in self.initiated_transports:
            self.initiated_transports.remove(transport)                     # Removing the connected transport from list of initiated transports.
            
    def unregister_transport(self, transport):
        """ Unregisters the CETP Transport AND launches resource cleanup if all CETPtransport are down """
        (ip_addr, port), proto = transport.remotepeer, transport.proto
        key = (ip_addr, port, proto)
        if key in self.remote_ces_eps:
            self.remote_ces_eps.remove((ip_addr, port, proto))

        self._remove_connected_transport(transport)                         # Removing the transport from list of connected transports
        if transport in self.initiated_transports:
            self.initiated_transports.remove(transport)                     # Removing the transport from list of initiated transports
        
        if (len(self.initiated_transports) ==0) & (len(self.connected_transports) ==0):
            self._logger.info(" No ongoing or in-progress CETP transport -- Close CETP-H2H and C2C layer towards {}".format(self.r_cesid))
            self.cetp_mgr.remove_c2c_layer(self.r_cesid)
            self.cetp_mgr.remove_cetp_endpoint(self.r_cesid)
            self.resource_cleanup()

    def _add_c2c_transactions(self, c2c_transaction):
        self.c2c_transaction_list.append(c2c_transaction)
    
    def _remove_c2c_transactions(self, c2c_transaction):
        if c2c_transaction in self.c2c_transaction_list:
            self.c2c_transaction_list.remove(c2c_transaction)
        
    def _add_c2c_transport_binding(self, c2c_transaction, transport):
        self.transport_c2c_binding[transport] = c2c_transaction
    
    def _remove_c2c_transport_binding(self, transport):
        if transport in self.transport_c2c_binding:
            del self.transport_c2c_binding[transport]
        
    def get_c2c_transaction(self, transport):
        if transport in self.transport_c2c_binding:
            return self.transport_c2c_binding[transport]

    def register_c2c_transport(self, transport, c2c_transaction):
        """ Registers the C2C-Transaction established on a CETPTransport, AND their binding """
        self._add_c2c_transactions(c2c_transaction)
        self._add_connected_transport(transport)
        self._add_c2c_transport_binding(c2c_transaction, transport)
        (ip_addr, port), proto = transport.remotepeer, transport.proto
        self.remote_ces_eps.append( (ip_addr, port, proto))
        
    def unregister_c2c_transport(self, transport):
        """ Removes the C2C-Transaction established on a CETPTransport, AND their binding """
        if transport in self.transport_c2c_binding:
            c2c_transaction = self.get_c2c_transaction(transport)
            self._remove_c2c_transactions(c2c_transaction)
            self._remove_connected_transport(transport)
            self._remove_c2c_transport_binding(transport)
            (ip_addr, port), proto = transport.remotepeer, transport.proto
            self.remote_ces_eps.append( (ip_addr, port, proto))
            c2c_transaction.set_terminated()                            # To terminate the tasks scheduled within c2c-transaction.

    def set_closure_signal(self):
        self._closure_signal = True
        
    def resource_cleanup(self):
        """ Cancels the pending tasks and deletes the object """
        self.handle_interrupt()
        self.cetp_h2h.resource_cleanup()
        del(self)

    def handle_interrupt(self):
        self.set_closure_signal()
        self.cetp_h2h.set_closure_signal()
        self.cancel_pending_tasks()

    def cancel_pending_tasks(self):
        """ Terminates asyncio-tasks in c2c-layer towards remote CES """
        for tsk in self.pending_tasks:
            if not tsk.cancelled():
                self._logger.info("Terminating asyncio-task in c2c-layer towards remote CES '{}'".format(self.r_cesid))            
                tsk.cancel()
    
    def trigger_cetp_h2h(self, cetp_h2h):
        """ Creates the CETP-H2H layer """
        self.cetp_h2h = cetp_h2h
        t1=asyncio.ensure_future(self.cetp_h2h.consume_h2h_requests())                       # For consuming DNS NAPTR-responses triggered by private hosts
        self.pending_tasks.append(t1)

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
    def initiate_transport(self, proto, ip_addr, port, delay=0):
        """ Description """
        if proto == 'tcp' or proto=="tls":
            self._logger.info(" Initiating CETPTransport towards cesid '{}' @({}, {})".format(self.r_cesid, ip_addr, port))
            transport_instance = CETPTransports.oCESTCPTransport(self, proto, self.r_cesid, self.ces_params, remote_addr=(ip_addr, port), loop=self._loop)
            yield from asyncio.sleep(delay)
            
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
                    self.remote_ces_eps.append( (ip_addr, port, proto) )
                    coro = self._loop.create_connection(lambda: transport_instance, ip_addr, port, ssl=sc)
                    self.initiated_transports.append(transport_instance)
                    yield from asyncio.ensure_future(coro)
                except Exception as ex:
                    self.remote_ces_eps.remove( (ip_addr, port, proto) )
                    self._logger.info(" Exception in {} transport towards {}: '{}'".format(proto, self.r_cesid, ex))                  # ex.errno == 111 -- means connection RST received
                    self.unregister_transport(transport_instance)

            elif proto == "tcp":
                try:
                    self.remote_ces_eps.append( (ip_addr, port, proto) )
                    coro = self._loop.create_connection(lambda: transport_instance, ip_addr, port)
                    self.initiated_transports.append(transport_instance)
                    connect_task = asyncio.ensure_future(coro)
                    yield from connect_task
                except Exception as ex:
                    self._logger.info(" Exception in {} transport towards {}: '{}'".format(proto, self.r_cesid, ex))
                    self.unregister_transport(transport_instance)



    def remote_endpoint_malicious_history(self, r_cesid, ip_addr):
        """ Function emulating the check whether 'r_cesid' & 'ip-address' have history of misbehavior """
        return False

    def send_cetp(self, msg):
        transport = self.select_transport()
        if transport!=None:
            transport.send_cetp(msg)

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

