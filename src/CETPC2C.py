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

LOGLEVEL_oCES2CESLayer          = logging.INFO
LOGLEVEL_iCETPC2CLayer          = logging.INFO


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




class iCETPC2CLayer:
    def __init__(self, loop, r_cesid="", cetp_mgr=None, name="iCETPC2CLayer"):
        self._loop                  = loop
        self.q                      = asyncio.Queue()               # Enqueues the messages from CETP Transport
        self.connected_transports   = []                            # To manage the connected CETP Transports
        self.c2c_transaction_list   = []
        self.pending_tasks          = []                            # iCETPC2CLayer specific
        self.r_cesid                = r_cesid
        self.cetp_mgr               = cetp_mgr
        self.transport_c2c_binding  = {}
        self.transport_rtt          = {}        
        self._closure_signal        = False
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iCETPC2CLayer)

    def register_transport_c2cTransaction(self, transport, c2c_transaction):
        """ Registers the stateful-inbound c2c-transaction, connected transport, AND their relation """
        self.transport_c2c_binding[transport] = c2c_transaction
        self.add_c2c_transactions(c2c_transaction)
        self.add_connected_transport(transport)

    def add_c2c_transactions(self, c2c_cetp_transaction):
        self.c2c_transaction_list.append(c2c_cetp_transaction)
    
    def remove_c2c_transactions(self, c2c_cetp_transaction):
        self.c2c_transaction_list.remove(c2c_cetp_transaction)

    def add_connected_transport(self, transport):
        self.connected_transports.append(transport)
        
    def remove_connected_transport(self, transport):
        if transport in self.connected_transports:
            self.connected_transports.remove(transport)
            
    def create_cetp_h2h(self, r_cesid, policy_mgr, cetpstate_mgr, l_cesid, ces_params, cetp_security, host_reg):
        """ Creating the upper layer to handle CETPTransport """
        self.h2h = CETPH2H.CETPH2H(c2c_layer=self, l_cesid=l_cesid, r_cesid=r_cesid, policy_mgr=policy_mgr, cetpstate_mgr=cetpstate_mgr, c2c_negotiated=True, \
                                   host_register=host_reg, loop=self._loop, cetp_mgr=self.cetp_mgr, ces_params=ces_params, cetp_security=cetp_security)
        
        self.cetp_mgr.add_client_endpoint(r_cesid, self.h2h)
        t1=asyncio.ensure_future(self.h2h.consume_h2h_requests())                       # For consuming DNS NAPTR-responses triggered by private hosts
        self.pending_tasks.append(t1)
        return self.h2h
    
    def cancel_pending_tasks(self):
        self._logger.info("Terminating pending tasks for cesid '{}'".format(self.r_cesid))
        for tsk in self.pending_tasks:
            if not tsk.cancelled():
                tsk.cancel()

    def handle_interrupt(self):
        self._closure_signal = True
        self.h2h.set_closure_signal()
        self.cancel_pending_tasks()
        
    def add_naptr_records(self, naptr_rrs):
        try:
            for naptr_rr in naptr_rrs:
                dst_id, r_cesid, r_ip, r_port, r_transport = naptr_rr                   # Assumption: All NAPTRs point towards one 'r_cesid'.    (Destination domain is reachable via one CES only)
                """
                if (r_ip, r_port, r_transport) not in self.remote_ces_eps:
                    self._logger.info(" Initiating a new CETPTransport")
                    if not self.remote_endpoint_malicious_history(r_cesid, r_ip):
                        asyncio.ensure_future(self.initiate_transport(r_transport, r_ip, r_port))
                """
            return dst_id
        except Exception as ex:
            self._logger.warning("Exception in parsing the NAPTR records: '{}'".format(ex))
            return None

    
    def report_connection_closure(self, transport):
        """ Removes connected client & checks for C2C-level connectivity """
        ic2c_transaction = self.transport_c2c_binding[transport]
        ic2c_transaction.set_terminated()                              # To terminate the tasks scheduled within c2c-transaction.
        self.remove_c2c_transactions(ic2c_transaction)
        self.remove_connected_transport(transport)
        del self.transport_c2c_binding[transport]
        
        if len(self.connected_transports) ==0:
            self._logger.info("No connected transport with remote CES '{}'".format(self.r_cesid))
            self.cetp_mgr.delete_c2c_layer(self.r_cesid)                   # Remove the c2c-layer registered to 'r_cesid'
            self.cetp_mgr.remove_client_endpoint(self.r_cesid)
            self.handle_interrupt()
            
            self._logger.info("Terminating inbound C2C-Layer and CETPServer for cesid '{}'".format(self.r_cesid))
            del(self.h2h)                                               # CETPServer's task is already deleted
            del(self)
                
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
            for transport in self.connected_transports:
                oc2c = self.get_c2c_transaction(transport)
                if oc2c.health_report:
                    return transport
                # TBD:  Case where all transports have bad health           # How to detect? and What to do?

        elif len(self.transport_rtt) == len(self.connected_transports):
            return self.active_transport
    
    def send_cetp(self, msg):
        """ Useful when initiating a (feedback/evidence/keepalive) message towards oCES """
        for transport in self.connected_transports:
            transport.send_cetp(msg)

    def consume_transport_message(self, msg, transport):
        try:
            if not self._pre_process(msg):
                return
                
            #self._logger.debug("data: {!r}".format(msg))
            #self._logger.debug("cetp_msg: {!r}".format(cetp_msg))
            cetp_msg = json.loads(msg)
            inbound_sst, inbound_dst = cetp_msg['SST'], cetp_msg['DST']
            sst, dst = inbound_dst, inbound_sst
            
            c2c_transaction = self.transport_c2c_binding[transport]
            c2c_transaction.update_last_seen()


            if self.is_c2c_transaction(sst, dst):
                self._logger.debug(" Inbound packet belongs to an established C2C transaction.")
                self.process_c2c(cetp_msg, transport)
            else:
                self._logger.debug(" Forward the packet to H2H-layer")
                self.forward_h2h(cetp_msg, transport)
        
        except Exception as ex:
            self._logger.info(" Exception in consuming Transport message: {}".format(ex))

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

        except Exception as msg:
            self._logger.error(" Exception in pre-processing the received message.")
            return False
        return True

    
    def is_c2c_transaction(self, sst, dst):
        """ Checks if (SST, DST) of the inbound CETP-message belongs to a C2C-transaction """
        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if (c_sst == sst) & (c_dst == dst):
                return True
        return False

    def forward_h2h(self, cetp_msg, transport):
        self.h2h.consume_message_from_c2c(cetp_msg, transport)
            
    def process_c2c(self, cetp_msg, transport):
        """ Processes C2C-CETP flow in post-c2c negotiation phase """
        c2c_transaction = None
        sst, dst = cetp_msg['DST'], cetp_msg['SST']
        for c2c_transaction in self.c2c_transaction_list:
            c_sst, c_dst = c2c_transaction.sstag, c2c_transaction.dstag
            if (c_sst == sst) & (c_dst == dst):
                ic2c_transaction = c2c_transaction
                break
        
        ic2c_transaction.post_c2c_negotiation(cetp_msg, transport)                  # Shall have logic for security, remote CES feedback, evidence collection etc.


    def feedback(self):
        """ Dummy method: simulating the methods used for reporting a host, or enforcing ratelimits to remote CES """
        pass

