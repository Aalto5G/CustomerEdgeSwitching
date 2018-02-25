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
import copy
import traceback
import cetpManager
import C2CTransaction
import H2HTransaction
import CETPH2H
import CETPTransports

LOGLEVEL_CETPC2CLayer          = logging.INFO

class CETPC2CLayer:
    """
    Initiates socket transports towards remote CES, based on the NAPTR records. -- Registers the reachable and unreachable transports endpoints.
    Ensures timely negotiation of the CES-to-CES policies with transport of remote CES.
    Manages the Transport failover seamlessly to H2H-layer. AND prevents reconnects to unresponsive end points.
    Forwards CETP message to H2H layer or corresponding C2CTransaction, in the post-c2c-negotiation phase.
    Performs resource cleanup upon 'Ctrl+C' or on CES-to-CES connectivity loss.
    Provides an API to forward messages to/from H2H Layer, once CES-to-CES is negotiated.
    """
    def __init__(self, loop, cetp_h2h=None, l_cesid=None, r_cesid=None, cetpstate_mgr=None, policy_mgr=None, policy_client=None, ces_params=None, \
                 cetp_security=None, cetp_mgr=None, conn_table=None, interfaces=None, name="CETPC2CLayer"):
        self._loop                      = loop
        self.cetp_h2h                   = cetp_h2h                          # H2H layer towards remote-cesid 
        self.l_cesid                    = l_cesid
        self.r_cesid                    = r_cesid
        self.cetpstate_mgr              = cetpstate_mgr
        self.policy_client              = policy_client
        self.policy_mgr                 = policy_mgr
        self.ces_params                 = ces_params
        self.cetp_security              = cetp_security
        self.cetp_mgr                   = cetp_mgr
        self.interfaces                 = interfaces
        self.conn_table                 = conn_table
        self.processed_rlocs            = []                                # Records (ip, port, protocol) values of RLOCs, to which an outbound connection is either initiated or connected.
        self.initiated_transports       = []                                # Records the transport instances initiated (but not connected) to a remote CES.
        self.connected_transports       = []                                # Records transport instances connected to/from a remote CES.
        self.c2c_connectivity           = False                             # Indicates the connectivity status b/w CES nodes
        self.c2c_transaction            = None
        self.c2c_initiated              = False
        self.c2c_negotiated             = False                             # Indicates whether c2c is successfully negotiated
        self._closure_signal            = False                             # To close CETP layering, either due to Ctrl+C interrupt or termination of C2C relation.
        self.active_transport           = None
        self.active_transport_cb        = None
        self._logger                    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPC2CLayer)
        self._logger.info("Initiating CETPC2CLayer towards cesid='{}'".format(r_cesid) )
        self._read_config()

    def _read_config(self):
        try:
            self.max_allowed_transports = self.ces_params["max_c2c_transports"]
            self.ces_certificate_path   = self.ces_params['certificate']
            self.ces_privatekey_path    = self.ces_params['private_key']
            self.ca_certificate_path    = self.ces_params['ca_certificate']
        except Exception as ex:
            self._logger.error("Exception '{}' in reading config file".format(ex))

    def process_naptrs(self, naptr_rrs):
        """ 
        Enforces limits, and prevents initiating a flood of transport connections to remote CES.
        New transport are triggered based on addressing in NAPTR records.
        """
        try:
            # Enforce limit on total no. of transport connection b/w CES nodes.
            allowed_transports = self.max_allowed_transports - len(self.connected_transports)
            if allowed_transports <= 0:
                return
            
            # Check if there are enough transport connections pending completion
            if len(self.processed_rlocs) > allowed_transports:
                return
            
            for naptr_rr in naptr_rrs:
                dst_id, r_cesid, r_ip, r_port, r_proto = naptr_rr
                
                # Checks that all NAPTRs point to same 'r_cesid'
                if r_cesid != self.r_cesid:
                    continue
                
                key = (r_ip, r_port, r_proto)
                if self._has_processed_rlocs(key):
                    continue

                if not self.is_unreachable_cetp_rloc(r_ip, r_port, r_proto):
                    self._add_processed_rlocs(key)
                    asyncio.ensure_future(self.initiate_transport(r_ip, r_port, r_proto))
                    allowed_transports -= 1
                    if allowed_transports == 0:
                        return
                
        except Exception as ex:
            self._logger.warning("Exception in processing the NAPTR records: '{}'".format(ex))
            return None
        
    def _add_processed_rlocs(self, key):
        self.processed_rlocs.append( key )

    def _remove_processed_rlocs(self, key):
        if self._has_processed_rlocs(key):
            self.processed_rlocs.remove( key )

    def _has_processed_rlocs(self, key):
        return key in self.processed_rlocs

    def get_c2c_transaction(self):
        return self.c2c_transaction
    
    def register_c2c(self, c2c_transaction):
        """ Registers the established C2C-Transaction """
        self.c2c_transaction = c2c_transaction
        
    def unregister_c2c(self):
        """ Terminates the tasks scheduled within C2C-transaction """
        if self.c2c_transaction is not None:
            self.c2c_transaction.set_terminated()
            del(self.c2c_transaction)
        
    def assign_cetp_h2h_layer(self, cetp_h2h):
        """ Assigns the CETP-H2H layer corresponding to this C2C layer """
        self.cetp_h2h = cetp_h2h
        
    def _update_connectivity_status(self):
        """ Activates the CETP-H2H layer upon completion of C2C negotiation with remote CES """
        if not self.is_connected() and self._is_c2c_negotiated():
            self.set_connectivity()
    
    def set_connectivity(self, status=True):
        """ Indicates presence of atleast one connected transport towards remote CES & Reports to H2H """
        self.c2c_connectivity = status
        self.report_connectivity_to_h2h(connected = status)

    def report_connectivity_to_h2h(self, connected=True):
        self.cetp_h2h.c2c_connectivity_report(connected=connected)
        
    def set_c2c_negotiation(self, status=True):
        """ Set the C2C negotiation status and updates it in Transport layer """
        self.c2c_negotiated = status
        self._set_c2c_transports(status)

    def _set_c2c_transports(self, status):
        """ Reports c2c_connectivity on all connected transport instances """
        for t in self.connected_transports:
            t.report_c2c_negotiation(status)
    
    def _is_c2c_negotiated(self):
        return self.c2c_negotiated

    def is_connected(self):
        """ Returns Boolean True/False, indicating presence/absence of a transport b/w CES nodes and successful C2C negotiation  """
        return self.c2c_connectivity

    def forward_h2h(self, cetp_msg):
        self.cetp_h2h.consume_message_from_c2c(cetp_msg)
            
    def _report_c2c_connectivity(self, transport, status):
        """ Reports c2c_connectivity to transport instance """
        transport.report_c2c_negotiation(status)

    def total_connected_transports(self):
        """ Returns total number of transports under this C2C Layer """
        return len(self.connected_transports)
    
    def total_inbound_transports(self):
        """ Returns total number of transports established by rces """
        n = self.total_connected_transports() - self.total_outbound_transports()
        return n
    
    def total_outbound_transports(self):
        """ Returns total number of transports established towards rces """
        cnt = 0
        for t in self.connected_transports:
            if t.name in ["oCESTransporttcp", "oCESTransporttls"]:
                cnt += 1
        return cnt

    """ CETP related processing """
    
    @asyncio.coroutine
    def initiate_c2c_transaction(self, transport):
        """ Initiates/Continues CES-to-CES negotiation """
        remote_addr, proto = transport.get_remotepeer(), transport.proto
        c2c_transaction  = C2CTransaction.oC2CTransaction(self._loop, l_cesid=self.l_cesid, r_cesid=self.r_cesid, cetpstate_mgr=self.cetpstate_mgr, remote_addr=remote_addr, \
                                                          policy_mgr=self.policy_mgr, proto=proto, ces_params=self.ces_params, cetp_security=self.cetp_security, \
                                                          interfaces=self.interfaces, c2c_layer=self, conn_table=self.conn_table, cetp_mgr=self.cetp_mgr)
        
        self.register_c2c(c2c_transaction)
        cetp_resp = yield from c2c_transaction.initiate_c2c_negotiation()
        if cetp_resp != None:
            cetp_packet = self._packetize(cetp_resp)
            transport.send_cetp(cetp_packet)
    
    
    def is_c2c_transaction(self, sstag, dstag):
        """ Determines whether CETP message belongs to an ongoing or completed C2C Transaction of this C2C layer """
        c_sstag, c_dstag = self.c2c_transaction.sstag, self.c2c_transaction.dstag
        if (c_sstag==sstag) and (c_dstag==dstag): 
            return True
        if (c_sstag==sstag) and (c_dstag==0) and (dstag!=0):                        # Ongoing C2CTransaction - completed at iCES, but still in-complete at oCES
            return True
        return False

    def _packetize(self, cetp_msg):
        return json.dumps(cetp_msg)
    
    def _depacketize(self, packet):
        return json.loads(packet)
    
    def _pre_process(self, packet):
        """ Checks whether inbound message conforms to CETP packet format. """
        try:
            cetp_msg = self._depacketize(packet)
            inbound_sstag, inbound_dstag, ver = cetp_msg['SST'], cetp_msg['DST'], cetp_msg['VER']
            sstag, dstag    = inbound_dstag, inbound_sstag
            supported_version = self.ces_params["CETPVersion"]
            
            if ver != supported_version:
                self._logger.error(" CETP Version {} is not supported.".format(ver))
                return False

            if ( (sstag==0) and (dstag ==0)) or (sstag < 0) or (dstag < 0):
                self._logger.error(" Session tag values are invalid")
                return False
            
            return (sstag, dstag, cetp_msg)

        except Exception as ex:
            self._logger.error(" Exception '{}' in pre-processing the received message.".format(ex))
            return False
        
    
    def consume_transport_message(self, packet, transport):
        """ Consumes CETP messages from transport. """
        try:
            outcome = self._pre_process(packet)
            if not outcome:     return                        # For repeated non-CETP packets, shall we terminate the connection?
            sstag, dstag, cetp_msg = outcome
            
            if not self.is_connected():
                self._logger.debug(" C2C policy is not negotiated with remote CES '{}'".format(self.r_cesid))
                self.process_c2c(sstag, dstag, cetp_msg, transport)

            else:
                if self.is_c2c_transaction(sstag, dstag):
                    self._logger.debug(" Inbound packet belongs to a C2C transaction.")
                    self.process_c2c(sstag, dstag, cetp_msg, transport)
                else:
                    self.forward_h2h(cetp_msg)                       # Forwarding packet to H2H-layer
                    
        except Exception as ex:
            self._logger.info("Exception in consuming messages from CETP Transport: {}".format(ex))
            traceback.print_exc(file=sys.stdout)
            
    
    def process_c2c(self, sstag, dstag, cetp_msg, transport):
        """ Calls corresponding C2CTransaction method, depending on whether its an ongoing or completed C2C Transaction. """
        
        if self.cetpstate_mgr.has(H2HTransaction.KEY_ESTABLISHED_TAGS, (sstag, dstag) ):
            self._logger.debug(" CETP for a negotiated C2C transaction (SST={}, DST={})".format(sstag, dstag))
            o_c2c = self.cetpstate_mgr.get(H2HTransaction.KEY_ESTABLISHED_TAGS, (sstag, dstag) )
            o_c2c.post_c2c_negotiation(cetp_msg, transport)
                
        elif self.cetpstate_mgr.has(H2HTransaction.KEY_INITIATED_TAGS, (sstag, 0) ):
            self._logger.info(" Continue resolving c2c-transaction (SST={}, DST={})".format(sstag, 0))
            o_c2c   = self.cetpstate_mgr.get(H2HTransaction.KEY_INITIATED_TAGS, (sstag, 0) )
            result  = o_c2c.continue_c2c_negotiation(cetp_msg)
            (status, cetp_resp) = result
            
            if status == True:
                self.set_c2c_negotiation()
                self._update_connectivity_status()
            
            elif status == False:
                if len(cetp_resp) > 0:
                    cetp_packet = self._packetize(cetp_resp)
                    transport.send_cetp(cetp_packet)
                    
                for t in self.connected_transports:
                    (r_ip, r_port), proto = t.remotepeer, t.proto
                    self.register_unreachable_cetp_addr(r_ip, r_port, proto)
                    
                self.unregister_c2c()
                self._logger.debug(" Close all transports towards {}.".format(self.r_cesid))
                self._close_all_initiated_transports()
                self._close_all_connected_transports()
                
            elif status == None:
                if len(cetp_resp) > 0:
                    self._logger.info(" CES-to-CES towards <{}> is not negotiated yet.".format(self.r_cesid))
                    cetp_packet = self._packetize(cetp_resp)
                    transport.send_cetp(cetp_packet)


    """  ***************    ***************    ***************    *************** ************
    ******  Functions handling transport-layer connection establishment (& termination) *****
    ***************    ***************  ***************  ******************* ************* """
    
    @asyncio.coroutine
    def initiate_transport(self, ip_addr, port, proto):
        """ Initiates CP-transport towards remote CES at (ip_addr, port) """
        if proto == 'tcp' or proto=="tls":
            triggered_at = time.time()
            self._logger.info(" Initiating a '{}' transport towards cesid='{}' @({}:{})".format(proto, self.r_cesid, ip_addr, port))
            t = CETPTransports.oCESTCPTransport(self, proto, self.r_cesid, self.ces_params, remote_addr=(ip_addr, port), loop=self._loop)
            timeout = self.ces_params["c2c_establishment_t0"]
            
            if proto == "tcp":
                coro = self._loop.create_connection(lambda: t, ip_addr, port)
                
            elif proto == "tls":
                sc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                sc.check_hostname = False
                #sc.verify_mode = ssl.CERT_NONE
                sc.verify_mode = ssl.CERT_REQUIRED
                sc.load_verify_locations(self.ca_certificate_path)
                sc.load_cert_chain(self.ces_certificate_path, self.ces_privatekey_path)
                coro = self._loop.create_connection(lambda: t, ip_addr, port, ssl=sc)
            
            try:
                self._add_initiated_transport(t)
                connect_task = asyncio.ensure_future(coro)
                yield from asyncio.wait_for(connect_task, timeout)
                
                connection_time = time.time() - triggered_at
                c2c_timeout = timeout - connection_time
                self._loop.call_later(c2c_timeout, self._c2cNegotiationCheckCb, t, ip_addr, port, proto, timeout)

            except Exception as ex:
                self._logger.error(" Exception '{}' in '{}' transport towards '{}'".format(ex, proto, self.r_cesid))                  # ex.errno == 111 -- means connection RST received
                self.unregister_transport(t)
                self.register_unreachable_cetp_addr(ip_addr, port, proto)


    def _c2cNegotiationCheckCb(self, transport, ip_addr, port, proto, timeout):
        """ Callback to close transport towards remote CES, if C2C-negotiation doesn't complete in 'To' """
        try:
            if transport.is_connected and (transport.c2c_negotiated == False):
                self._logger.error(" C2C policies to '{}' are not negotiated in To='{}' sec @ {}:{}".format(self.r_cesid, timeout, ip_addr, port))
                self.register_unreachable_cetp_addr(ip_addr, port, proto)        
                transport.close()
        except Exception as ex:
            self._logger.error(ex)

    def register_unreachable_cetp_addr(self, ip_addr, port, proto):
        self.cetp_security.register_unreachable_cetp_addr(ip_addr, port, proto)
    
    def is_unreachable_cetp_rloc(self, ip_addr, port, proto):
        return self.cetp_security.is_unreachable_cetp(ip_addr, port, proto)    
        
    def report_connectivity(self, transport, status=True):
        """ Called by transport layer: On connection success (to trigger C2C negotiation); AND on transport failure (for resouce-cleanup) """ 
        if status == True:
            self._logger.info(" CETP Transport is connected {}".format(transport.get_remotepeer()))
            self.register_connected_transport(transport)

            if self.c2c_transaction is None:
                if self.c2c_initiated is False:
                    self._logger.info(" Initiating C2C negotiation towards '{}'".format(self.r_cesid))
                    asyncio.ensure_future(self.initiate_c2c_transaction(transport))
                    self.c2c_initiated = True
            
            if self._is_c2c_negotiated():
                self._report_c2c_connectivity(transport, self._is_c2c_negotiated())
        else:
            self._logger.info(" CETP Transport is disconnected.")
            self.unregister_transport(transport)

    def _add_initiated_transport(self, transport):
        self.initiated_transports.append(transport)
            
    def _remove_initiated_transport(self, transport):
        if transport in self.initiated_transports:
            self.initiated_transports.remove(transport)

    def _close_all_initiated_transports(self):
        while len(self.connected_transports)>0:
            t = self.connected_transports[0]
            t.close()
        
    def _add_connected_transport(self, transport):
        self.connected_transports.append(transport)
        
    def _remove_connected_transport(self, transport):
        if transport in self.connected_transports:
            self.connected_transports.remove(transport)

    def _close_all_connected_transports(self):
        while len(self.connected_transports)>0:
            t = self.connected_transports[0]
            t.close()

    def register_connected_transport(self, transport):
        """ Registers the connected CETP Transport """
        self._remove_initiated_transport(transport)
        self._add_connected_transport(transport)
        self._logger.debug("Number of connected transports: {}".format(len(self.connected_transports)))
        self._update_connectivity_status()
        
    def unregister_transport(self, transport):
        """ Unregisters the CETP Transport AND launches resource cleanup if all CETPtransport are down """
        (ip_addr, port), proto = transport.remotepeer, transport.proto
        self._remove_processed_rlocs( (ip_addr, port, proto) )
        
        # Removing the transport from list of initiated/connected transports
        self._remove_connected_transport(transport)
        self._remove_initiated_transport(transport)
        
        if len(self.connected_transports)==0:
            if self.is_connected():
                self.set_connectivity(status=False)

            if len(self.initiated_transports)==0:
                self._logger.info(" No initiated/connected transport towards '{}' -> Closing CETP-H2H and C2C layer".format(self.r_cesid))
                self.cetp_mgr.remove_c2c_layer(self.r_cesid)
                self.resource_cleanup()
                self.unregister_c2c()

    """ ***********************   ********************************************** ********************* *********
    ****  Functions for selecting Active transport b/w CES nodes AND for handling transport-layer failover *****
    *********************** *********************** *********************** ************ ******** ********   """

    def send_cetp(self, msg):
        cetp_packet = self._packetize(msg)
        t = self._select_transport()
        if t!=None:
            t.send_cetp(cetp_packet)
            
    def _select_transport(self):
        """ Selects a transport instance towards remote CES. """
        try:
            n = random.randint(0, len(self.connected_transports)-1)
            t = self.connected_transports[n]
            return t
    
        except Exception as ex:
            self._logger.error("Exception '{}' in selecting transport".format(ex))
            return None
       
    def _check_active_transport(self, transport):
        if self.active_transport is None:
            self.active_transport = transport
            self.active_transport_cb = self._loop.call_later(70, self._select_transport)

        
    """ *************  *************  *************  *****************
    ********* Some functionalities exposed by the CETP-C2C API *******
    *************  *************  ************* ********* ******** """

    def shutdown(self):
        """ Close the C2C link between two CES nodes """
        c2c_transaction = self.get_c2c_transaction()
        c2c_transaction.set_terminated()
        c2c_transaction.send_cetp_terminate()
        self.close_all_transport_connections()
            
    def close_all_transport_connections(self):
        """ Closes all connected transports to remote CES """
        for transport in self.connected_transports:
            transport.close()
        
    def report_evidence(self, h_sstag, h_dstag, r_hostid, r_cesid, misbehavior_evidence):
        """ Reports misbehavior evidence observed in H2H (sstag, dstag) to the remote CES """
        c2c_transaction = self.get_c2c_transaction()
        c2c_transaction.report_misbehavior_evidence(h_sstag, h_dstag, r_hostid, misbehavior_evidence)

    def block_malicious_remote_host(self, r_hostid):
        c2c_transaction = self.get_c2c_transaction()
        c2c_transaction.block_remote_host(r_hostid)
        
    def drop_connection_to_local_domain(self, l_domain):
        c2c_transaction = self.get_c2c_transaction()
        c2c_transaction.drop_connection_to_local_domain(l_domain)

    def close_all_h2h_sessions(self):
        c2c_transaction = self.get_c2c_transaction()
        c2c_transaction.drop_all_h2h_sessions()

    def close_h2h_sessions(self, h2h_tags):
        c2c_transaction = self.get_c2c_transaction()
        c2c_transaction.drop_h2h_sessions(h2h_tags)
    

    """ ***********************    ***********************    ***********************
    ******* Functions to handle interrupt (Ctrl+C) and C2C-relation closure.  *******
    ***********************    ***********************   ***********************  """
    
    def resource_cleanup(self):
        """ Cancels the tasks in progress and deletes the object """
        if not self._closure_signal:
            self._set_closure_signal()
            self._report_closure()
            
    def _report_closure(self):
        """ Report closure to H2H layer """
        self.cetp_h2h.set_closure_signal()

    def _set_closure_signal(self):
        """ Unregister the C2C layer and set a closure flag """
        self._closure_signal = True
        self.cetp_mgr.remove_c2c_layer(self.r_cesid)
        del(self)
    
    def handle_interrupt(self):
        if not self._closure_signal:
            self._set_closure_signal()
            self._close_all_initiated_transports()
            self._close_all_connected_transports()
