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
import CETPH2H
import CETPC2C
import cetpOperations
import CETP
import copy
import ConnectionTable
import CETPSecurity

LOGLEVEL_H2HTransaction         = logging.INFO
LOGLEVEL_H2HTransactionOutbound = logging.INFO
LOGLEVEL_H2HTransactionInbound  = logging.INFO
LOGLEVEL_H2HTransactionLocal    = logging.INFO

NEGOTIATION_RTT_THRESHOLD       = 3
DEFAULT_STATE_TIMEOUT           = 5


class H2HTransaction(object):
    def __init__(self, name="H2HTransaction"):
        self.name       = name
        self._logger    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransaction)

    def get_cetp_packet(self, sstag=None, dstag=None, tlvs=[]):
        """ Default CETP fields for signalling message """
        version             = 1
        cetp_header         = {}
        cetp_header['VER']  = version
        cetp_header['SST']  = sstag
        cetp_header['DST']  = dstag
        cetp_header['TLV']  = tlvs
        return cetp_header

    def _get_unavailable_response(self, tlv):
        resp_tlv = copy.copy(tlv)
        resp_tlv['cmp'] = 'NotAvailable'
        resp_tlv['ope'] = "info"
        return resp_tlv
    
    def _get_terminate_tlv(self, err_tlv=None):
        terminate_tlv = {}
        terminate_tlv['ope'], terminate_tlv['group'], terminate_tlv['code'], terminate_tlv['value'] = "info", "control", "terminate", ""
        if err_tlv is not None:
            terminate_tlv['value'] = err_tlv
        return terminate_tlv
    
    def _create_offer_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        if (group!="control") or ((group=="control") and (code in CETP.CONTROL_CODES)):
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv = func(tlv=tlv, code=code, cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, interfaces=self.interfaces, query=False)
        return tlv          # shall use try, except here.

    def _create_offer_tlv2(self, group=None, code=None):
        tlv ={}
        tlv['group'], tlv['code'], tlv["value"] = group, code, ""
        if group=="ces":
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv = func(tlv=tlv, code=code, cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, interfaces=self.interfaces, query=False)
        return tlv

    def _create_request_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        #print(self.policy)
        if (group!="control") or ((group=="control") and (code in CETP.CONTROL_CODES)):
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, interfaces=self.interfaces, query=True)
            return tlv

    def _create_request_tlv2(self, group=None, code=None):
        tlv = {}
        tlv['group'], tlv['code'] = group, code
        if (group!="control") or ((group=="control") and (code in CETP.CONTROL_CODES)):
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, interfaces=self.interfaces, query=True)
            return tlv
    
    def _create_response_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        if (group!="control") or ((group=="control") and (code in CETP.CONTROL_CODES)):
            func = CETP.RESPONSE_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, l_cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, interfaces=self.interfaces)
            return tlv

    def _verify_tlv(self, tlv, policy=None):
        group, code = tlv['group'], tlv['code']
        if (group!="control") or ((group=="control") and (code in CETP.CONTROL_CODES)):
            func   = CETP.VERIFY_TLV_GROUP[group][code]
            if policy!=None:
                result = func(tlv=tlv, code=code, l_cesid=self.l_cesid, r_cesid=self.r_cesid, policy=policy, interfaces=self.interfaces)
            else:
                result = func(tlv=tlv, code=code, l_cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, interfaces=self.interfaces)
            return result

    def _check_tlv(self, tlv, ope=None, cmp=None, group=None, code=None):
        """ Check whether an attribute with given value exists in a TLV"""
        try:
            if (ope != None) and (tlv["ope"] == ope):
                return True
            if (cmp != None) and (tlv["cmp"] == cmp):
                return True
            if (group != None) and (tlv["group"] == group):
                return True
            if (code != None) and (tlv["code"] == code):
                return True
            return False
        except:
            return False
        
    def _get_from_tlvlist(self, tlvlist, group, code = None, ope = ""):
        retlist = []
        for tlv in tlvlist:
            if tlv["group"] != group:
                continue
            if len(ope) != 0:
                if tlv["ope"] != ope:
                    continue
            
            if code is None:
                retlist.append(tlv)
            elif tlv.code == code:
                retlist.append(tlv)
        return retlist
        
    def is_IPv4(self, ip4_addr):
        try:
            socket.inet_pton(socket.AF_INET, ip4_addr)
            return True
        except socket.error:
            return False
    
    def is_IPv6(self, ip6_addr):
        try:
            socket.inet_pton(socket.AF_INET6, ip6_addr)
            return True
        except socket.error:
            return False


    def get_rloc(self, rrloc_tlv, policy):
        #iface_list = CES_CONF.network.get((KEY_NETWORK_PORT, KEY_IFACE_REALM, INTERFACE_PUBLIC), update=False)
        #for iface in iface_list:
        if policy.has_available(rrloc_tlv):
            lrloc_tlv = policy.get_available(rrloc_tlv)
            self._create_offer_tlv(lrloc_tlv)
            #print(rrloc_tlv)
            lrloc = lrloc_tlv["value"]
            rrloc = rrloc_tlv["value"]
            
        return (lrloc, rrloc)


    def _get_connection_rlocs(self):
        l_rlocs, r_rlocs = [], []
        rrloc_tlvs = self._get_from_tlvlist(self.received_tlvs, "rloc", ope="info", code=None)
        #print("rrlocs: ", rrloc_tlvs)
        for rrloc_tlv in rrloc_tlvs:
            lrloc, rrloc = self.get_rloc(rrloc_tlv, self.policy)
            l_rlocs.append(lrloc)
            r_rlocs.append(rrloc)
            
        return (l_rlocs, r_rlocs)


    def get_payload(self, rpayload_tlv, policy):
        if policy.has_available(rpayload_tlv):
            lpayload_tlv = policy.get_available(rpayload_tlv)
            self._create_offer_tlv(lpayload_tlv)
            lpayload = lpayload_tlv["code"]
            rpayload = rpayload_tlv["code"]
        return (lpayload, rpayload)

    def _get_connection_payloads(self):
        l_payloads, r_payloads = [], []
        rpayloads = self._get_from_tlvlist(self.received_tlvs, "payload", ope="info", code=None)
        for rpayload in rpayloads:
            lpayload, rpayload = self.get_payload(rpayload, self.policy)
            l_payloads.append(lpayload)
            r_payloads.append(rpayload)
            
        return (lpayload, rpayload)

        
    def _allocate_proxy_address(self, lip):
        """Allocates a proxy IP address to represent remote host in local CES."""
        if self.is_IPv4(lip):      ap = "AP_PROXY4_HOST_ALLOCATION"
        elif Utils.is_IPv6(lip):   ap = "AP_PROXY6_HOST_ALLOCATION"
        proxy_ip = self.cetpstate_mgr.allocate_proxy_address(lip)
        return proxy_ip

    def get_proxy_address(self, key, local_ip):
        proxy_ip = "10.1.3.103"
        return proxy_ip

    def is_local_host_allowed(self, hostid):
        """ Checks in the CETPSecurity module if the traffic from the sender is permitted (towards remote CES).. OR  whether the host is blacklisted """
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_BlacklistedLHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_DisabledLHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_BlockedHostsByRCES, hostid, key=self.r_cesid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_Unreachable_local_destinations, hostid, key=self.r_cesid):
            return False
        return True

    def is_remote_host_allowed(self, hostid):
        """ Determines whether the traffic to destination is permitted """
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_BlacklistedRHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_BlockedHostsOfRCES, hostid, key=self.r_cesid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_Unreachable_remote_destinations, hostid, key=self.r_cesid):
            return False
        return True
    
    def generate_session_tags(self, dstag=0):
        """ Returns a session-tag of 4-byte length, if sstag is not part of an connecting or ongoing transaction """
        while True:
            sstag = random.randint(0, 2**32)
            if dstag ==0:
                # For oCES, it checks the connecting transactions
                if not self.cetpstate_mgr.has_initiated_transaction((sstag, 0)):
                    return sstag
            
            elif dstag:
                self._logger.debug("iCES is requesting source session tag")
                """ iCES checks if upon assigning 'sstag' the resulting (SST, DST) pair will lead to a unique transaction. """
                if not self.cetpstate_mgr.has_established_transaction((sstag, dstag)):                   # Checks connected transactions
                    return sstag
                
    def show(self, packet):
        self._logger.info("CETP Packet")
        for k, v in packet.items():
            if k != "TLV":
                print(str(k)+": "+ str(v))
            else:
                print("TLV:")
                for tlv in v:
                    if 'value' in tlv:
                        print("\t { 'ope':{}, 'group':{}, 'code':{}, 'value':{} }".format(tlv['ope'], tlv['group'],tlv['code'], tlv['value']))
                    else:
                        print("\t { 'ope':{}, 'group':{}, 'code':{} }".format(tlv['ope'], tlv['group'],tlv['code']))
        print("\n")
        
    def show2(self, packet):
        self._logger.info("CETP Packet")
        for k, v in packet.items():
            if k != "TLV":
                print(str(k)+": "+ str(v))
            else:
                print("TLV:")
                for tlv in v:
                    print("\t", tlv)
        print("\n")

    def pprint(self, packet):
        self.show2(packet)


class H2HTransactionOutbound(H2HTransaction):
    def __init__(self, loop=None, sstag=0, dstag=0, cb=None, host_ip="", src_id="", dst_id="", l_cesid="", r_cesid="", policy_mgr= None, host_register=None, cetp_security=None, \
                 cetpstate_mgr=None, cetp_h2h=None, ces_params=None, interfaces=None, conn_table=None, direction="outbound", name="H2HTransactionOutbound", rtt_time=[]):
        self.sstag, self.dstag  = sstag, dstag
        self.cb                 = cb
        self.host_ip            = host_ip                   # IP of the sender host
        self.src_id             = src_id                    # FQDN
        self.dst_id             = dst_id
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.policy_mgr         = policy_mgr
        self.cetpstate_mgr      = cetpstate_mgr
        self._loop              = loop
        self.cetp_h2h           = cetp_h2h
        self.ces_params         = ces_params
        self.direction          = direction
        self.host_register      = host_register
        self.src_id             = src_id
        self.interfaces         = interfaces
        self.conn_table         = conn_table
        self.cetp_security      = cetp_security
        self.rtt                = 0
        self.name               = name
        self._logger            = logging.getLogger(name)
        self.start_time         = time.time()
        self._logger.setLevel(LOGLEVEL_H2HTransactionOutbound)
        self.h2h_negotiation_status = False
        self.cetp_negotiation_history   = []
        self.rtt_time           = rtt_time

    def handle_h2h(self):
        if not self.h2h_negotiation_status:
            self._logger.info(" Incomplete H2H-state towards '{}' expired".format(self.dst_id))
            self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))
            self.cetp_h2h.update_H2H_transaction_count(initiated=False)
    
    def load_policies(self, l_cesid=None, r_cesid=None, src_id=None, dst_id=None):
        """ Selection of host policy """
        #index = self.policy_mgr.mapping_srcId_to_policy(src_id)                # Choosing policy for sender's (identity)
        self.opolicy  = self.policy_mgr.get_host_policy(self.direction, host_id=src_id)
        self.policy   = self.opolicy

    def _initialize(self):
        """ Loads policies, generates session tags, and initiates event handlers """
        try:
            self.src_id = self.host_register.ip_to_fqdn_mapping(self.host_ip)
            if not self.is_local_host_allowed(self.src_id):
                self._logger.warning(" Sender '{}' cannot initiate connection towards CES '{}'".format(self.src_id, self.r_cesid))
                return False
            if not self.is_remote_host_allowed(self.dst_id):
                self._logger.warning(" Remote CES doesn't accept connection to '{}'.".format(self.dst_id))
                return False
            
            self.sstag = self.generate_session_tags()
            self.load_policies(src_id = self.src_id)
            self.state_timeout = DEFAULT_STATE_TIMEOUT
            
            if 'state_timeout' in self.ces_params:
                self.state_timeout   = self.ces_params['state_timeout']
        
            # Handler to unregister the incomplete CETP-C2C transaction
            self.h2h_handler = self._loop.call_later(self.state_timeout, self.handle_h2h)
            return True
        
        except Exception as ex:
            self._logger.info(" Exception in initiating the H2H session: '{}'".format(ex))
            return False

    def send_cetp(self, cetp_packet):
        self.cetp_h2h.send(cetp_packet)
    
    @asyncio.coroutine
    def start_cetp_processing(self):
        """ Returns CETP message containing Policy Offers & Request towards remote-host """
        #try:
        if not self._initialize():
            self._logger.debug(" Failure in initiating the CES-to-CES session.")
            return None
        
        self._logger.debug(" Starting H2H session towards '{}' (SST= {} -> DST={})".format(self.dst_id, self.sstag, self.dstag))
        tlvs_to_send = []
        dstep_tlv = self.append_dstep_info()
        tlvs_to_send.append(dstep_tlv)
        self._logger.info("outbound policy: {}".format(self.opolicy))

        # Check if sender supports the id_type as of the destination-id, otherwise maybe not even initiate a transaction? or initiate with a default ID-type?
        # And regardless of id_type being used, FQDN of host shall be made part of the messages exchanged?
        
        # Offered TLVs
        for otlv in self.opolicy.get_offer():
            tlv = self._create_offer_tlv(otlv)
            tlvs_to_send.append(tlv)
            
        # Required TLVs
        for rtlv in self.opolicy.get_required():
            tlv = self._create_request_tlv(rtlv)
            tlvs_to_send.append(tlv)
        
        cetp_msg = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
        cetp_packet = json.dumps(cetp_msg)
        self.pprint(cetp_msg)
        self.last_packet_sent = cetp_packet
        self.cetp_negotiation_history.append(cetp_packet)
        self.cetpstate_mgr.add_initiated_transaction((self.sstag,0), self)                # Registering the H2H state
        self.cetp_h2h.update_H2H_transaction_count()
        #self._logger.info("start_cetp_processing delay: {}".format(now-start_time))
        return cetp_packet
        
        #except Exception as msg:
        #    self._logger.info("Exception in start_cetp_processing(): {}".format(msg))
        #    return None
        #policies = yield from self.get_policies_from_PolicySystem(r_id, r_cesid)

    def append_dstep_info(self):
        dstep_tlv = {}
        dstep_tlv["ope"], dstep_tlv["group"], dstep_tlv["code"], dstep_tlv["value"] = "info", "control", "dstep", self.dst_id 
        return dstep_tlv

    def _pre_process(self, cetp_msg):
        """ Checks for minimum packet detail & CETP format compliance in the inbound packet """
        try:
            self.query_message = False
            ver, inbound_sstag, inbound_dstag = cetp_msg['VER'], cetp_msg['SST'], cetp_msg['DST']
            self.received_tlvs = cetp_msg['TLV']
            self.sstag, self.dstag = inbound_dstag, inbound_sstag                                       # Sender's SST is DST for CES
            self.packet = cetp_msg

            if ver!=1:
                self._logger.error(" CETP Version is not supported.")
                return False
            
            for received_tlv in self.received_tlvs:
                if self._check_tlv(received_tlv, ope="query"):
                    self.query_message = True
                    break
            return True
            
        except Exception as ex:
            self._logger.error(" Pre-processing the CETP packet failed. {}".format(ex))
            return False


    def continue_cetp_processing(self, cetp_packet, transport):
        #try:
        if not self._pre_process(cetp_packet):
            self._logger.info(" Inbound packet failed in pre_processing.")
            return None
        
        #self._logger.info("Continue establishing H2H session towards '{}' ({} -> {})".format(self.dst_id, self.sstag, 0))
        #self._logger.info("Host policy: {}".format(self.opolicy))
        tlvs_to_send = []
        error = False
        satisfied_requriements = 0
        self.rtt += 1

        if self.rtt > NEGOTIATION_RTT_THRESHOLD:                                        # Prevents infinite-exchange of CETP policies.
            self.cetpstate_mgr.remove_initiated_transaction((self.sstag, self.dstag))
            return False
        """
        Processing logic:
            If pre-processing determined that inbound packet is (or contains) a request message, oCES sends response & issue local CES policy queries.
            If message contains no query, it is treated as a response message.     If all TLVs could be verified, the message is accepted. Otherwise, oCES sends terminate-TLV, if iCES has already completed (SST, DST) state.
        """
        
        # Processing inbound packet
        for received_tlv in self.received_tlvs:
            if self.query_message:
                if self._check_tlv(received_tlv, ope="query"):
                    if self.opolicy.has_available(received_tlv):
                        ret_tlv = self._create_response_tlv(received_tlv)
                        if ret_tlv !=None:
                            tlvs_to_send.append(ret_tlv)
                            continue
                                                
                    if self._check_tlv(received_tlv, cmp="optional"):
                        self._logger.info(" An optional requirement {}.{} is not available locally.".format(received_tlv['group'], received_tlv['code']))
                        ret_tlv = self._get_unavailable_response(received_tlv)
                        tlvs_to_send.append(ret_tlv)
                    else:
                        error = True
                        break
    
            #A CETP response message is processed for: Policy Matching and TLV Verification. The message can have: 1) Less than required TLVs; 2) TLVs with wrong value; 3) a notAvailable TLV; OR 4) a terminate TLV.
            elif self._check_tlv(received_tlv, ope="info"):
                if (received_tlv['group'] == 'control') and (received_tlv['code']=='terminate'):
                    self._logger.info(" Terminate-TLV received with value: {}".format(received_tlv['value']) )
                    error = True
                    break

                elif self.opolicy.has_required(received_tlv):
                    if self._verify_tlv(received_tlv):
                        satisfied_requriements += 1
                    else:
                        # Absorbs failure in case of 'optional' required policy TLV
                        if not self.opolicy.is_mandatory_required(received_tlv):
                            satisfied_requriements += 1
                        else:
                            self._logger.info(" TLV {}.{} failed verification".format(received_tlv['group'], received_tlv['code']))
                            tlvs_to_send =  []
                            tlvs_to_send.append(self._get_terminate_tlv(err_tlv=received_tlv))
                            error=True
                            break
                elif not self.opolicy.has_required(received_tlv):
                    self._logger.info("Unrequrested TLV is received")
                    pass
                
                
        # Evaluation of Policy Matching
        if error:
            # Locally terminate session, as iCES is stateless
            self._logger.warning(" H2H policy negotiation failed in {} RTT".format(self.rtt))
            self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))
            self.cetp_h2h.update_H2H_transaction_count(initiated=False)
            self.h2h_handler.cancel()
            self._execute_dns_callback(resolution=False)

            if self.dstag==0:
                return False
            else:
                # Return terminate packet to remote end, as it has completed the transaction
                self._logger.info(" Responding remote CES with the terminate-TLV")
                cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)        # Send as 'Info' TLV
                self.last_packet_sent = cetp_message
                self.cetp_negotiation_history.append(cetp_message)
                self.pprint(cetp_message)
                cetp_packet = json.dumps(cetp_message)
                self.send_cetp(cetp_packet)
                return False
        else:
            if (satisfied_requriements == len(self.opolicy.required)) and (self.dstag!=0):
                self._logger.info(" H2H policy negotiation succeeded in {} RTT".format(self.rtt))
                self._logger.info("{}".format(42*'*') )
                self.h2h_negotiation_status = True
                #self._logger.info("continue_cetp_processing delay #1: {}".format(now - start_time))
                #self.rtt_time.append(now-self.start_time)
                #print(self.rtt_time)
                if not self._cetp_established(cetp_packet):
                    return False

                return True
            else:
                self._logger.info(" Inbound packet didn't meet all the policy requirements of sender-host")
                self._logger.debug("A more LAX version may allow another negotiation round")

                # Issuing sender's policy requirements
                for rtlv in self.opolicy.get_required():
                    tlv = self._create_request_tlv(rtlv)
                    tlvs_to_send.append(tlv)
            
                tlvs_to_send.append(self.append_dstep_info())
                cetp_msg = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)           # Sending 'response' as 'info'
                self.last_packet_sent = cetp_msg
                self.last_packet_received = self.packet
                self.cetp_negotiation_history.append(cetp_msg)
                self.pprint(cetp_msg)
                cetp_packet = json.dumps(cetp_msg)
                self.send_cetp(cetp_packet)
                return None

        #except Exception as msg:
        #    self._logger.info(" Exception in negotiating CETP-H2H session: {}".format(msg))
        #    return (None, "")
                

    def _cetp_established(self, cetp_packet):
        """ 
        1) Executes DNS callback,    2) Replaces initiated transaction with an established transaction
        3) Checks whether DST assigned by iCES has resulted in an (SST, DST) pair which is unique at oCES. If not, it sends a terminate to iCES.
        """
        self.cetp_h2h.update_H2H_transaction_count(initiated=False)                            # To reduce number of ongoing transactions.
        self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))
        
        #Checks whether (SST, DST) pair is locally unique.
        if self.cetpstate_mgr.has_established_transaction((self.sstag, self.dstag)):
            self._logger.warning(" Terminating transaction as ({},{}) pair is not unique in CES".format(self.sstag, self.dstag))
            self.session_failure()
            return False
        
        proxy_ip = self._create_connection()
        self.cetpstate_mgr.add_established_transaction((self.sstag, self.dstag), self)
        self._execute_dns_callback(r_addr=proxy_ip)
        #self.create_transaction_in_dp()
        return True

    def _create_connection(self):
        """ Extract the negotiated parameters to create a connection state """
        self.lfqdn, self.rfqdn          = self.src_id, self.dst_id                  #self._create_connection_get_fqdns()
        self.lip                        = self.host_ip
        self.proxy_ip                   = self._allocate_proxy_address(self.lip)
        self.lrloc, self.rrloc          = self._get_connection_rlocs()
        self.lpayload, self.rpayload    = self._get_connection_payloads()
        self.lid, self.rid              = None, None
        
        self.conn = ConnectionTable.H2HConnection(120.0, "outbound", self.lid, self.lip, self.proxy_ip, self.rid, self.lrloc, self.rrloc, self.lfqdn, self.rfqdn, \
                                              self.sstag, self.dstag, self.lpayload, self.rpayload, self.r_cesid)
        self.conn_table.add(self.conn)
        print(self.lfqdn, self.rfqdn, self.lip, self.proxy_ip, self.lrloc, self.rrloc, self.lpayload, self.rpayload, self.lid, self.rid)
        return self.proxy_ip
    

        #conn = CES_CONF.state_creator.createconnection(CONNECTION_CETP,direction='O',sstag=self.sstag, dstag=self.dstag,lip=lip,lpip=lpip,lid=lid,rid=rid,lfqdn=lfqdn,\
        #rfqdn=rfqdn,lrloc=lrloc,rrloc=rrloc,lpayload=lpayload,rpayload=rpayload)

        """
        group, code, ope = TLV_GROUP["rloc"], None, [TLV_OPE["response"], TLV_OPE["info"]]
        remote_rloc = self._get_from_tlvlist(self.received_tlv_list, group, code, ope)

        #Use the received RLOCs to create the list of offered RLOCs
        #This is due to the model 1.5 RTT because we are stateless and can't recall the TLVs we sent before
        for p in remote_rloc:
            local_rloc += self._create_offer_tlv(p)

        #Filter out the non-matching rloc technologies
        local_rloc, remote_rloc = self._filter_rloc_list(local_rloc, remote_rloc)
        return (local_rloc, remote_rloc)
        """
        
        
    def _execute_dns_callback(self, r_addr="", resolution=True):
        """ Executes DNS callback towards host """
        (cb_func, cb_args) = self.cb
        dns_q, addr = cb_args
        cb_func(dns_q, addr, r_addr, success=resolution)

    def _create_terminate_message(self):
        terminate_tlv = self._create_offer_tlv2(group="control", code="terminate")
        tlv_to_send = [terminate_tlv]
        cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlv_to_send)
        cetp_packet = json.dumps(cetp_message)
        return cetp_packet

    def terminate_session(self):
        """ Sends a terminate TLV and closes the established transaction """
        cetp_packet = self._create_terminate_message()
        self.send_cetp(cetp_packet)
        
    def session_failure(self):
        """ Sends a terminate TLV and closes the established transaction """
        self.terminate_session()
        self._execute_dns_callback(resolution=False)

    def create_transaction_in_dp(self, cetp_msg):
        #self.create_dataplane_entry(sst, dst, info)
        pass
    
    @asyncio.coroutine
    def get_policies_from_PolicySystem(self, r_hostid, r_cesid):        # Has to be a coroutine in asyncio - PolicyAgent
        #yield from self.policy_client.send(r_hostid, r_cesid)
        pass

    def post_h2h_negotiation(self, cetp_packet, transport):
        """ Processes a CETP packet received on a negotiated H2H session.     e.g. a 'terminate' CETP message, or change ratelimit of dataplane connection. 
        """
        self._logger.info(" Post-H2H negotiation packet on (SST={}, DST={})".format(self.sstag, self.dstag))
        self.packet = cetp_packet
        tlv_to_send = []
        
        if 'TLV' in cetp_packet:
            received_tlvs = cetp_packet['TLV']
        
        for received_tlv in received_tlvs:
            if (received_tlv['group'] == 'control') and (received_tlv['code']=='terminate'):
                self._logger.warning(" Terminate received for an established H2H Session ({}->{}).".format(self.sstag, self.dstag))
                self.cetpstate_mgr.remove_established_transaction((self.sstag, self.dstag))
                keytype = ConnectionTable.KEY_MAP_CES_TO_CES
                key = (self.sstag, self.dstag)
                if self.conn_table.has(keytype, key):
                    conn = self.conn_table.get(keytype, key)
                    self.conn_table.delete(conn)
                    print("After terminate")
                    print(self.conn_table.connection_dict)
                    



class H2HTransactionInbound(H2HTransaction):
    def __init__(self, sstag=0, dstag=0, l_cesid="", r_cesid="", policy_mgr= None, cetpstate_mgr= None, interfaces=None, conn_table=None, \
                 cetp_h2h=None, cetp_security=None, name="H2HTransactionInbound"):
        self.sstag              = sstag
        self.dstag              = dstag
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.policy_mgr         = policy_mgr                # This could be policy client in future use.
        self.cetpstate_mgr      = cetpstate_mgr
        self.interfaces         = interfaces
        self.direction          = "inbound"
        self.conn_table         = conn_table
        self.cetp_h2h           = cetp_h2h
        self.cetp_security      = cetp_security
        self.name               = name
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransactionInbound)

    def load_policies(self, dst_id):
        #index = self.policy_mgr.mapping_srcId_to_policy(host_id)
        self.ipolicy        = self.policy_mgr.get_host_policy(self.direction, host_id=dst_id)
        self.policy         = self.ipolicy
    
    def _pre_process(self, cetp_packet):
        """ Pre-process the inbound packet for the minimum necessary details. """
        try:
            ver, inbound_sstag, inbound_dstag = cetp_packet['VER'], cetp_packet['SST'], cetp_packet['DST']
            self.sstag, self.dstag = inbound_dstag, inbound_sstag
            self.packet            = cetp_packet
            self.received_tlvs     = cetp_packet['TLV']
            self.src_id, self.dst_id = "", ""
            
            if ver!=1:
                self._logger.error(" CETP Version is not supported.")
                return False

            for received_tlv in self.received_tlvs:
                if self._check_tlv(received_tlv, ope="info"):
                    if (received_tlv['group']== "id") and (received_tlv['code']=="fqdn"):
                        self.src_id = received_tlv['value']
                    elif (received_tlv['group']=="control") and (received_tlv['code']=="dstep"):
                        self.dst_id = received_tlv["value"]
                        
            if (len(self.src_id)<=0) or (len(self.src_id)>256):             # Max length of FQDN = 256
                return False
            if (len(self.dst_id)<=0) or (len(self.dst_id)>256):             # Max length of FQDN = 256
                return False

            if not self.dst_hostId_is_valid(self.dst_id):
                self._logger.warning(" Destination is not served by this CES.")
                return False
            
            if not self.is_remote_host_allowed(self.src_id):
                self._logger.warning(" Sender '{}' is blocked.".format(self.src_id))
                return False
            if not self.is_local_host_allowed(self.dst_id):
                self._logger.warning(" Connection to destination '{}' is not allowed".format(self.dst_id))
                return False
            
            self.load_policies(self.dst_id)
            return True
        
        except Exception as ex:
            self._logger.error(" Pre-processing the inbound CETP packet failed: '{}'".format(ex))
            return False

    
    def get_tlv(self, recv_tlv_lst, group=None, code=None):
        for tlv in recv_tlv_lst:
            if (tlv['group']==group) and (tlv['code'] == code):
                return tlv
        return None

    @asyncio.coroutine
    def start_cetp_processing(self, cetp_packet, transport):
        """ Processes the inbound CETP-packet for negotiating the H2H policies """
        #try:
        self._logger.info("{}".format(42*'*') )
        self._logger.info("Inbound packet:")
        self.pprint(cetp_packet)
        
        if not self._pre_process(cetp_packet):
            self._logger.info("Inbound packet failed the pre-processing()")
            return False
        
        satisfied_requirements = 0
        tlvs_to_send = []
        error = False
        
        # Processing inbound packet
        for received_tlv in self.received_tlvs:
            # Processing sender's requests  -- Evaluates whether the sender's requirements could be answered
            if self._check_tlv(received_tlv, ope="query"):
                if self.ipolicy.has_available(received_tlv):
                    ret_tlv = self._create_response_tlv(received_tlv)
                    if ret_tlv !=None:
                        tlvs_to_send.append(ret_tlv)
                        continue
                    
                if self._check_tlv(received_tlv, cmp="optional"):
                    self._logger.info(" An optional requirement TLV {}.{} is not available locally.".format(received_tlv['group'], received_tlv['code']))
                    ret_tlv = self._get_unavailable_response(received_tlv)
                    tlvs_to_send.append(ret_tlv)
                else:
                    self._logger.info(" A required TLV {}.{} is not available locally.".format(received_tlv['group'], received_tlv['code']))
                    error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                    error = True
                    break
                        
            # Checks whether the sender's offer met the policy requirements of destination, and the Offer can be verified.
            elif self._check_tlv(received_tlv, ope="info"):
                if received_tlv["group"] == "control" and received_tlv["code"]== "terminate":
                    self._logger.info(" Terminate-TLV received with payload: {}".format(received_tlv['value']) )                     # In stateless mode, iCES shall not receive terminate TLV.
                    return None

                elif self.ipolicy.has_required(received_tlv):
                    if self._verify_tlv(received_tlv):
                        satisfied_requirements += 1
                    else:
                        # Absorbs failure in case of 'optional' required policy TLV
                        if not self.ipolicy.is_mandatory_required(received_tlv):
                            satisfied_requirements += 1
                        else:
                            self._logger.info("TLV {}.{} failed verification".format(received_tlv['group'], received_tlv['code']))
                            error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                            error = True
                            break
                else:
                    self._logger.debug("Non-requested TLV {} is received: ".format(received_tlv))
                    pass

    
        if error:
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=error_tlvs)
            #self.pprint(cetp_message)
            cetp_packet = json.dumps(cetp_message)
            transport.send_cetp(cetp_packet)
            return False
            # Future item:     Return value shall allow CETPLayering to distinguish (Failure due to policy mismatch from wrong value and hence blacklisting subsequent interactions) OR shall this be handled internally?
        else:
            if (satisfied_requirements == len(self.ipolicy.required)):
                #All the  requirements of remote-CES are met -> Accept/Create CETP connection (i.e. by assigning 'SST') and Export to stateful (for post-negotiation CETP flow etc.)
                self.sstag = self.generate_session_tags(self.dstag)
                stateful_transansaction = self._export_to_stateful()
                self._logger.info("H2H-policy negotiation succeeded -> Create transaction (SST={}, DST={})".format(self.sstag, self.dstag))
                self._logger.info("{}".format(42*'*') )
                
                cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                self._logger.info("Response packet:")
                self.pprint(cetp_message)
                cetp_packet = json.dumps(cetp_message)
                self.last_packet_sent = cetp_packet
                #self._logger.info("iCES start_cetp_processing delay: {}".format(now- start_time))
                transport.send_cetp(cetp_packet)
                return True
            else:
                self._logger.info(" {} unsatisfied iCES requirements: ".format( len(self.ipolicy.required)-satisfied_requirements ))
                self._logger.info(" Initiate full query")
                
                tlvs_to_send = []
                for rtlv in self.ipolicy.get_required():            # Generating Full Query message
                    tlv = self._create_request_tlv(rtlv)
                    tlvs_to_send.append(tlv)
                
                cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                self._logger.info("Response packet:")
                self.pprint(cetp_message)
                cetp_packet = json.dumps(cetp_message)
                transport.send_cetp(cetp_packet)
                return None
    
        #except Exception as msg:
        #    self._logger.info("Exception: {}".format(msg))
        #    return (None, "")

    def dst_hostId_is_valid(self, host):
        """ Emulates that host exists behind CES """
        return True

    def _create_connection(self):
        lfqdn, rfqdn            = self.src_id, self.dst_id
        lip                     = "10.0.3.111"
        proxy_ip                = self._allocate_proxy_address(lip)          # Get local IP for a domain from Host-register
        lrloc, rrloc            = self._get_connection_rlocs()
        lpayload, rpayload      = self._get_connection_payloads()
        lid, rid                = None, None
        conn = ConnectionTable.H2HConnection(120.0, "inbound", lid, lip, proxy_ip, rid, lrloc, rrloc, lfqdn, rfqdn, self.sstag, self.dstag, lpayload, rpayload, self.r_cesid)
        print(lfqdn, rfqdn, lip, proxy_ip, lrloc, rrloc, lpayload, rpayload, lid, rid)
        self.conn_table.add(conn)

    def _export_to_stateful(self):
        """ Creates connection and complete H2Htransaction to stateful """
        new_transaction = H2HTransactionOutbound(sstag=self.sstag, dstag=self.dstag, policy_mgr= self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr, conn_table=self.conn_table, \
                                                 l_cesid=self.l_cesid, r_cesid=self.r_cesid, direction="inbound", src_id=self.src_id, dst_id=self.dst_id, cetp_h2h=self.cetp_h2h, \
                                                 cetp_security=self.cetp_security)
        new_transaction.opolicy = self.ipolicy
        new_transaction.policy  = self.policy
        self.cetpstate_mgr.add_established_transaction((self.sstag, self.dstag), new_transaction)
        return new_transaction
    

    @asyncio.coroutine
    def get_policies_from_PolicySystem(self, r_hostid, r_cesid):
        yield from self.policy_client.send(r_hostid, r_cesid)



class H2HTransactionLocal(H2HTransaction):
    def __init__(self, loop=None, host_ip="", cb=None, src_id="", dst_id="", policy_mgr= None, host_register=None, cetpstate_mgr=None, cetp_h2h=None, interfaces=None, conn_table=None, name="H2HTransactionLocal"):
        self.cb                 = cb
        self.host_ip            = host_ip                   # IP of the sender host
        self.src_id             = src_id                    # FQDN
        self.dst_id             = dst_id
        self.policy_mgr         = policy_mgr
        self.cetpstate_mgr      = cetpstate_mgr
        self._loop              = loop
        self.cetp_h2h           = cetp_h2h
        self.host_register      = host_register
        self.interfaces         = interfaces
        self.conn_table         = conn_table
        self.l_cesid            = ""
        self.r_cesid            = ""
        self.name               = name
        self._logger             = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransactionLocal)

    @asyncio.coroutine
    def _initialize(self):
        yield from asyncio.sleep(0.000)          # Simulating the delay in loading policies from the Policy System
        self.src_id   = self.host_register.ip_to_fqdn_mapping(self.host_ip)
        self.opolicy  = self.policy_mgr.get_host_policy("outbound", host_id=self.src_id)
        self.ipolicy  = self.policy_mgr.get_host_policy("inbound",  host_id=self.dst_id)
        
    @asyncio.coroutine
    def start_cetp_processing(self):
        """ Starts the CETPLocal policy negotiation """
        yield from self._initialize()
        #self._logger.info("Local-host policy: {}".format(self.opolicy))
        #self._logger.info("Remote-host policy: {}".format(self.ipolicy))
        error = False
        
        # TBD: Verification & enforcement of policy elements is next
        # If someone is reaching itself,     we don't assign any address to it (Or perform negotiation) 

            
        #Match Outbound-Requirements vs Inbound-Available TLVs:           1) Requirements are fulfilled; AND 2) Responses are acceptable 
        #self._logger.info("Outbound-Requirements vs Inbound-Available")
        for rtlv in self.opolicy.get_required():
            #RLOC and payload-encapsulation polcies are not applicable in local connection context
            if rtlv["group"] in ["rloc", "payload"]:
                continue
            
            if not self.ipolicy.has_available(rtlv):
                self._logger.warning("Outbound Requirement '{}.{}' is not met by destination" % (rtlv['group'], rtlv['code']))
                error = True
                break
            else:
                resp_tlv = self.ipolicy.get_available(tlv=rtlv)
                # Check if the TLV value is acceptable to the sender host's requirements
                if not self._verify_tlv(resp_tlv, policy=self.opolicy):
                    # Absorbs failure in case of 'optional' required policy TLV
                    if self.opolicy.is_mandatory_required(rtlv):
                        self._logger.info(" TLV {}.{} failed verification".format(rtlv['group'], rtlv['code']))
                        error=True
                        break


        if not error:
            #Match Inbound-Requirements vs Outbound-Available TLVs        1) Requirements are fulfilled; AND 2) Responses are acceptable 
            #self._logger.info("Match Inbound-Requirements vs Outbound-Available")
            for rtlv in self.ipolicy.get_required():
                #RLOC and payload-encapsulation polcies are not applicable in local connection context
                if rtlv["group"] in ["rloc", "payload"]:
                    continue
                
                if not self.opolicy.has_available(tlv=rtlv):
                    self._logger.warning("Remote host requirement '{}.{}' is not met by the sender" % (rtlv['group'], rtlv['code']))
                    error = True
                    break
                else:
                    resp_tlv = self.opolicy.get_available(rtlv)
                    if not self._verify_tlv(resp_tlv, policy=self.ipolicy):
                        # Absorbs failure in case of 'optional' required policy TLV
                        if self.opolicy.is_mandatory_required(rtlv):
                            self._logger.info(" TLV {}.{} failed verification".format(resp_tlv['group'], resp_tlv['code']))
                            error=True
                            break


        if error:
            self._logger.warning("CETP Policy mismatched! Connection refused {} -> {}".format(self.src_id, self.dst_id))
            self._execute_dns_callback(resolution=False)
            #self.dns_state.delete(stateobj)
            return False
        else:
            self._logger.warning("CETP Policy matched! Allocate proxy address. {} -> {}".format(self.src_id, self.dst_id))
            lpip = self._create_local_connection()
            self._execute_dns_callback(lpip)
            #o_connection, i_connection = self.create_local_connection(localhost, remotehost)
            #lpip = o_connection.lpip
            #rrset = dns.rrset.from_text(domain, self.proxytimeout, dns.rdataclass.IN, query_type, lpip)
            #self.answer_no_error(dns_query, stateobj, [rrset], [], [])
            return True
        
        
    def _execute_dns_callback(self, r_addr, resolution=True):
        """ Executes DNS callback towards host """
        (cb_func, cb_args) = self.cb
        dns_q, addr = cb_args
        cb_func(dns_q, addr, r_addr, success=resolution)
    
    def _create_local_connection(self):
        lip, rip        = self.host_ip, "10.0.3.103"                            # Get from host-register (IPv4 or IPv6 address depending on sender address type)
        lpip            = self.cetpstate_mgr.allocate_proxy_address(lip)
        lfqdn, rfqdn    = self.src_id, self.dst_id
        lid, rid        = None, None
        rpip            = self.cetpstate_mgr.allocate_proxy_address(rip)
        
        connection_direction = "" #both outbound and inbound

        self._logger.info("Creating Local connection between %s and %s" % (lfqdn, rfqdn))
        
        self.o_connection = ConnectionTable.LocalConnection(120.0, "CONNECTION_OUTBOUND", lid=lid,lip=lip,lpip=lpip,lfqdn=lfqdn,
                                                       rid=rid,rip=rip,rpip=rpip,rfqdn=rfqdn)
        
        self.i_connection = ConnectionTable.LocalConnection(120.0, "CONNECTION_INBOUND", rid=lid,rip=lip,rpip=lpip,rfqdn=lfqdn,
                                                       lid=rid,lip=rip,lpip=rpip,lfqdn=rfqdn)        
        self.conn_table.add(self.o_connection)
        self.conn_table.add(self.i_connection)
        return lpip
        

