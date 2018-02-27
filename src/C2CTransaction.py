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
import H2HTransaction
from H2HTransaction import CETPTransaction

LOGLEVELCETP                    = logging.DEBUG
LOGLEVEL_C2CTransaction         = logging.INFO
LOGLEVEL_oC2CTransaction        = logging.INFO
LOGLEVEL_iC2CTransaction        = logging.INFO

NEGOTIATION_RTT_THRESHOLD       = 2

KEY_INITIATED_TAGS        = H2HTransaction.KEY_INITIATED_TAGS
KEY_ESTABLISHED_TAGS      = H2HTransaction.KEY_ESTABLISHED_TAGS
KEY_HOST_IDS              = H2HTransaction.KEY_HOST_IDS
KEY_RCESID                = H2HTransaction.KEY_RCESID
KEY_CES_IDS               = H2HTransaction.KEY_CES_IDS

"""
General_CES_policy
        cesid: cesa.lte.
        certificate: config_cesa/cesa.crt
        #private_key: config_cesa/cesa.key
        #ca_certificate: config_cesa/ca.crt
        dp_ttl: 3600
        keepalive_timeout: 2
        keepalive_cycle: 20
        caces: 127.0.0.1
        fw_version: 0.1
        ces_session_limit: 30
        host_ratelimit: 2
        pow_algo: hashcash
        max_ces_session_limit: 100
        max_dp_ttl: 7200
        max_host_ratelimit: 10
        min_keepalive_timeout: 10
"""


class C2CTransaction(CETPTransaction):

    def _create_offer_tlv(self, tlv):
        try:
            group, code = tlv['group'], tlv['code']
            if group in ["ces", "rloc", "payload"]:
                func = CETP.SEND_TLV_GROUP[group][code]
                tlv = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, \
                           cetp_security=self.cetp_security, policy = self.ces_policy, interfaces=self.interfaces, query=False)
            return tlv
        except Exception as ex:
            self._logger.error("Exception '{}' in _create_offer_tlv() for tlv : '{}'".format(ex, tlv))
            return None
                    
    def _create_offer_tlv2(self, group=None, code=None, value=None):
        try:
            tlv ={}
            tlv['ope'], tlv['group'], tlv['code'], tlv["value"] = "info", group, code, ""
            if value!=None:
                tlv["value"] = value
                
            if group in ["ces", "rloc", "payload"]:
                func = CETP.SEND_TLV_GROUP[group][code]
                tlv = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, \
                           cetp_security=self.cetp_security, policy = self.ces_policy, interfaces=self.interfaces, query=False)
                
            return tlv
        
        except Exception as ex:
            self._logger.error("Exception in _create_offer_tlv2() '{}'".format(ex))
            return None

    def _create_request_tlv(self, tlv):
        try:
            group, code = tlv['group'], tlv['code']
            if group in ["ces", "rloc", "payload"]:
                func = CETP.SEND_TLV_GROUP[group][code]
                tlv  = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, \
                            cetp_security=self.cetp_security, policy = self.ces_policy, interfaces=self.interfaces, query=True)
            return tlv
        except Exception as ex:
            self._logger.error("Exception in _create_request_tlv() '{}'".format(ex))
            return None

    def _create_request_tlv2(self, group=None, code=None, value=None):
        try:
            tlv = {}
            tlv['ope'], tlv['group'], tlv['code'], tlv['value'] = "query", group, code, ""
            if value!=None:
                tlv["value"] = value
                
            if group in ["ces", "rloc", "payload"]:
                func = CETP.SEND_TLV_GROUP[group][code]
                tlv  = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, \
                            cetp_security=self.cetp_security, policy = self.ces_policy, interfaces=self.interfaces, query=True)
                return tlv
        except Exception as ex:
            self._logger.error("Exception in _create_request_tlv2() '{}'".format(ex))
            return None
    
    def _create_response_tlv(self, tlv, post_c2c=False):
        try:
            group, code = tlv['group'], tlv['code']
            if group in ["ces", "rloc", "payload"]:
                func = CETP.RESPONSE_TLV_GROUP[group][code]
                tlv  = func(tlv=tlv, code=code, ces_params=self.ces_params, l_cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, post_c2c=post_c2c, \
                            cetp_security=self.cetp_security, policy = self.ces_policy, transaction=self, interfaces=self.interfaces, packet=self.packet)
            return tlv
        except Exception as ex:
            self._logger.error("Exception in _create_response_tlv() '{}'".format(ex))
            return None
        
    def _verify_tlv(self, tlv):
        try:
            group, code = tlv['group'], tlv['code']
            if group in ["ces", "rloc", "payload"]:
                func   = CETP.VERIFY_TLV_GROUP[group][code]
                result = func(tlv=tlv, code=code, ces_params=self.ces_params, l_cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, packet=self.packet, \
                              cetp_security=self.cetp_security, policy = self.ces_policy, transaction=self, interfaces=self.interfaces, session_established=self.c2c_negotiation_status)
                return result
        except Exception as ex:
            self._logger.error("Exception in _verify_tlv() '{}'".format(ex))
            return False

    def _get_value(self, tlv):
        if 'value' in tlv:
            return tlv["value"]
        else:
            return None
        
    def get_localCES_rlocs(self, rrloc_tlv, policy):
        """ Extracts local RLOCs from ces-policy """
        lrloc_tlv = None
        if policy.has_available(rrloc_tlv):
            lrloc_tlv = self._create_offer_tlv(rrloc_tlv)
        
        return lrloc_tlv

    def _get_dp_connection_rlocs(self):
        l_rlocs, r_rlocs = [], []
        ope, group = "info", "rloc"
        rrloc_tlvs = self._get_from_tlvlist(self.received_tlvs, group, ope=ope)
        lrloc_tlvs = []
        
        #print("rrlocs: ", rrloc_tlvs)
        for rrloc_tlv in rrloc_tlvs:
            lrloc_tlv = self.get_localCES_rlocs(rrloc_tlv, self.ces_policy)
            lrloc_tlvs += lrloc_tlv
                
        l_rlocs, r_rlocs = self._filter_rlocs_list(lrloc_tlvs, rrloc_tlvs)       # Matches & Verifies the payload in the TLVs, and Removes duplicate RLOCs (on sender and receiver side)
        self.add_negotiated_params("lrlocs", l_rlocs)
        self.add_negotiated_params("rrlocs", r_rlocs)
        return (l_rlocs, r_rlocs)
    

    def _filter_rlocs_list(self, lrlocs_list, rrlocs_list):
        """ Extracts matching RLOCs b/w Local and Remote CES """
        
        def _build_list(tlvlist):
            """ Builds list of rloc_tlv values for comparison """
            retlist = []
            for p in tlvlist:
                if 'cmp' in p:
                    if p['cmp']=="notAvailable":
                        continue
                    
                pref, order, addr, alias = p["value"]
                addrtype = p["code"]
                if addrtype == "ipv4":
                    if CETP.is_IPv4(addr):
                        retlist.append((order, pref, addrtype, addr, alias))
                elif addrtype == "ipv6":
                    if CETP.is_IPv6(addr):
                        retlist.append((order, pref, addrtype, addr, alias))

            return retlist
    

        def _filter(base_rloc, cmp_rloc):
            """ Compares the local and remote RLOCs to filter unmatching RLOCs """ 
            lrlocs, rrlocs = [], []
            for p in range(0, len(base_rloc)):
                prloc = base_rloc[p]
                p_addrtype, p_alias = prloc[2], prloc[4]
                #self.logger.debug("# Evaluating p rloc: %s" % (str(prloc)))
                for q in range(0, len(cmp_rloc)):
                    qrloc = cmp_rloc[q]
                    q_addrtype, q_alias = qrloc[2], qrloc[4]
                    #self.logger.debug(">>> Evaluating q rloc: %s" % (str(qrloc)))
                    if p_addrtype == q_addrtype and p_alias == q_alias:
                        lrlocs.append(prloc)
                        rrlocs.append(qrloc)
                    
            return (lrlocs, rrlocs)


        lrlocs_list = _build_list(lrlocs_list)
        rrlocs_list = _build_list(rrlocs_list)
        lrlocs_list = list(set(lrlocs_list))        # Removes the duplicated RLOCs information in a list
        rrlocs_list = list(set(rrlocs_list))
        #print("Filtered Local_RLOCs_list & Remote_RLOCs_list: ", lrlocs_list, rrlocs_list)
        lrlocs, rrlocs = _filter(lrlocs_list, rrlocs_list)
        
        lrlocs = sorted(lrlocs, key=lambda s:s[0], reverse=True)
        rrlocs = sorted(rrlocs, key=lambda s:s[0], reverse=True)
        return (lrlocs, rrlocs)


    def _get_dp_connection_payloads(self):
        l_payloads, r_payloads = [], []
        group, ope = "payload", "info"
        r_payloads = self._get_from_tlvlist(self.received_tlvs, group, ope=ope)
        
        for rpayload in r_payloads:
            if self.ces_policy.has_available(rpayload):
                group, code = rpayload["group"], rpayload["code"]
                lpayload = self._create_offer_tlv2(group=group, code=code)
                l_payloads += lpayload
        
        lpayloads, rpayloads = self._filter_payload_list(l_payloads, r_payloads)
        self.add_negotiated_params("lpayloads", lpayloads)
        self.add_negotiated_params("rpayloads", rpayloads)
        return (lpayloads, rpayloads)


    def _filter_payload_list(self, sent_tlvlist, recv_tlvlist):
        """ @todo: Sort the payload lists , as per preference field? """
        def _build_list(tlvlist):
            """ Build a list based on the code field of the payload TLV: "ipv4", "ipv6", "ether" """
            retlist = []
            for p in tlvlist:
                if 'cmp' in p:
                    if p['cmp']=="notAvailable":
                        continue
                
                typ, pref = p["code"], p["value"]
                retlist.append((typ, pref))
            return retlist

        def _filter(base_payload, cmp_payload):
            """ Compares the local and remote RLOCs to filter unmatching RLOCs """ 
            lpayloads, rpayloads = [], []

            for p in range(0, len(base_payload)):
                p_pay = base_payload[p]
                if p_pay in cmp_payload:
                    lpayloads.append(p_pay)
                    rpayloads.append(p_pay)
                    
            return (lpayloads, rpayloads)

        
        r_payloads = _build_list(recv_tlvlist)
        l_payloads = _build_list(sent_tlvlist)          #Build the payload list for comparison
        l_payloads = list(set(l_payloads))
        r_payloads = list(set(r_payloads))
        (l_payloads, r_payloads) = _filter(l_payloads, r_payloads)
        
        l_payloads = sorted(l_payloads, key=lambda s:s[1], reverse=True)
        r_payloads = sorted(r_payloads, key=lambda s:s[1], reverse=True)
        return (l_payloads, r_payloads)
    
    def add_negotiated_params(self, code, value):
        self.negotiated_params[code] = value
    
    def get_negotiated_params(self):
        return self.negotiated_params
        
    def get_negotiated_parameter(self, key=None):
        """ Possible keys: 1) lrlocs, 2) rrlocs, 3) lpayloads, 4) rpayloads, """
        if key is not None:
            if key in self.negotiated_params:
                return self.negotiated_params[key]



class oC2CTransaction(C2CTransaction):
    """
    Negotiates outbound CES policies with the remote CES.
    Also contains methods to facilitate signalling in the post-c2c negotiation phase between CES nodes.
    """
    def __init__(self, loop, l_cesid="", r_cesid="", c_sstag=0, c_dstag=0, cetpstate_mgr=None, policy_client=None, policy_mgr=None, proto="tls", ces_params=None, \
                 cetp_security=None, remote_addr=None, interfaces=None, c2c_layer=None, conn_table=None, cetp_mgr=None, direction="outbound", name="oC2CTransaction"):
        self._loop                  = loop
        self.l_cesid                = l_cesid
        self.r_cesid                = r_cesid
        self.sstag                  = c_sstag
        self.dstag                  = c_dstag
        self.cetpstate_mgr          = cetpstate_mgr
        self.policy_client          = policy_client
        self.policy_mgr             = policy_mgr                            # Used in absence of the PolicyAgent to PolicyManagementSystem interaction.
        self.direction              = direction
        self.proto                  = proto                                 # Protocol of the CETP-Transport.
        self.ces_params             = ces_params
        self.remote_addr            = remote_addr
        self.cetp_security          = cetp_security
        self.c2c_layer              = c2c_layer
        self.interfaces             = interfaces
        self.conn_table             = conn_table
        self.rtt                    = 0
        self.packet_count           = 0
        self.last_packet_received   = None
        self.c2c_negotiation_status = False
        self.terminated             = False
        self._start_time            = time.time()
        self.name                   = name
        self.cetp_mgr               = cetp_mgr
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oC2CTransaction)
        self.cetp_negotiation_history  = []
        self.r_ces_requirements        = []                                 # To store list of remote CES requirements
        self.post_c2c_cbs              = {}
        self.unresponded_post_c2c_msg  = {}
        self.negotiated_params         = {} 

    def load_parameters(self):
        self.keepalive_cycle    = self.ces_params['keepalive_idle_t0']
        self.keepalive_timeout  = self.ces_params['keepalive_interval']
        self.completion_t0      = self.ces_params['incomplete_cetp_state_t0']
    
    def load_policies(self):
        """ Retrieves the policies stored in the Policy file"""
        self.oces_policy      = self.policy_mgr.get_ces_policy(proto=self.proto)
        self.oces_policy_tmp  = self.policy_mgr.get_policy_copy(self.oces_policy)
        self.ces_policy       = self.oces_policy
        return self.ces_policy

    def _initialize(self):
        """ Loads policies, generates session tags, and initiates event handlers """
        try:
            self.load_parameters()            
            self.sstag = self.generate_session_tags()
            
            if self.load_policies() is None:
                self._logger.error("Failure to load policies for local CES '{}'".format(self.l_cesid))
                return False
            
            return True
        except Exception as ex:
            self._logger.error(" Exception '{}' in initializing CES-to-CES session towards: '{}'".format(ex, self.r_cesid))
            return False
        
    def _schedule_completion_check(self):
        self.unregister_handler = self._loop.call_later(self.completion_t0, self._unregister_cb)

    def _unregister_cb(self):
        """ Unregisters the incomplete negotiation upon timeout """
        if not self.is_negotiated():
            self._logger.error("C2C negotiation towards '{}' did not complete in '{}' sec.".format(self.r_cesid, self.completion_t0))
            self.cetpstate_mgr.remove(self)
    
    def is_negotiated(self):
        return self.c2c_negotiation_status

    def set_negotiated(self, status=True):
        self.c2c_negotiation_status = status
        
    @asyncio.coroutine
    def initiate_c2c_negotiation(self):
        """ Sends C2C policy offers and requirements to remote CES """
        try:
            if not self._initialize():
                self._logger.error(" Failure in initiating CES-to-CES session towards: '{}'".format(self.r_cesid))
                return None
            
            tlvs_to_send = []
            #self._logger.info(" Starting CES-to-CES session towards '{}' (SST={} -> DST={})".format(self.sstag, self.dstag, self.r_cesid))
            #self._logger.debug("Outbound policy: ", self.ces_policy)
            
            # Offered TLVs
            for otlv in self.ces_policy.get_offer():
                ret_tlv = self._create_offer_tlv(otlv)
                if ret_tlv != None:
                    tlvs_to_send +=  ret_tlv
                
            # Required TLVs
            for rtlv in self.ces_policy.get_required():
                ret_tlv = self._create_request_tlv(rtlv)
                if ret_tlv != None:
                    tlvs_to_send +=  ret_tlv
            
            cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
            self.pprint(cetp_message, m="Outbound packet")
            self.cetpstate_mgr.add(self)
            self._schedule_completion_check()                   # Callback to unregister the incomplete C2C transaction
            self.last_packet_sent = cetp_message
            self._start_time = time.time()
            return cetp_message
        
        except Exception as ex:
            self._logger.error(" Exception '{}' in initiating CES-to-CES session towards: '{}'".format(ex, self.r_cesid))
            return None
    
    def set_terminated(self, terminated=True):
        self.terminated = terminated
        self.cetpstate_mgr.remove(self)

        if self.is_negotiated():
            self.conn_table.delete(self.conn)
        
        if hasattr(self, 'unregister_handler'):
            self.unregister_handler.cancel()
        
    def get_remote_cesid(self):
        return self.r_cesid
    
    def _pre_process(self, cetp_msg):
        """ Pre-processing to check for the version field, session tags & format of TLVs in the inbound packet.
            AND, checks whether the inbound packet is a request message.
        """
        try:
            self.query_message = False
            self.get_packet_details(cetp_msg)

            if len(self.received_tlvs) == 0:
                self._logger.error(" The inbound packet ({}->{}) contains no TLV to be processed.".format(self.sstag, self.dstag))
                return False
            
            for received_tlv in self.received_tlvs:
                if self._check_tlv(received_tlv, ope="query"):
                    self.query_message = True
                    break
                
            return True
        
        except Exception as ex:
            self._logger.error(" Exception '{}' in pre-processing the CETP packet from '{}'".format(ex, self.r_cesid))
            return False
         

    def continue_c2c_negotiation(self, cetp_message):
        """ Continues CES policy negotiation towards remote CES """
        #try:
        #self._logger.info(" Continuing CES-to-CES session negotiation (SST={} -> DST={}) towards '{}'".format(self.sstag, 0, self.r_cesid))
        #self._logger.info(" Outbound policy: ", self.ces_policy)
        self.pprint(cetp_message, m="Inbound Response packet")
        negotiation_status, error = None, False
        tlvs_to_send, error_tlvs  = [], []
        self.rtt                  += 1
        cetp_resp                 = ""
        
        if self.rtt > NEGOTIATION_RTT_THRESHOLD:
            self._logger.error(" CES-to-CES negotiation towards '{}' exceeded {} RTTs".format(self.r_cesid, NEGOTIATION_RTT_THRESHOLD))
            negotiation_status = False
            return (negotiation_status, cetp_resp)

        if not self._pre_process(cetp_message):
            self._logger.error(" Failure to pre-process the C2C-CETP packet from '{}'.".format(self.r_cesid))
            return (negotiation_status, cetp_resp)                          
        
        """
        Processing logic:
            If pre-processing determined that inbound packet is (or contains) a request message, oCES sends response & issue local CES policy queries.
            If message contains no query, it is treated as a response message.     If all TLVs could be verified, the message is accepted. Otherwise, oCES sends terminate-TLV, if iCES has already completed (SST, DST) state.
        """
        
        # Processing inbound packet
        for received_tlv in self.received_tlvs:
            
            if self.query_message:
                if self._check_tlv(received_tlv, ope="query"):
                    if self.ces_policy.has_available(received_tlv):
                        ret_tlv = self._create_response_tlv(received_tlv)
                        if ret_tlv !=None:
                            self.r_ces_requirements.append(received_tlv)
                            tlvs_to_send += ret_tlv
                            continue
                            
                    if self._check_tlv(received_tlv, cmp="optional"):
                        #self._logger.info(" A remote optional required TLV {}.{} is not available.".format(received_tlv['group'], received_tlv['code']))
                        ret_tlv = self._get_unavailable_response(received_tlv)
                        tlvs_to_send.append(ret_tlv)
                    else:
                        if self._check_tlv2(received_tlv, group=["rloc", "payload"]):
                            #self._logger.info(" A remote required TLV {}.{} is not available.".format(received_tlv['group'], received_tlv['code']))
                            ret_tlv = self._get_unavailable_response(received_tlv)
                            tlvs_to_send.append(ret_tlv)
                        else:
                            self._logger.error("'{}.{}' TLV requested by remote CES is not locally available.".format(received_tlv['group'], received_tlv['code']))
                            error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                            error = True
                            break
                        
            #A CETP info message is processed for: Policy Matching and TLV Verification. The message can have: 1) Less than required TLVs; 2) TLVs with wrong value; 3) a notAvailable TLV; OR 4) a terminate TLV.
            elif self._check_tlv(received_tlv, ope="info"):
                if (received_tlv['group'] == 'ces') and (received_tlv['code']=='terminate'):
                    self._logger.info(" Terminate-TLV received with value: {}".format(received_tlv['value']) )
                    error = True
                    break

                elif self.ces_policy.has_required(received_tlv):
                    if self._verify_tlv(received_tlv):
                        self.oces_policy_tmp.del_required(received_tlv)
                    else:
                        # Absorbs failure in case of 'optional' required policy TLV
                        if not self.ces_policy.is_mandatory_required(received_tlv):
                            self.oces_policy_tmp.del_required(received_tlv)
                        else:
                            print("received_tlv: ", received_tlv)
                            if self._check_tlv2(received_tlv, group=["rloc", "payload"]) and (self._check_tlv(received_tlv, cmp="notAvailable")):           # Limiting type of failure that is acceptable from remote CES.
                                self._logger.info(" A locally required TLV {}.{} is not available.".format(received_tlv['group'], received_tlv['code']))
                                error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                                self.oces_policy_tmp.del_required(received_tlv)
                            else:
                                self._logger.error("TLV {}.{} failed verification".format(received_tlv['group'], received_tlv['code']))
                                error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                                error = True
                                break
                else:
                    #self._logger.warning("Unrequested TLV '{}.{}' is received".format(received_tlv["group"], received_tlv["code"]))
                    pass

        # Evaluation of Policy Matching        
        if error:
            self._logger.error(" CES-to-CES policy negotiation with remote CES '{}' failed in {} RTT".format(self.r_cesid, self.rtt))
            self._process_negotiation_failure()
            negotiation_status = False
            
            if self.dstag==0:
                return (negotiation_status, "")                                               # Locally terminate connection, as iCES is stateless
            else:
                self._logger.info(" Responding remote CES with terminate-TLV")                # Since remote CES has completed the transaction
                cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=error_tlvs)
                self.cetp_negotiation_history.append(cetp_message)
                self.pprint(cetp_message, m="Outbound CETP Error")
                return (negotiation_status, cetp_message)
            
        else:
            if self._is_ready():
                if self._create_connection():
                    self._logger.info(" '{}'\n C2C policy negotiation succeeded in {} RTT with CES '{}'".format(30*'#', self.rtt, self.r_cesid))
                    self._process_negotiation_success()
                    self.c2c_negotiation_status = True
                    return (self.c2c_negotiation_status, "")
                else:
                    self._logger.error(" C2C Negotiation failure with CES '{}' -> Responding remote CES with the terminate-TLV".format(self.r_cesid))
                    self._process_negotiation_failure()
                    tlvs_to_send = [self._get_terminate_tlv()]
                    if len(error_tlvs) != 0:   tlvs_to_send = error_tlvs
                    
                    cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                    self.pprint(cetp_message, m="Outbound Msg")
                    negotiation_status = False
                    return (negotiation_status, cetp_message)
                
            else:
                if self.rtt < NEGOTIATION_RTT_THRESHOLD:
                    # Issuing oCES Full query
                    for rtlv in self.ces_policy.get_required():
                        ret_tlv = self._create_request_tlv(rtlv)
                        if ret_tlv!=None:
                            tlvs_to_send += ret_tlv
                            
                    negotiation_status = None
                    cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=0, tlvs=tlvs_to_send)
                    self.last_packet_sent = cetp_message
                    self.last_packet_received = self.packet
                    self.cetp_negotiation_history.append(cetp_message)
                    self.pprint(cetp_message, m="Sent packet")
                    return (negotiation_status, cetp_message)

                else:
                    self._logger.error(" Remote CES '{}' didn't meet the oCES policy requirements in {} RTT".format(self.r_cesid, self.rtt))
                    self._process_negotiation_failure()
                    cetp_resp = ""
                    
                    if self.dstag!=0:
                        tlvs_to_send = [self._get_terminate_tlv()]
                        cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                        self.pprint(cetp_message)
                        negotiation_status = False
                        return (negotiation_status, cetp_message)
                    else:
                        return (negotiation_status, cetp_resp)
                        
        #except Exception as msg:
        #    #self._logger.info(" Exception in resolving C2C transaction: {}".format(msg))
        # return                        # What value shall it return in this case?

    def _is_ready(self):
        return (len(self.oces_policy_tmp.required)==0) and self.dstag!=0

    def _process_negotiation_failure(self):
        """ Steps to execute on failure of negotiation """
        self.cetpstate_mgr.remove(self)                # Since transaction didn't completed at oCES yet.
        self.unregister_handler.cancel()
        
    def _process_negotiation_success(self):
        """ State management of established C2C transaction, and triggering the negotiated functions """
        self.cetpstate_mgr.reregister(self)
        self.unregister_handler.cancel()
        self.trigger_negotiated_functionality()
        return True

    def _create_connection(self):
        """ Extract the negotiated parameters to create a connection state """
        try:
            self.lrloc, self.rrloc          = self._get_dp_connection_rlocs()
            self.lpayload, self.rpayload    = self._get_dp_connection_payloads()
            self._logger.info(" Negotiated params: {}".format(self.get_negotiated_params()))
            
            if len(self.lrloc)==0 or len(self.rrloc)==0:
                self._logger.error("C2C negotiation with CES '{}' didn't provide RLOC information".format(self.r_cesid))
                return False
                
            if len(self.lpayload)==0 or len(self.rpayload)==0:
                self._logger.error("C2C negotiation with CES '{}' didn't provide Payload information.".format(self.r_cesid))
                return False
            
            keytype = ConnectionTable.KEY_MAP_RCESID_C2C
            key = self.r_cesid
            if not self.conn_table.has(keytype, key):
                self.conn = ConnectionTable.C2CConnection(self.l_cesid, self.r_cesid, self.lrloc, self.rrloc, self.lpayload, self.rpayload)
                self.conn_table.add(self.conn)                
            
            return True
        except Exception as ex:
            self._logger.error("Exception in _create_connection(): '{}'".format(ex))
            return False
        
    def lookupkeys(self):
        if self.is_negotiated():
            keys = [(KEY_ESTABLISHED_TAGS, (self.sstag, self.dstag), False), (KEY_CES_IDS, (self.l_cesid, self.r_cesid), False), (KEY_RCESID, self.r_cesid, True)]
        else:
            keys = [(KEY_INITIATED_TAGS, (self.sstag, 0), False), (KEY_CES_IDS, (self.l_cesid, self.r_cesid), False), (KEY_RCESID, self.r_cesid, True)]

        return keys
    
    def _assign_c2c_layer(self, c2c_layer):
        """ Assigned by CETP Manager """
        self.c2c_layer = c2c_layer
    
    def get_cetp_terminate_msg(self, error_tlv=None):
        terminate_tlv = self._create_offer_tlv2(group="ces", code="terminate")
        if terminate_tlv != None:
            if error_tlv != None:   terminate_tlv["value"] = error_tlv
                
            cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=terminate_tlv)
            return cetp_message
    
    def send_cetp_terminate(self, error_tlv=None):
        """ Sends a terminate TLV towards remote CES """
        cetp_message = self.get_cetp_terminate_msg(error_tlv=error_tlv)
        self._send(cetp_message)
    
    def trigger_negotiated_functionality(self):
        """ Triggers the flist of functions negotiated with remote CES upon completion of the C2C negotiation. """
        functionalities_code = ["keepalive"]

        if len(self.r_ces_requirements) !=0:                       # List of accepted queries of remote CES
            for f in functionalities_code:
                if self._is_requested_functionality(f):
                    
                    # Send keepalives, if the remote CES requested it (& if you negotiated).
                    if f == "keepalive":
                        self._logger.info(" Remote end requires keepalive")
                        #Add the process for getting keepalive values
                        
        elif self.rtt==1:                                          # A negotiation may complete in 1-RTT, so CES must support the promised policy offers.
            for otlv in self.ces_policy.get_offer():
                if self._check_tlv(otlv, group="ces"):
                    if otlv['code'] == "keepalive":
                        #Add the process for getting keepalive values
                        pass

    def _is_requested_functionality(self, fun):
        for received_tlv in self.r_ces_requirements:
            if self._check_tlv(received_tlv, ope="query") and self._check_tlv(received_tlv, group="ces") and received_tlv['code']==fun and self.ces_policy.has_available(received_tlv):
                return True
        return False
    
    def update_last_seen(self):
        self.last_seen = time.time()

    def feedback_report(self):
        # Function for reporting feedback to remote CES.
        pass

    def report_misbehavior_evidence(self, h_sstag, h_dstag, r_hostid, misbehavior_evidence):
        """ Reports misbehavior evidence observed in (h_sstag, h_dstag) to the remote CES """
        #self._logger.info(" Sending misbehavior evidence towards remote CES '{}' )".format(self.r_cesid, r_hostid))
        evidence = {"h2h_session":(h_sstag, h_dstag), "misbehavior":misbehavior_evidence}             # misbehavior_evidence="FSecure-MalwarePayload"
        evidence_value = json.dumps(evidence)
        evidence_tlv = self._create_request_tlv2(group="ces", code="evidence", value=evidence_value)
        tlvs_to_send = evidence_tlv
        self.seek_response(tlvs_to_send)
        
    def block_remote_host(self, r_hostid):
        #self._logger.info(" Blocking a remote host '{}' at remote CES '{}'.".format(r_hostid, self.r_cesid))
        blocking_msg = {"remote_host": r_hostid}             # misbehavior_evidence="FSecure-MalwarePayload"
        blocking_payload = json.dumps(blocking_msg)
        host_filter_tlv = self._create_request_tlv2(group="ces", code="host_filtering", value=blocking_payload)
        tlvs_to_send = host_filter_tlv
        self.seek_response(tlvs_to_send)        
        
    def drop_connection_to_local_domain(self, l_domain):
        #self._logger.info(" Preventing remote CES '{}' from forwarding traffic to '{}'.".format(self.r_cesid, l_domain))
        blocking_msg = {"local_domain": l_domain}             # misbehavior_evidence="FSecure-MalwarePayload"
        blocking_payload = json.dumps(blocking_msg)
        host_filter_tlv = self._create_request_tlv2(group="ces", code="host_filtering", value=blocking_payload)
        tlvs_to_send = host_filter_tlv
        self.seek_response(tlvs_to_send)        

    def drop_all_h2h_sessions(self):
        self._logger.warning(" Closing all H2H sessions with remote CES '{}'.".format(self.r_cesid))
        h2h_sessions = {"sessions": '*' }
        host_filter_tlv = self._create_offer_tlv2(group="ces", code="terminate", value=h2h_sessions)
        tlvs_to_send = host_filter_tlv
        self.send_message(tlvs_to_send)

    def drop_h2h_sessions(self, tags_list):
        """ Provide a list of (SST, DST) pairs for H2H sessions that shall be closed """
        self._logger.warning(" Closing all H2H sessions with remote CES '{}'.".format(self.r_cesid))
        h2h_sessions = {"sessions": tags_list }
        host_filter_tlv = self._create_offer_tlv2(group="ces", code="terminate", value=h2h_sessions)
        tlvs_to_send = host_filter_tlv
        self.send_message(tlvs_to_send)
        
    def get_ack_request_tlv(self):
        tlv = self._create_request_tlv2(group="ces", code="ack")
        return tlv
    
    def _send(self, cetp_message):
        self.c2c_layer.send_cetp(cetp_message)
    
    def send_message(self, tlvs_to_send):
        """ Method to send TLVs that do not need any acknowledgement """
        cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
        self._send(cetp_message)
    
    def seek_response(self, tlvs_to_send, timeout=10):
        """ Sends request TLVs towards remote CES, after appending ack-tlv.        And schedules a callback to check the acknowledgement message.
            On an established C2C transaction, A CES node could send requests triggered by local Events, Thresholds, Handlers, Security modules, or Admin commands etc.
             # Example of requests/events: 1) terminate host session (for non-compliance); 2) keepalives; 3) new SSL key_negotiation; 4) new session_limit; 5) misbehavior evidences; 6) block_host; 7) ratelimiting the sender, destination. """
        try:
            ack_tlv = self.get_ack_request_tlv()[0]
            tlvs_to_send.append(ack_tlv)
            ack_value = self._get_value(ack_tlv)           # Assure that no two messages pending acknowledgement have the same ack-id value
            
            if ack_value != None:
                cb = self._loop.call_later(timeout, self._unresponsive_ack_cb, ack_value, tlvs_to_send)
                self.post_c2c_cbs[ack_value]=(cb, tlvs_to_send)
                self.send_message(tlvs_to_send)
            
        except Exception as ex:
            self._logger.error("Exception '{}' in seek_response() to '{}'. (sst={}, dst={})".format(ex, self.r_cesid, self.sstag, self.dstag))
            return

    def _process_ack_response(self, ack_value):
        (cb, sent_tlvs) = self.post_c2c_cbs[ack_value]
        cb.cancel()
        del self.post_c2c_cbs[ack_value]
    
    def _unresponsive_ack_cb(self, ack_value, sent_tlvs):
        self._logger.error(" CES-ID '{}' didn't respond to post-c2c-negotiation query (sst={}, dst={})".format(self.r_cesid, self.sstag, self.dstag))
        self.unresponded_post_c2c_msg[ack_value] = sent_tlvs
        del self.post_c2c_cbs[ack_value]
        
    def _has_requested(self, tlvlist, code):
        for tlv in tlvlist:
            if tlv["code"]== code:
                return True
        return False
    
    def _shutdown_c2c(self):
        self.c2c_layer.shutdown()

    def _process_terminate_tlv(self, received_tlv):
        """ Processing the received TLV to terminate C2C connectivity, OR 1 or more H2H sessions """
        value = self._get_value(received_tlv)
        print("Value:", value)
        
        if (value is None) or (value is '') or ('tlv' in value): 
            self._logger.info(" Terminate received with value: {}".format(received_tlv['value']) )
            self._shutdown_c2c()
        
        elif 'sessions' in value:
            h2h_sessions = value["sessions"]
            
            if h2h_sessions == "*":
                self._logger.warning(" Remote CES '{}' requests to close all the H2H sessions.".format(self.r_cesid))
                self.cetp_mgr.process_session_terminate_message(self.r_cesid)
                
            elif type(h2h_sessions) == type(list()):
                self._logger.warning(" Remote CES requested to close {} H2H sessions.".format(len(h2h_sessions)))
                self.cetp_mgr.process_session_terminate_message(self.r_cesid, tag_list = h2h_sessions)
            
        
    def post_c2c_negotiation(self, cetp_msg):
        """
        Processes a CETP packet received on an established CES-to-CES session.
        A message can be either a Response or Request message, indicated by the presence or absence of 'info.ces.ack' tlv. Only exception being 'info.terminate'
        A request message comes from remote CES based on some internal thresholds triggering actions on remote CES.
        Whereas, the response message comes in response to the request message sent earlier to remote CES.

        Processing:
            Upon requests,  CES must respond to the ACK-TLV in CETP message, but might not or might respond to individual query-TLVs (with Acceptable/Non-acceptable values).
            Upon responses, CES node only processes the message if value of ACK-TLV in message corresponds to a sent value.
        """
        
        #self._logger.info(" Post-C2C negotiation packet from '{}' (SST={}, DST={})".format(self.r_cesid, self.sstag, self.dstag))
        self.pprint(cetp_msg, m="Inbound packet")
        self.recvd_tlvs    = cetp_msg['TLV']

        if len(self.recvd_tlvs) == 0:
            return                              # No TLVs to process

        tlvs_to_send = []
        sent_tlvs    = []
        is_response  = False
        ack_resp_tlv  = self._get_from_tlvlist(self.recvd_tlvs, "ces", code="ack", ope="info")
        #print("ack_resp_tlv: ", ack_resp_tlv)
        
        #Check if 'ack_resp_tlv' exists, to determine if the inbound CETP message is a response to requests sent by this CES node.
        if len(ack_resp_tlv) != 0:
            ack_tlv = ack_resp_tlv[0]
            ack_id = self._get_value(ack_tlv)
            if ack_id not in self.post_c2c_cbs:
                self._logger.warning(" Unrequested packet from CES '{}' is received.".format(self.r_cesid))
                return                  # Unrequested packet from CES
            else:
                self._logger.debug(" Evaluating the response against sent requests. ACK-ID {}".format(ack_id))
                (cb, sent_tlvs) = self.post_c2c_cbs[ack_id]
                self._process_ack_response(ack_id)
                is_response = True

        if is_response:
            for received_tlv in self.recvd_tlvs:
                # Process the responses received for requested TLVs only
                if self._check_tlv(received_tlv, ope="info") and self._check_tlv(received_tlv, group="ces"):
                    
                    if self._has_requested(sent_tlvs, received_tlv["code"]):
                        if self._check_tlv(received_tlv, code="ack"):
                            pass                                                # Already processed
                        elif self._check_tlv2(received_tlv, code=["evidence", "host_filtering"]):
                            self._logger.info(" {} ACKed: {}".format(code, received_tlv["value"]))
                        else:
                            if self._verify_tlv(received_tlv):
                                self._logger.debug(" '{}.{}' TLV is verified in post-c2c negotiation.".format(received_tlv["group"], received_tlv["code"]))
                                pass
                            else:
                                self._logger.warning(" Response TLV '{}.{}' failed verification in post-c2c (SST={}, DST=={})".format(received_tlv['group'], received_tlv['code'], self.sstag, self.dstag) )
                                # Process the unsatisfied queries in CETPManager, expect no compliance from remote end.
                                # Aggregate all the non-compliance responses & display to admin for decison-making discretion
                                # self.last_packet.queries.satisfied(tlv, False)        # Unsatisfied policy requirements
                                break
                    
                    #  By default, assume the unacked TLVs as answered?
    
                        
        else:
            # Absence of 'ack_resp_tlv' indicates inbound CETP is not a response message. And (mostly) contains request from the sender.
            for received_tlv in self.recvd_tlvs:
                
                if self._check_tlv(received_tlv, ope="info") and self._check_tlv(received_tlv, group="ces"):
                    if self._check_tlv(received_tlv, code="terminate"):
                        self._process_terminate_tlv(received_tlv)
                        
                # Processing the inbound request TLVs
                elif self._check_tlv(received_tlv, ope="query") and self._check_tlv(received_tlv, group="ces"):
                    
                    if self.ces_policy.has_available(received_tlv):
                        ret_tlv = self._create_response_tlv(received_tlv)
                        if ret_tlv !=None:
                            tlvs_to_send += ret_tlv
                        else:
                            self._logger.warning(" Error responding to '{}.{}' TLV request in post-c2c negotiation (SST={}, DST={})".format(received_tlv['group'], received_tlv['code'], self.sstag, self.dstag))
                            ret_tlv = self._get_unavailable_response(received_tlv)
                            tlvs_to_send += ret_tlv
    
                    # Check if the remote CES is sending request for a supported policy element.
                    elif self._check_tlv2(received_tlv, code=["evidence", "host_filtering"]):
                        self._logger.warning(" '{}.{}' TLV request is received from remote CES '{}'".format(received_tlv["code"], received_tlv["code"], self.r_cesid))
                        continue
                        
                    elif self._check_tlv(received_tlv, code = "ack"):
                        ret_tlv = self._create_response_tlv(received_tlv, post_c2c=True)
                        tlvs_to_send += ret_tlv
                        continue
                    
                    elif self._check_tlv(received_tlv, code = "comment"):
                        # General commentary from remote CES (or its admin), displayed to NW admin... Allowing cooperation enhancement at human level. Good idea?
                        self._logger.info("General comment: {}".format(received_tlv['value']))          # Should be stored in CETPSecurity module?
                        pass
                    
                    else:
                        self._logger.warning(" Unsupported TLV '{}.{}' request is received in post-c2c negotiation".format(received_tlv['group'], received_tlv['code'], self.sstag, self.dstag))
                        ret_tlv = self._get_unavailable_response(received_tlv)
                        tlvs_to_send += ret_tlv

        
        if len(tlvs_to_send) != 0:
            cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
            self.pprint(cetp_message, m="Sending Post-C2C packet")
            self._send(cetp_message)

"""
Just a thought:
    C2C has two kinda TLV elements:
        1) Which represent CES policy elements, and are required for initial CES-to-CES negotiation, i.e. for authentication & security etc.
        2) There are other TLVs which are used at a later stage.  For example, to block a sender/receiver host, connection termination.

    Should the second type of TLV elements too be negotiated with remote CES? or Assumed as default capabilities?
        1) perhaps as part of a capability-TLV? and should these capabilites too be policy controlled? If yes, shall they be policy controlled & differentiate from 1st set of policy elements? in policy file (and negotiation)?
        2) Should a basic->derived TLV relation be defined between TLVs? For example, if A is supported, B&C are supported too. 
        
        For now, capabilities are assumed as default.
        
Another possible post-c2c work:
    Given the reliable delivery by underlying transport.
    Some TLV elements don't need ACKs, and rather they shall be immediately acted upon. For example, 'block_host' or 'filter_host' messages. 
        For these, 'info.host_filter' shall be supported instead of 'req.host_filter' etc.
"""



LOGLEVEL_iC2CTransaction        = logging.INFO

class iC2CTransaction(C2CTransaction):
    def __init__(self, loop, sstag=0, dstag=0, l_cesid="", r_cesid="", l_addr=(), r_addr=(), policy_mgr= None, policy_client=None, cetpstate_mgr= None, ces_params=None, \
                 cetp_security=None, interfaces=None, conn_table=None, proto="tcp", cetp_mgr=None, name="iC2CTransaction"):
        self._loop                      = loop
        self.local_addr                 = l_addr
        self.remote_addr                = r_addr
        self.policy_mgr                 = policy_mgr                # This could be policy client in future use.
        self.cetpstate_mgr              = cetpstate_mgr
        self.l_cesid                    = l_cesid
        self.r_cesid                    = r_cesid
        self.proto                      = proto
        self.direction                  = "inbound"
        self.sstag                      = sstag
        self.dstag                      = dstag
        self.ces_params                 = ces_params
        self.cetp_security              = cetp_security
        self.interfaces                 = interfaces
        self.name                       = name
        self.conn_table                 = conn_table
        self.c2c_negotiation_status     = False
        self.cetp_mgr                   = cetp_mgr
        self.r_ces_requirements         = []
        self.keepalive_timeout          = ces_params['keepalive_interval']
        self._logger                    = logging.getLogger(name)
        self.negotiated_params          = {} 
        self._logger.setLevel(LOGLEVEL_iC2CTransaction)        
        
    def load_policies(self):
        """ Retrieves the policies stored in the policy file"""
        self.ices_policy, self.ices_policy_tmp  = None, None
        self.ices_policy        = self.policy_mgr.get_ces_policy(proto=self.proto)
        self.ices_policy_tmp    = self.policy_mgr.get_policy_copy(self.ices_policy)
        self.ces_policy         = self.ices_policy
        return self.ces_policy
        
    def _pre_process(self, cetp_msg):
        """ Pre-process the inbound packet for the minimum necessary details, AND loads the CES-to-CES policies. """
        try:
            r_cesid = ""
            self.get_packet_details(cetp_msg)

            if len(self.received_tlvs) == 0:
                self._logger.debug("Inbound CETP has no TLVs for processing")
                return False

            for received_tlv in self.received_tlvs:
                if self._check_tlv(received_tlv, ope="info"):
                    if self._check_tlv(received_tlv, group="ces") and self._check_tlv(received_tlv, code="cesid"):
                        r_cesid = received_tlv['value']
                        break
            
            if len(r_cesid)==0 or len(r_cesid) > 256 or (r_cesid != self.r_cesid) or (r_cesid==self.l_cesid):
                self._logger.error(" Invalid Remote CES-ID '{}'".format(r_cesid))
                return False

            if self.load_policies() is None:
                self._logger.error("Failure to load the CES policies '{}'".format(self.l_cesid))
                return False
            
            return True
        
        except Exception as ex:
            self._logger.error(" Exception in pre-processing the CETP packet: '{}'".format(ex))
            return False
    
    def process_c2c_transaction(self, cetp_message):
        """ Processes the inbound CETP-packet for negotiating the CES-to-CES (CETP) policies """
        #self._logger.info("{}\n {}".format(42*'*', self.ices_policy))
        #self._logger.info("{}".format(42*'*') )
        self.pprint(cetp_message, m="Inbound packet")
        tlvs_to_send, error_tlvs = [], []
        negotiation_status       = None
        cetp_response            = ""
        error                    = False
        #time.sleep(3)
        
        if not self._pre_process(cetp_message):
            self._logger.error("Inbound CETP packet ({}->{}) failed pre-processing()".format(self.sstag, self.dstag))
            negotiation_status = False
            return (negotiation_status, cetp_response)
        
        for received_tlv in self.received_tlvs:
            # Verification and matching of Offers in the inbound packet, with iCES policy requirements.
            if self._check_tlv(received_tlv, ope="info"):
                
                if self._check_tlv(received_tlv, group="ces") and self._check_tlv(received_tlv, code= "terminate"):
                    self._logger.warning(" Terminate-TLV with payload '{}' received".format(received_tlv['value']) )      # stateless iCES shall not receive terminate TLV.
                    return (False, cetp_response)
                
                elif self.ices_policy_tmp.has_required(received_tlv):
                    if self._verify_tlv(received_tlv):
                        self.ices_policy_tmp.del_required(received_tlv)
                    else:
                        # Absorbs failure in case of 'optional' required policy TLV
                        if not self.ices_policy.is_mandatory_required(received_tlv):
                            self.ices_policy_tmp.del_required(received_tlv)
                        else:
                            if self._check_tlv2(received_tlv, group=["rloc", "payload"]):
                                #self._logger.info(" Locally required TLV {}.{} is not available.".format(received_tlv['group'], received_tlv['code']))
                                error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                                self.ices_policy_tmp.del_required(received_tlv)
                            else:
                                #self._logger.info("TLV {}.{} failed verification".format(received_tlv['group'], received_tlv['code']))
                                error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                                error = True
                                break
                else:
                    #self._logger.debug("Non-requested TLV {} is received: ".format(received_tlv))
                    pass

        # Check to prevent processing of policy requests in the inbound packet, if the remote CES made invalid offers
        if not error:
            for received_tlv in self.received_tlvs:
                # Responds the remote CES requirements, with available policies or the 'notAvailable' attribute.
                if self._check_tlv(received_tlv, ope="query"):
                    
                    if self.ices_policy.has_available(received_tlv):
                        ret_tlv = self._create_response_tlv(received_tlv)
                        if ret_tlv!=None:
                            self.r_ces_requirements.append(received_tlv)
                            tlvs_to_send += ret_tlv
                            continue
                        
                    if self._check_tlv(received_tlv, cmp="optional"):
                        #self._logger.info(" A remote-CES required optional TLV {}.{} is not available.".format(received_tlv['group'], received_tlv['code']))
                        ret_tlv = self._get_unavailable_response(received_tlv)
                        tlvs_to_send.append(ret_tlv)
                    else:
                        if self._check_tlv2(received_tlv, group=["rloc", "payload"]):
                            #self._logger.info(" A remote-CES required TLV {}.{} is not available.".format(received_tlv['group'], received_tlv['code']))
                            ret_tlv = self._get_unavailable_response(received_tlv)
                            tlvs_to_send.append(ret_tlv)
                        else:
                            self._logger.info("'{}.{}' TLV required by remote-CES is not available.".format(received_tlv['group'], received_tlv['code']))
                            error_tlvs += [self._get_terminate_tlv(err_tlv=received_tlv)]
                            error = True
                            break
        
        if error:
            tlvs_to_send        = error_tlvs
            negotiation_status  = False
        else:
            if self._is_ready():                    # Checks if all the local CES requirements are met
                # Create CETP connection
                if self._create_connection():
                    #self._logger.info("{} C2C-policy negotiation succeeded -> Created stateful transaction (SST={}, DST={})".format(30*'*', self.sstag, self.dstag) )
                    stateful_transaction = self._export_to_stateful()            #Export to stateful transaction for CETP messages in post-c2c negotiation
                    stateful_transaction.last_packet_received = self.packet
                    self._process_negotiation_success()
                    negotiation_status = True
                else:
                    if len(error_tlvs) == 0:    
                        error_tlvs = [self._get_terminate_tlv()]
                    tlvs_to_send        = error_tlvs
                    negotiation_status  = False
                    
            else:
                #self._logger.info(" Inbound packet didn't meet all the policy requirements.")
                negotiation_status = None
                #Generate the Full Query message
                tlvs_to_send = []
                for rtlv in self.ices_policy.get_required():            
                    ret_tlv = self._create_request_tlv(rtlv)
                    if ret_tlv != None:
                        tlvs_to_send +=ret_tlv

                
        cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
        if negotiation_status is True:  stateful_transaction.last_packet_sent     = cetp_message
        self.pprint(cetp_message, m="CETP Response")
        return (negotiation_status, cetp_message)

    
    def _is_ready(self):
        """ Returns True, if all the local CES requirements are met by the inbound packet """
        return len(self.ices_policy_tmp.required)==0

    def _process_negotiation_success(self):
        self.add_negotiated_params("lcesid", self.l_cesid)
        self.add_negotiated_params("rcesid", self.r_cesid)
    
    def _create_connection(self):
        try:
            self.sstag                      = self.generate_session_tags(self.dstag)
            self.lrloc, self.rrloc          = self._get_dp_connection_rlocs()
            self.lpayload, self.rpayload    = self._get_dp_connection_payloads()
            self._logger.info(" Negotiated params: {}".format(self.get_negotiated_params()))            
            
            if len(self.lrloc)==0 or len(self.rrloc)==0:
                self._logger.error(" Remote CES '{}' didn't negotiate RLOC information in C2C negotiation".format(self.r_cesid))
                return False
                
            if len(self.lpayload)==0 or len(self.rpayload)==0:
                self._logger.error(" Remote CES '{}' didn't negotiate  Payload information in C2C negotiation.".format(self.r_cesid))
                return False
            
            keytype = ConnectionTable.KEY_MAP_RCESID_C2C
            key = self.r_cesid
            if not self.conn_table.has(keytype, key):
                self.conn = ConnectionTable.C2CConnection(self.l_cesid, self.r_cesid, self.lrloc, self.rrloc, self.lpayload, self.rpayload)
                self.conn_table.add(self.conn)
                
            return True
        
        except Exception as ex:
            self._logger.error("Exception in _create_connection(): '{}'".format(ex))
            return False

    def _export_to_stateful(self):
        new_transaction = oC2CTransaction(self._loop, l_cesid=self.l_cesid, r_cesid=self.r_cesid, c_sstag=self.sstag, c_dstag=self.dstag, policy_mgr= self.policy_mgr, \
                                          cetpstate_mgr=self.cetpstate_mgr, ces_params=self.ces_params, proto=self.proto, direction="inbound", \
                                          cetp_security=self.cetp_security, conn_table=self.conn_table, cetp_mgr=self.cetp_mgr)
        
        new_transaction.ces_policy              = self.ces_policy
        new_transaction.c2c_negotiation_status  = True
        new_transaction.r_ces_requirements      = self.r_ces_requirements
        new_transaction.last_packet_received    = self.packet
        new_transaction.load_parameters()
        new_transaction.negotiated_params       = self.negotiated_params
        new_transaction.conn                    = self.conn
        self.cetpstate_mgr.add(new_transaction)
        new_transaction.trigger_negotiated_functionality()
        return new_transaction
