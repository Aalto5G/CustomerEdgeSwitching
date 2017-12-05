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

LOGLEVELCETP                    = logging.DEBUG
LOGLEVEL_C2CTransaction         = logging.INFO
LOGLEVEL_oC2CTransaction        = logging.INFO
LOGLEVEL_iC2CTransaction        = logging.INFO

NEGOTIATION_RTT_THRESHOLD       = 3

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


class C2CTransaction(object):
    def __init__(self, name="C2CTransaction"):
        self.name       = name
        self._logger    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_C2CTransaction)

    def get_cetp_message(self, sstag=None, dstag=None, tlvs=[]):
        """ Default CETP fields for signalling message """
        version                     = 2
        cetp_msg                 = {}
        cetp_msg['VER']          = version
        cetp_msg['SST']          = sstag
        cetp_msg['DST']          = dstag
        cetp_msg['TLV']          = tlvs
        return cetp_msg
    
    def get_cetp_packet(self, cetp_msg, pprint_msg=""):
        cetp_packet = json.dumps(cetp_msg)
        return cetp_packet

    def _get_unavailable_response(self, tlv):
        resp_tlv = copy.copy(tlv)
        resp_tlv['cmp'] = 'notAvailable'
        resp_tlv['ope'] = "info"
        return resp_tlv
        
    def _get_terminate_tlv(self, err_tlv=None):
        terminate_tlv = {}
        terminate_tlv['ope'], terminate_tlv['group'], terminate_tlv['code'], terminate_tlv['value'] = "info", "ces", "terminate", ""
        if err_tlv is not None:
            terminate_tlv['value'] = err_tlv
        return terminate_tlv

    def _create_offer_tlv(self, tlv):
        try:
            group, code = tlv['group'], tlv['code']
            if group in ["ces", "rloc", "payload"]:
                func = CETP.SEND_TLV_GROUP[group][code]
                tlv = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, \
                           cetp_security=self.cetp_security, policy = self.ces_policy, interfaces=self.interfaces, query=False)
            return tlv
        except Exception as ex:
            self._logger.error("Exception in _create_offer_tlv(): '{}'".format(ex))
            return None
                    
    def _create_offer_tlv2(self, group=None, code=None, value=None):
        try:
            tlv ={}
            tlv['ope'], tlv['group'], tlv['code'] = "info", group, code
            if value!=None:
                tlv["value"] = value
            else:
                tlv["value"] = ""
                
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

    def _get_tlv_value(self, tlv):
        return tlv["value"]

    def _get_ack_value(self, tlvs_list):
        ack_value = None
        for tlv in tlvs_list:
            if tlv["code"] == "ack":
                ack_value = self._get_tlv_value(tlv)
        return ack_value

    def _check_tlv(self, tlv, ope=None, cmp=None, group=None, code=None):
        """ Check whether an attribute with given value exists in a TLV"""
        try:
            if (ope != None) and (tlv["ope"] == ope):
                return True
            if 'cmp' in tlv:
                if (cmp != None) and (tlv["cmp"] == cmp):
                    return True
            if (group != None) and (tlv["group"] == group):
                return True
            if (code != None) and (tlv["code"] == code):
                return True
            return False
        except Exception as ex:
            self._logger.error("Exception in _check_tlv(): {}".format(ex))
            return False

    def _check_tlv2(self, tlv, group=[], code=[]):
        """ Check whether an attribute with given value exists in a TLV"""
        try:
            if (group != []) and (tlv["group"] in group):
                return True
            if (code != []) and (tlv["code"] in code):
                return True
            return False
        except Exception as ex:
            self._logger.error("Exception in _check_tlv2(): {}".format(ex))
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
            elif tlv["code"] == code:
                retlist.append(tlv)
        return retlist
        

    def generate_session_tags(self, dstag=0):
        """ Returns a session-tag of 4-byte length, if sstag is not part of an connecting or ongoing transaction """
        while True:
            sstag = random.randint(0, 2**32)
            if dstag ==0:
                # For oCES, it checks the connecting transactions
                if not self.cetpstate_mgr.has_initiated_transaction((sstag, 0)):
                    return sstag
            
            elif dstag:
                #self._logger.info("iCES is requesting source session tag")
                """ iCES checks if upon assigning 'sstag' the resulting (SST, DST) pair will lead to a unique transaction. """
                if not self.cetpstate_mgr.has_established_transaction((sstag, dstag)):                   # Checks connected transactions
                    return sstag


    def get_local_rloc(self, rrloc_tlv, policy):
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
            lrloc_tlv = self.get_local_rloc(rrloc_tlv, self.ces_policy)
            lrloc_tlvs += lrloc_tlv
                
        l_rlocs, r_rlocs = self._filter_rlocs_list(lrloc_tlvs, rrloc_tlvs)       # Matches & Verifies the payload in the TLVs, and Removes duplicate RLOCs (on sender and receiver side)
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
                #p["value"]
                retlist.append(p["code"])
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

        
        l_payloads = _build_list(sent_tlvlist)          #Build the payload list for comparison
        r_payloads = _build_list(recv_tlvlist)
        l_payloads = list(set(l_payloads))
        r_payloads = list(set(r_payloads))
        (l_payloads, l_payloads) = _filter(l_payloads, r_payloads)
        return (l_payloads, r_payloads)
    
    def add_negotiated_params(self, code, value):
        self.negotiated_params[code] = value
    
    def negotiated_parameters(self):
        #s = [self.l_cesid, self.r_cesid, self.ttl, self.evidence_format, self.remote_session_limit, self.lrloc, self.rrloc, self.lpayload, self.rpayload]
        print("New functions: ", self.negotiated_params)
        
        s = [self.l_cesid, self.r_cesid, self.ttl, self.remote_session_limit, self.lrloc, self.rrloc, self.lpayload, self.rpayload]
        return s
        
    def show(self, packet):
        s = ""
        for k, v in packet.items():
            if k != "TLV":
                s += str(k)+": "+ str(v) + "\n"
            else:
                s+=k+":\n"
                for tlv in v:
                    ope, group = CETP.PPRINT_OPE[tlv['ope']], CETP.PPRINT_GROUP[tlv['group']]
                    code = tlv["code"]
                    if code in CETP.PPRINT_CODE:
                        code = CETP.PPRINT_CODE[code]
                    
                    s += "\t ['ope':{}, 'group':{}, 'code':{}".format(ope, group, code)
                    
                    if 'cmp' in tlv:
                        s += ", 'cmp':{}".format(tlv['cmp'])
                    if 'value' in tlv:
                        s += ", 'value':{}".format(tlv['value'])                   
                    s += " ]\n"
        return s
        
    def show2(self, packet):
        #self._logger.info("CETP Packet")
        for k, v in packet.items():
            if k != "TLV":
                print(str(k)+": "+ str(v))
            else:
                print("TLV:")
                for tlv in v:
                    print("\t", tlv)
        print("\n")

    def pprint(self, packet, m=None):
        if m!=None:
            self._logger.info(m)
        s = self.show(packet)
        print(s, "\n")



class oC2CTransaction(C2CTransaction):
    """
    Negotiates outbound CES policies with the remote CES.
    Also contains methods to facilitate signalling in the post-c2c negotiation phase between CES nodes.
    """
    def __init__(self, loop, l_cesid="", r_cesid="", c_sstag=0, c_dstag=0, cetpstate_mgr=None, policy_client=None, policy_mgr=None, proto="tls", ces_params=None, \
                 cetp_security=None, transport=None, interfaces=None, c2c_layer=None, conn_table=None, direction="outbound", name="oC2CTransaction"):
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
        self.transport              = transport
        self.remote_addr            = transport.remotepeer
        self.cetp_security          = cetp_security
        self.c2c_layer              = c2c_layer
        self.interfaces             = interfaces
        self.conn_table             = conn_table
        self.rtt                    = 0
        self.packet_count           = 0
        self.missed_keepalives      = 0
        self.packet_b4_success      = 0
        self.last_seen              = time.time()
        self.last_packet_received   = None
        self.keepalive_handler      = None
        self.keepalive_scheduled    = False
        self.c2c_negotiation_status = False
        self.terminated             = False
        self.transport_health       = True                                  # Indicates if the CES-to-CES keepalive is responded in 'timeout' duration.
        self.keepalive_trigger_time = time.time()
        self._start_time            = time.time()
        self.name                   = name
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oC2CTransaction)
        self.cetp_negotiation_history  = []
        self.r_ces_requirements        = []                                 # To store list of remote CES requirements
        self.post_c2c_cbs              = {}
        self.unresponded_post_c2c_msg  = {}
        self.negotiated_params         = {} 

    def load_parameters(self):
        self.keepalive_cycle    = self.ces_params['keepalive_cycle']
        self.keepalive_timeout  = self.ces_params['keepalive_t0']
        self.completion_t0      = self.ces_params['incomplete_cetp_state_t0']
    
    def load_policies(self):
        """ Retrieves the policies stored in the Policy file"""
        self.oces_policy      = self.policy_mgr.get_ces_policy(proto=self.proto)
        self.oces_policy_tmp  = self.policy_mgr.get_policy_copy(self.oces_policy)
        self.ces_policy       = self.oces_policy

    def _initialize(self):
        """ Loads policies, generates session tags, and initiates event handlers """
        try:
            self.load_parameters()            
            self.load_policies()
            self.sstag = self.generate_session_tags()
            return True
        except Exception as ex:
            self._logger.error(" Exception '{}' in initializing CES-to-CES session towards: '{}'".format(ex, self.r_cesid))
            return False
        
    def _schedule_completion_check(self):
        self.unregister_handler = self._loop.call_later(self.completion_t0, self._unregister_cb)

    def _unregister_cb(self):
        """ Unregisters the incomplete transaction upon timeout """
        if not self.is_negotiated():
            self._logger.error("C2C negotiation towards '{}' did not complete in '{}' sec.".format(self.r_cesid, self.completion_t0))
            self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))
    
    def is_negotiated(self):
        return self.c2c_negotiation_status
        
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
                if ret_tlv!=None:
                    tlvs_to_send +=  ret_tlv
                
            # Required TLVs
            for rtlv in self.ces_policy.get_required():
                ret_tlv = self._create_request_tlv(rtlv)
                if ret_tlv!=None:
                    tlvs_to_send +=  ret_tlv
            
            # Signing the CETP header, if required by policy    - Depends on the type of transport layer.
            # self.attach_cetp_signature(tlv_to_send)
            cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
            self.pprint(cetp_message, m="Outbound packet")
            cetp_packet = self.get_cetp_packet(cetp_message)
            self.cetpstate_mgr.add_initiated_transaction((self.sstag,0), self)
            self._schedule_completion_check()                   # Callback to unregister the incomplete C2C transaction
            self.last_packet_sent = cetp_message
            self._start_time = time.time()
            return cetp_packet
        except Exception as ex:
            self._logger.error(" Exception '{}' in initiating CES-to-CES session towards: '{}'".format(ex, self.r_cesid))
            return None
            
    
    def set_terminated(self, terminated=True):
        self.terminated = terminated
        self.cetpstate_mgr.remove_established_transaction((self.sstag, self.dstag))

    def get_remote_cesid(self):
        return self.r_cesid
    
    def _pre_process(self, cetp_msg):
        """ Pre-processing check for the version field, session tags & format of TLVs in the inbound packet.
        AND, checks whether the inbound packet is a request message.
        """
        try:
            self.query_message = False
            self.packet        = cetp_msg
            self.received_tlvs, inbound_sstag, inbound_dstag = cetp_msg['TLV'], cetp_msg['SST'], cetp_msg['DST']
            self.sstag, self.dstag = inbound_dstag, inbound_sstag
            
            for received_tlv in self.received_tlvs:
                if self._check_tlv(received_tlv, ope="query"):
                    self.query_message = True
                    break
                
            return True
        except Exception as ex:
            self._logger.error(" Exception '{}' in pre-processing the CETP packet from '{}'".format(ex, self.r_cesid))
            return False
         

    def continue_c2c_negotiation(self, cetp_packet, transport):
        """ Continues CES policy negotiation towards remote CES """
        #try:
        #self._logger.info(" Continuing CES-to-CES session negotiation (SST={} -> DST={}) towards '{}'".format(self.sstag, 0, self.r_cesid))
        #self._logger.info(" Outbound policy: ", self.ces_policy)
        self.pprint(cetp_packet, m="Inbound Response packet")
        negotiation_status, error = None, False
        cetp_resp = ""
        
        self.packet_b4_success += 1
        if self.packet_b4_success > 10:
            self._logger.warning("C2C state is under scanning/flooding attack.")  # TBD: in CETPLayering - safety of session tag reserved by a 'CES-ID'
            #self.cetp_securtiy.report(r_cesid, behavior)                         # TBD: Reporting remote end to CETPSecurity module?
            transport.close()
        
        if not self._pre_process(cetp_packet):
            self._logger.error(" Failure to pre-process the CETP packet from '{}'.".format(self.r_cesid))
            return (negotiation_status, cetp_resp)                          

        
        self.transport = transport
        tlvs_to_send, error_tlvs = [], []
        self.rtt += 1

        if self.rtt>2:
            self._logger.error(" CES-to-CES negotiation exceeded {} RTTs".format(self.rtt))
            negotiation_status = False
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
                            self._logger.error("'{}.{}' TLV requested by remote CES is not available.".format(received_tlv['group'], received_tlv['code']))
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
                            if self._check_tlv2(received_tlv, group=["rloc", "payload"]) and (self._check_tlv(received_tlv, cmp="notAvailable")):           # Limiting type of failure that is acceptable from remote CES.
                                #self._logger.info(" A locally required TLV {}.{} is not available.".format(received_tlv['group'], received_tlv['code']))
                                error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                                self.oces_policy_tmp.del_required(received_tlv)
                            else:
                                self._logger.error("TLV {}.{} failed verification".format(received_tlv['group'], received_tlv['code']))
                                error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                                error = True
                                break

                else:
                    #self._logger.info("Unrequrested offer is received")
                    pass
        
        if error:
            self._logger.error(" CES-to-CES policy negotiation failed in {} RTT".format(self.rtt))
            self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))      # Since transaction didn't completed at oCES yet.
            self.unregister_handler.cancel()            
            negotiation_status = False
            if self.dstag==0:
                return (negotiation_status, "")                                   # Locally terminate connection, as iCES is stateless
            else:
                # Return terminate packet to remote end, as it has completed the transaction
                self._logger.info(" Responding remote CES with terminate-TLV")
                cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=error_tlvs)
                cetp_packet = self.get_cetp_packet(cetp_message)
                self.cetp_negotiation_history.append(cetp_message)
                self.pprint(cetp_message, m="Outbound CETP Error")
                return (negotiation_status, cetp_packet)

        else:
            if self._is_ready():
                if self._create_connection():
                    #self._logger.info(" '{}'\n C2C policy negotiation succeeded in {} RTT".format(30*'#', self.rtt))
                    self._set_established_cetp()
                    negotiation_status = True
                    return (negotiation_status, "")
                else:
                    self._logger.error(" Responding remote CES with the terminate-TLV")
                    tlvs_to_send = self._create_offer_tlv2(group="ces", code="terminate")
                    cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                    self.pprint(cetp_message, m="Outbound Msg")
                    cetp_packet = self.get_cetp_packet(cetp_message)
                    negotiation_status = False
                    return (negotiation_status, cetp_packet)
                
            else:
                if self.rtt<2:
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
                    cetp_packet = self.get_cetp_packet(cetp_message)
                    return (negotiation_status, cetp_packet)

                else:
                    self._logger.error(" Remote CES didn't meet the oCES policy requirements in {} RTT".format(self.rtt))
                    self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))        # Since transaction didn't completed yet.
                    self.unregister_handler.cancel()            
                    
                    if self.dstag!=0:
                        tlvs_to_send = self._create_offer_tlv2(group="ces", code="terminate")
                        cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                        self.pprint(cetp_message)
                        cetp_packet = self.get_cetp_packet(cetp_message)
                        negotiation_status = False
                        return (negotiation_status, cetp_packet)
                        
        #except Exception as msg:
        #    #self._logger.info(" Exception in resolving C2C transaction: {}".format(msg))
        # return                        # What value shall it return in this case?

    def _is_ready(self):
        return (len(self.oces_policy_tmp.required)==0) and self.dstag!=0

    def _create_connection(self):
        """ Extract the negotiated parameters to create a connection state """
        try:
            self.lrloc, self.rrloc          = self._get_dp_connection_rlocs()
            self.lpayload, self.rpayload    = self._get_dp_connection_payloads()
            #print("Negotiated params: {}".format(self.negotiated_parameters()))
            
            if len(self.lrloc)==0 or len(self.rrloc)==0 or len(self.lpayload)==0 or len(self.rpayload)==0:
                self._logger.error("C2C negotiation didn't provide info to create C2C-DP-Connection. ")
                return False
            
            self._logger.info("Negotiated params: {}".format(self.negotiated_parameters()))
            keytype = ConnectionTable.KEY_MAP_RCESID_C2C
            key = self.r_cesid
            if not self.conn_table.has(keytype, key):
                self.conn = ConnectionTable.C2CConnection(self.l_cesid, self.r_cesid, self.lrloc, self.rrloc, self.lpayload, self.rpayload)
                self.conn_table.add(self.conn)                
            
            return True
        except Exception as ex:
            self._logger.error("Exception in _create_connection(): '{}'".format(ex))
            return False

    def _set_established_cetp(self):
        """ State management of established C2C transaction, and triggering the negotiated functions """
        self.c2c_negotiation_status = True
        self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))
        self.cetpstate_mgr.add_established_transaction((self.sstag, self.dstag), self)
        self.unregister_handler.cancel()
        self.trigger_negotiated_functionality()
        
    def trigger_negotiated_functionality(self):
        """ Triggers the functionalities negotiated with remote CES upon completion of the C2C negotiation. """
        functionalities_code = ["keepalive"]

        if len(self.r_ces_requirements) !=0:                       # List of accepted queries of remote CES
            for f in functionalities_code:
                if self._is_requested_functionality(f):
                    
                    # Send keepalives, if the remote CES requested it (& if you negotiated).
                    if f == "keepalive":
                        self._logger.info(" Remote end requires keepalive")
                        self._loop.call_later(self.keepalive_cycle, self.initiate_keepalives)         # Callback for triggering keepalives
                        
        elif self.rtt==1:                                          # A negotiation may complete in 1-RTT, so CES must support the promised policy offers.
            for otlv in self.ces_policy.get_offer():
                if otlv["group"] == "ces" and otlv['code'] == "keepalive":
                    self._loop.call_later(self.keepalive_cycle, self.initiate_keepalives)

    def _is_requested_functionality(self, fun):
        for received_tlv in self.r_ces_requirements:
            if self._check_tlv(received_tlv, ope="query") and received_tlv['group']=='ces' and received_tlv['code']==fun and self.ces_policy.has_available(received_tlv):
                return True
        return False
    
    def is_transport_active(self):
        """ Indicates whether the transport link corresponding to this transaction is active. """
        return self.transport_health
    
    def update_last_seen(self):
        self.last_seen = time.time()

    def _assign_c2c_layer(self, c2c_layer):
        """ Assigned by CETP Manager """
        self.c2c_layer = c2c_layer

    def trigger_mandatory_functions(self):
        """ Not in use:     Function to trigger functionalities inherent/mandatory to a CETP version, e.g. keepalives """
        try:
            functionalities_code = ["keepalive"]
            for f in functionalities_code:

                # Send keepalives, if the remote CES requested it (& if you negotiated).
                if f == "keepalive":
                    self._logger.info(" Trigger keepalive functionality")
                    self._loop.call_later(self.keepalive_cycle, self.initiate_keepalives)         # Callback for triggering keepalives

        except Exception as ex:
            self._logger.error(" Exception in trigger negotiated functions {}".format(ex))
            return

    def initiate_keepalives(self):
        """ Schedules keepalive upon inactivity of time 'To' on a transport link """
        if not self.terminated:
            now = time.time()
            lapsed_time = now-self.last_seen
            
            if lapsed_time > self.keepalive_cycle:
                if not self.keepalive_scheduled:
                    self._loop.call_later(self.keepalive_cycle, self.initiate_keepalives)
                    self.send_keepalive()
                    self.keepalive_scheduled = True
            else:
                schedule_at = self.keepalive_cycle - lapsed_time
                self._loop.call_later(schedule_at, self.initiate_keepalives)

    def send_keepalive(self):
        """ Sends CES keepalive message on transport towards remote CES """
        if not self.terminated:
            #self._logger.info(" Sending CES keepalive towards '{}' (SST={}, DST={})".format(self.r_cesid, self.sstag, self.dstag))
            self.keepalive_trigger_time = time.time()
            self.keepalive_tracker = self._loop.call_later(self.keepalive_timeout, self.trace_keepalive_cb)      # Callback to check keepalive response.
            keepalive_tlv = self._create_request_tlv2(group="ces", code="keepalive")
            self.send_post_c2c(keepalive_tlv, timeout=self.keepalive_timeout-0.001)

    def trace_keepalive_cb(self):
        """ Evaluates whether remote CES is: active; or dead """
        self.missed_keepalives += 1
        #self.c2c_layer.report_rtt(self.transport, rtt=2**32)
        if self.transport_health == True:                                                               # Reporting the change in transport status to C2C layer.
            self.transport_health = False
            self.c2c_layer.report_transport_health(self.transport, healthy=self.transport_health)

        if self.missed_keepalives <3:
            self.keepalive_handler  = self._loop.call_later(3.0, self.initiate_keepalives)               # Sending next keepalive-request
        else:
            self._logger.warning(" Remote CES has not answered any keepalive within 'To'.")
            self.set_terminated()
            #self.send_cetp_terminate()        # No need to send cetp_terminate on an un-responsive transport.
            self.terminate_transport()

        
    def keepalive_success_cb(self):
        """ Method executed on reception of keepalive response """
        self.keepalive_tracker.cancel()
        self.keepalive_scheduled = False
        now = time.time()
        rtt = now - self.keepalive_trigger_time
        #self.c2c_layer.report_rtt(self.transport, rtt=rtt)                                            # Report RTT
        
        if self.transport_health == False:
            self.transport_health = True
            self.missed_keepalives = 0
            self.c2c_layer.report_transport_health(self.transport, healthy=self.transport_health)      # Reporting the change in transport status to C2C layer.


    def feedback_report(self):
        # Function for reporting feedback to remote CES.
        pass
    
    def get_cetp_terminate_msg(self, error_tlv=None):
        terminate_tlv = self._create_offer_tlv2(group="ces", code="terminate", value=error_tlv)
        if terminate_tlv!=None:
            cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=terminate_tlv)
            cetp_packet = self.get_cetp_packet(cetp_message)
            return cetp_packet
    
    def send_cetp_terminate(self, error_tlv=None):
        """ Sends a terminate TLV towards remote CES """
        cetp_packet = self.get_cetp_terminate_msg(error_tlv)
        self.send_cetp(cetp_packet)

    def terminate_transport(self):
        """ Closes the connected transport """
        self.transport.close()
    
    def report_misbehavior_evidence(self, h_sstag, h_dstag, r_hostid, misbehavior_evidence):
        """ Reports misbehavior evidence observed in (h_sstag, h_dstag) to the remote CES """
        #self._logger.info(" Sending misbehavior evidence towards remote CES '{}' )".format(self.r_cesid, r_hostid))
        evidence = {"h2h_session":(h_sstag, h_dstag), "misbehavior":misbehavior_evidence}             # misbehavior_evidence="FSecure-MalwarePayload"
        evidence_value = json.dumps(evidence)
        evidence_tlv = self._create_request_tlv2(group="ces", code="evidence", value=evidence_value)
        tlvs_to_send = evidence_tlv
        self.send_post_c2c(tlvs_to_send)
        
    def block_remote_host(self, r_hostid):
        #self._logger.info(" Blocking a remote host '{}' at remote CES '{}'.".format(r_hostid, self.r_cesid))
        blocking_msg = {"remote_host": r_hostid}             # misbehavior_evidence="FSecure-MalwarePayload"
        blocking_payload = json.dumps(blocking_msg)
        host_filter_tlv = self._create_request_tlv2(group="ces", code="host_filtering", value=blocking_payload)
        tlvs_to_send = host_filter_tlv
        self.send_post_c2c(tlvs_to_send)        
        
    def drop_connection_to_local_domain(self, l_domain):
        #self._logger.info(" Preventing remote CES '{}' from forwarind traffic to '{}'.".format(self.r_cesid, l_domain))
        blocking_msg = {"local_domain": l_domain}             # misbehavior_evidence="FSecure-MalwarePayload"
        blocking_payload = json.dumps(blocking_msg)
        host_filter_tlv = self._create_request_tlv2(group="ces", code="host_filtering", value=blocking_payload)
        tlvs_to_send = host_filter_tlv
        self.send_post_c2c(tlvs_to_send)        
        
    def get_ack_request(self):
        tlv = self._create_request_tlv2(group="ces", code="ack")
        return tlv
    
    def send_cetp(self, cetp_packet):
        self.transport.send_cetp(cetp_packet)
    
    def send_post_c2c_msg(self, tlvs_to_send):
        """ Method to send TLVs that do not need any acknowledgement """
        cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
        cetp_packet = self.get_cetp_packet(cetp_message)
        self.send_cetp(cetp_packet)
    
    def send_post_c2c(self, tlvs_to_send, timeout=10):
        """ Sends request TLVs towards remote CES, after appending ack-tlv.        And schedules a callback to check the acknowledgement message.
            On an established C2C transaction, A CES node could send requests triggered by local Events, Thresholds, Handlers, Security modules, or Admin commands etc.
             # Example of requests/events: 1) terminate host session (for non-compliance); 2) keepalives; 3) new SSL key_negotiation; 4) new session_limit; 5) misbehavior evidences; 6) block_host; 7) ratelimiting the sender, destination. """
        try:
            ack_value = None
            ack_tlv = self.get_ack_request()
            tlvs_to_send += ack_tlv
            ack_value = self._get_ack_value(ack_tlv)           # Assure that no two messages pending acknowledgement have the same ack-id value
            
            if ack_value!=None:
                cb = self._loop.call_later(timeout, self.unresponsive_ack_cb, ack_value, tlvs_to_send)
                self.post_c2c_cbs[ack_value]=(cb, tlvs_to_send)
                
                cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                cetp_packet = self.get_cetp_packet(cetp_message)
                self.send_cetp(cetp_packet)
            
        except Exception as ex:
            self._logger.error("Exception '{}' in sending post_c2c message to '{}'. (sst={}, dst={})".format(ex, self.r_cesid, self.sstag, self.dstag))
            return

    
    def unresponsive_ack_cb(self, ack_value, sent_tlvs):
        self._logger.error(" CES-ID '{}' didn't respond to post-c2c-negotiation query (sst={}, dst={})".format(self.r_cesid, self.sstag, self.dstag))
        self.unresponded_post_c2c_msg[ack_value] = sent_tlvs
        del self.post_c2c_cbs[ack_value]
        
    def _pre_process_established_c2c(self, cetp_msg):
        """ Pre-processing check for the version field, session tags & format of TLVs in the inbound packet. """
        try:
            self.packet        = cetp_msg
            self.recvd_tlvs    = cetp_msg['TLV']
            return True
        except Exception as ex:
            self._logger.error(" Exception in processing CETP packet on established transaction. '{}'".format(ex))
            return False
    
    def _has_requested(self, tlvlist, code):
        for tlv in tlvlist:
            if tlv["code"]== code:
                return True
        return False
    
    def post_c2c_negotiation(self, packet, transport):
        """ 
        Processes a CETP packet received on an established CES-to-CES session.
        A message shall be entirely a Response or Request message, identified by the presence or absence of 'info.ces.ack' tlv. Only exception being 'info.terminate'

        A CES node can either receive requests from remote CES, OR responses for the requests sent earlier to remote CES.
            Upon requests,  CES must respond to the ACK TLV in CETP message, but might not or might respond to individual query-TLVs (with Acceptable/Non-acceptable values).
            Upon responses, CES node only processes the message if value of ACK-TLV in message corresponds to a sent value.
        """
        
        #time.sleep(20)
        #self._logger.info(" Post-C2C negotiation packet from '{}' (SST={}, DST={})".format(self.r_cesid, self.sstag, self.dstag))
        self.pprint(packet, m="Inbound packet")
        
        if not self._pre_process_established_c2c(packet):
            return
        
        tlvs_to_send, received_tlvs = [], []
        status, error = False, False
        
        
        #Checks whether 'info.ces.ack' tlv is present (i.e. a Response message), then the message is evaluated against the sent requests.
        
        info_ack_tlv = self._get_from_tlvlist(self.recvd_tlvs, "ces", code="ack", ope="info")
        #print("info_ack_tlv: ", info_ack_tlv)
        if len(info_ack_tlv)!=0:
            ack_id = self._get_ack_value(info_ack_tlv)
            if ack_id not in self.post_c2c_cbs:
                self._logger.warning("Unrequested packet from CES '{}' is received. (sst={}, dst={})".format(self.r_cesid, self.sstag, self.dstag))
                return
            else:
                self._logger.debug(" Processing the response for the sent requests.")
                (cb, sent_tlvs) = self.post_c2c_cbs[ack_id]
                del self.post_c2c_cbs[ack_id]
                cb.cancel()

                for received_tlv in self.recvd_tlvs:
                    # Process the responses received for requested TLVs only
                    if self._has_requested(sent_tlvs, received_tlv["code"]) and self._check_tlv(received_tlv, ope="info") and self._check_tlv(received_tlv, group="ces"):
                        
                        if self._check_tlv(received_tlv, code="ack"):
                            continue                                            # Already validated
                        
                        elif self._check_tlv(received_tlv, code="keepalive"):
                            self.keepalive_success_cb()
                            
                        elif self._check_tlv(received_tlv, code="evidence"):
                            self._logger.info("Evidence ACKed".format(received_tlv["value"]))
                            
                        elif self._check_tlv(received_tlv, code="host_filtering"):
                            self._logger.info(" Host filtering is acked")
                            
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

                    
        
        # This is not a response message - Process the TLVs (all requested and selected offers) contained in the message.
        for received_tlv in self.recvd_tlvs:
            # Processing the inbound 'terminate' TLV
            if self._check_tlv(received_tlv, ope="info") and self._check_tlv(received_tlv, group="ces"):
                
                if self._check_tlv(received_tlv, code="terminate"):
                    #self._logger.info(" Terminate received with value: {}".format(received_tlv['value']) )
                    # Check value field in CETPOperations, to determine more possible terminate options.
                    self.set_terminated()
                    transport.close()
                    
            # Processing the inbound request TLVs
            elif self._check_tlv(received_tlv, ope="query") and self._check_tlv(received_tlv, group="ces"):
                supported_req = False
                
                # Check whether the remote CES is sending request for a supported/available policy element.
                if self.ces_policy.has_available(received_tlv) or received_tlv["code"] in ["evidence", "keepalive", "host_filtering", "ack"]:       #provide them as list
                    supported_req = True

                    if received_tlv["code"] in ["evidence", "host_filtering"]:
                        self._logger.warning(" '{}.{}' TLV request is received from remote CES '{}'".format(received_tlv["code"], received_tlv["code"], self.r_cesid))                    
                    elif received_tlv["code"]=="keepalive":
                        self._logger.info(" Keepalive request received from remote CES")
                        #self.c2c_layer.report_rtt(self.transport, last_seen=self.last_seen)
                        self.c2c_layer.report_transport_health(self.transport)
                        self.health_report   = True
                    
                    elif received_tlv["code"]=="ack":
                        ret_tlv = self._create_response_tlv(received_tlv, post_c2c=True)
                        tlvs_to_send += ret_tlv
                        continue
                    
                if supported_req:
                    ret_tlv = self._create_response_tlv(received_tlv)
                    if ret_tlv !=None:
                        tlvs_to_send += ret_tlv
                    else:
                        self._logger.warning(" Error responding to '{}.{}' TLV request in post-c2c negotiation (SST={}, DST={})".format(received_tlv['group'], received_tlv['code'], self.sstag, self.dstag))
                        ret_tlv = self._get_unavailable_response(received_tlv)
                        tlvs_to_send += ret_tlv
                
                elif received_tlv["code"]=="comment":
                    # General commentary from remote CES (or its admin), displayed to NW admin... Allowing cooperation enhancement at human level. Good idea?
                    self._logger.info("General comment: {}".format(received_tlv['value']))          # Should be stored in CETPSecurity module?
                    pass
                
                else:
                    self._logger.warning(" Unsupported TLV '{}.{}' request is received in post-c2c negotiation".format(received_tlv['group'], received_tlv['code'], self.sstag, self.dstag))
                    # Some action or reporting mechanism needed to report this?
                    ret_tlv = self._get_unavailable_response(received_tlv)
                    tlvs_to_send += ret_tlv

        
        if len(tlvs_to_send)!=0:
            cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
            cetp_packet = self.get_cetp_packet(cetp_message)
            #self.pprint(cetp_message)
            self.last_seen = time.time()
            transport.send_cetp(cetp_packet)

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
                 cetp_security=None, interfaces=None, conn_table=None, proto="tcp", transport=None, name="iC2CTransaction"):
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
        self.transport                  = transport
        self.cetp_security              = cetp_security
        self.interfaces                 = interfaces
        self.name                       = name
        self.conn_table                 = conn_table
        self.transport_health           = True
        self.c2c_negotiation_status     = False
        self.r_ces_requirements         = []
        self.last_seen                  = time.time()
        self.keepalive_trigger_time     = time.time()
        self.keepalive_timeout          = ces_params['keepalive_t0']
        self._logger                    = logging.getLogger(name)
        self.negotiated_params          = {} 
        self._logger.setLevel(LOGLEVEL_iC2CTransaction)        
        
    def load_policies(self):
        """ Retrieves the policies stored in the policy file"""
        self.ices_policy, self.ices_policy_tmp  = None, None
        self.ices_policy        = self.policy_mgr.get_ces_policy(proto=self.proto)
        self.ices_policy_tmp    = self.policy_mgr.get_policy_copy(self.ices_policy)
        self.ces_policy         = self.ices_policy

    def _pre_process(self, cetp_packet):
        """ Pre-process the inbound packet for the minimum necessary details, AND loads the CES-to-CES policies. """
        try:
            self.load_policies()
            
            self.packet            = cetp_packet
            self.received_tlvs     = cetp_packet['TLV']
            ver, inbound_sstag, inbound_dstag = cetp_packet['VER'], cetp_packet['SST'], cetp_packet['DST']
            self.sstag, self.dstag = inbound_dstag, inbound_sstag
            supported_ver          = self.ces_params["CETPVersion"]
            
            if ver!=supported_ver:
                self._logger.error(" CETP Version is not supported.")
                return False

            for received_tlv in self.received_tlvs:
                if self._check_tlv(received_tlv, ope="info"):
                    if self._check_tlv(received_tlv, group="ces") and self._check_tlv(received_tlv, code="cesid"):
                        self.r_cesid = received_tlv['value']
                        break

            if len(self.r_cesid)==0 or len(self.r_cesid)>256:
                self._logger.error(" Invalid CES-ID")
                return False
            
            return True
        except Exception as ex:
            self._logger.error(" Exception in pre-processing the CETP packet: '{}'".format(ex))
            return False
    
    def process_c2c_transaction(self, cetp_packet):
        """ Processes the inbound CETP-packet for negotiating the CES-to-CES (CETP) policies """
        #self._logger.info("{}".format(42*'*') )
        self.pprint(cetp_packet, m="Inbound packet")
        negotiation_status  = None
        cetp_response       = ""
        #time.sleep(3)
        
        if not self._pre_process(cetp_packet):
            self._logger.error("Inbound packet failed pre-processing()")
            negotiation_status = False
            return (negotiation_status, cetp_response)
        
        #self._logger.info("{}\n {}".format(42*'*', self.ices_policy))
        src_addr = self.remote_addr[0]
        tlvs_to_send, error_tlvs = [], []
        error = False

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
                            if self._check_tlv2(received_tlv, group=["rloc", "payload"]) and (self._check_tlv(received_tlv, cmp="notAvailable")):
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
            cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=error_tlvs)
            cetp_packet  = self.get_cetp_packet(cetp_message)
            self.pprint(cetp_message, m="Sent Response")
            negotiation_status = False
            return (negotiation_status, cetp_packet)
            # Shall the return value include error code to reveal the reason of C2C negotiation failure? 
        else:
            # Checks if all the local CES requirements are met
            if self._is_ready():
                # Create CETP connection
                if self._create_connection():
                    self.sstag = self.generate_session_tags(self.dstag)
                    #self._logger.info("{}".format(30*'*') )
                    #self._logger.info("C2C-policy negotiation succeeded -> Created stateful transaction (SST={}, DST={})".format(self.sstag, self.dstag))
                    stateful_transansaction = self._export_to_stateful()            #Export to stateful transaction for CETP messages in post-c2c negotiation
                    negotiation_status = True
                    cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                    cetp_packet = self.get_cetp_packet(cetp_message)
                    self.pprint(cetp_message, m="Sent Response")
                    stateful_transansaction.last_packet_sent = cetp_message
                    stateful_transansaction.last_packet_received = self.packet
                    return (negotiation_status, cetp_packet)
                else:
                    if len(error_tlvs) == 0:
                        error_tlvs = [self._get_terminate_tlv()]
                        
                    cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=error_tlvs)
                    cetp_packet = self.get_cetp_packet(cetp_message)
                    self.pprint(cetp_message, m="Sent Response")
                    negotiation_status = False
                    return (negotiation_status, cetp_packet)
                    
            else:
                #self._logger.info(" Inbound packet didn't meet all the policy requirements.")
                #Generate the Full Query message
                tlvs_to_send = []
                for rtlv in self.ices_policy.get_required():            
                    ret_tlv = self._create_request_tlv(rtlv)
                    if ret_tlv!=None:
                        tlvs_to_send +=ret_tlv
                
                negotiation_status = None
                cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                cetp_packet = self.get_cetp_packet(cetp_message)
                self.pprint(cetp_message, m="Sent Response")
                return (negotiation_status, cetp_packet)

    
    def _is_ready(self):
        """ Returns True, if all the local CES requirements are met by the inbound packet """
        return len(self.ices_policy_tmp.required)==0
    
    def _create_connection(self):
        try:
            self.lrloc, self.rrloc          = self._get_dp_connection_rlocs()
            self.lpayload, self.rpayload    = self._get_dp_connection_payloads()
            #print("Negotiated params: {}".format(self.negotiated_parameters()))
            
            if len(self.lrloc)==0 or len(self.rrloc)==0 or len(self.lpayload)==0 or len(self.rpayload)==0:
                self._logger.error("C2C negotiation didn't provide info to create a C2C-DP-Connection.")
                return False
            
            self._logger.info(" Negotiated params: {}".format(self.negotiated_parameters()))            
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
                                          cetpstate_mgr=self.cetpstate_mgr, ces_params=self.ces_params, proto=self.proto, transport=self.transport, direction="inbound", \
                                          cetp_security=self.cetp_security, conn_table=self.conn_table)
        
        new_transaction.ces_policy              = self.ces_policy
        new_transaction.c2c_negotiation_status  = True
        new_transaction.r_ces_requirements      = self.r_ces_requirements
        new_transaction.load_parameters()
        new_transaction.negotiated_params       = self.negotiated_params
        self.cetpstate_mgr.add_established_transaction((self.sstag, self.dstag), new_transaction)
        new_transaction.trigger_negotiated_functionality()
        return new_transaction
