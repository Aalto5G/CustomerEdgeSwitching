#!/usr/bin/python3.5

import asyncio
import logging
import sys
import random
import time
import traceback
import json
import dns

import cetpManager
import CETPH2H
import CETPC2C
import CETP
import copy
import CETPSecurity
import host
import connection
import customdns
import helpers_n_wrappers

from customdns import dnsutils
from helpers_n_wrappers import utils3
from helpers_n_wrappers import network_helper3
from helpers_n_wrappers import container3

LOGLEVEL_H2HTransaction         = logging.INFO
LOGLEVEL_H2HTransactionOutbound = logging.INFO
LOGLEVEL_H2HTransactionInbound  = logging.INFO
LOGLEVEL_H2HTransactionLocal    = logging.INFO

# Global Variables
KEY_INITIATED_TAGS        = 0
KEY_ESTABLISHED_TAGS      = 1
KEY_HOST_IDS              = 2
KEY_RCESID                = 3
KEY_CES_IDS               = 4
    
NEGOTIATION_RTT_THRESHOLD       = 2


class CETPTransaction(container3.ContainerNode):

    def __init__(self, name="CETPTransaction"):
        self._name      = name
        self._logger    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransaction)

    def _get_unavailable_response(self, tlv):
        resp_tlv = copy.copy(tlv)
        resp_tlv['cmp'] = 'notAvailable'
        resp_tlv['ope'] = "info"
        return resp_tlv
    
    def get_cetp_message(self, sstag=None, dstag=None, tlvs=[]):
        """ Default CETP fields for signalling message """
        cetp_header         = {}
        cetp_header['VER']  = self.ces_params["CETPVersion"]
        cetp_header['SST']  = sstag
        cetp_header['DST']  = dstag
        cetp_header['TLV']  = tlvs
        return cetp_header

    def _create_basic_tlv(self, ope=None, cmp=None, group=None, code=None, value=None):
        try:
            basic_tlv = {}
            if ope is not None:     basic_tlv["ope"]    = ope
            if cmp is not None:     basic_tlv["cmp"]    = cmp
            if group is not None:   basic_tlv["group"]  = group
            if code is not None:    basic_tlv["code"]   = code
            if value is not None:   basic_tlv["value"]  = value
            
            return basic_tlv
        
        except Exception as ex:
            self._logger.error("Exception in _create_basic_tlv(): '{}'".format(ex))
            return None
    
    def get_packet_details(self, cetp_msg):
        """ Sets basic details of an inbound CETP message """
        inbound_sstag           = cetp_msg['SST']
        inbound_dstag           = cetp_msg['DST']
        self.sstag, self.dstag  = inbound_dstag, inbound_sstag                                       # Sender's SST is DST for CES
        self.packet             = cetp_msg
        self.received_tlvs      = cetp_msg['TLV']

    def _get_terminate_tlv(self, err_tlv=None):
        terminate_tlv = {}
        terminate_tlv['ope'], terminate_tlv['group'], terminate_tlv['code'], terminate_tlv['value'] = "info", "control", "terminate", ""
        if err_tlv is not None:
            terminate_tlv['value'] = err_tlv
        return terminate_tlv

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
        except Exception as ex:
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
            sstag = random.randint(1, 2**32)
            if dstag == 0:
                # For oCES, it checks the connecting transactions
                if not self.cetpstate_table.has( (KEY_INITIATED_TAGS, sstag, 0)):
                    return sstag
            
            elif dstag:
                #self._logger.debug("iCES is requesting source session tag")
                """ iCES checks if upon assigning 'sstag' the resulting (SST, DST) pair will lead to a unique transaction. """
                if not self.cetpstate_table.has( (KEY_ESTABLISHED_TAGS, sstag, dstag)):                   # Checks connected transactions
                    return sstag

    def _check_sessionTags_uniqueness(self, sstag=0, dstag=0):
        """ Checks whether (SST, DST) pair will be locally unique, if the H2H negotiation succeeds    - Since DST is assigned by remote CES. """
        if dstg !=0 and self.cetpstate_table.has((KEY_ESTABLISHED_TAGS, sstag, dstag)):
            self._logger.error(" Failure: Resulting ({},{}) pair will not be locally unique in CES".format(sstag, dstag))
            return False
        return True
        
    def get_policy_copy(self, policy):
        """ Creates a copy of PolicyCETP object """
        try:
            return copy.deepcopy(policy)
        except Exception as ex:
            return None
                
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
        s = ""
        for k, v in packet.items():
            if k != "TLV":
                s += str(k)+": "+ str(v)+ "\n"
            else:
                s += k+":\n"
                for tlv in v:
                    s += "\t"+ str(tlv)+"\n"
                s += "\n"

    def pprint(self, packet, m=None):
        if m!=None:
            self._logger.info("\n"+m)
        s = self.show(packet)
        print(s, "\n")   

    def add_negotiated_param(self, k, v):
        self.negotiated_params[k]=v



class H2HTransaction(CETPTransaction):

    def _create_offer_tlv(self, tlv):
        try:
            group, code = tlv['group'], tlv['code']
            if group in ["id", "control"]:
                func = CETP.SEND_TLV_GROUP[group][code]
                tlv = func(tlv=tlv, code=code, cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, transaction=self, h2h_session=True, interfaces=self.interfaces, query=False)
            return tlv
        
        except Exception as ex:
            self._logger.error("Exception '{}' in _create_offer_tlv() for tlv : '{}'".format(ex, tlv))
            return None

    def _create_request_tlv(self, tlv):
        try:
            group, code = tlv['group'], tlv['code']
            #print(self.policy)
            if group in ["id", "control"]:
                func = CETP.SEND_TLV_GROUP[group][code]
                tlv  = func(tlv=tlv, code=code, cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, transaction=self, h2h_session=True, interfaces=self.interfaces, query=True)
                return tlv

        except Exception as ex:
            self._logger.error("Exception '{}' in  _create_request_tlv() for tlv : '{}'".format(ex, tlv))
            return None

    def _create_response_tlv(self, tlv):
        try:
            group, code = tlv['group'], tlv['code']
            if group in ["id", "control"]:
                func = CETP.RESPONSE_TLV_GROUP[group][code]
                tlv  = func(tlv=tlv, code=code, l_cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, transaction=self, h2h_session=True,interfaces=self.interfaces)
            return tlv

        except Exception as ex:
            self._logger.error("Exception '{}' in  _create_response_tlv() for tlv : '{}'".format(ex, tlv))
            return None

    def _verify_tlv(self, tlv, policy=None):
        try:
            group, code = tlv['group'], tlv['code']
            if group in ["id", "control"]:
                func   = CETP.VERIFY_TLV_GROUP[group][code]
                if policy!=None:
                    result = func(tlv=tlv, code=code, l_cesid=self.l_cesid, r_cesid=self.r_cesid, policy=policy, transaction=self, h2h_session=True, interfaces=self.interfaces)
                else:
                    result = func(tlv=tlv, code=code, l_cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, transaction=self, h2h_session=True, interfaces=self.interfaces)
                return result
        
        except Exception as ex:
            self._logger.error("Exception '{}' in _verify_tlv() for tlv : '{}'".format(ex, tlv))
            return False


    def has_domain(self, fqdn):
        """ Checks if an FQDN is hosted by this CES node. """
        key = (host.KEY_HOST_SERVICE, fqdn)
        res = self.host_table.has(key)
        return res
    
    def _record_negotiated_params(self):
        self.add_negotiated_param("lfqdn", self.lfqdn)
        self.add_negotiated_param("rfqdn", self.rfqdn)
        self.add_negotiated_param("lid", self.lid)
        self.add_negotiated_param("rid", self.rid)
        self.add_negotiated_param("lip", self.lip)
        self.add_negotiated_param("lpip", self.lpip)
        self.add_negotiated_param("sst", self.sstag)
        self.add_negotiated_param("dst", self.dstag)

    def is_ipv4(self, ip4_addr):
        return network_helper3.is_ipv4(ip4_addr)
    
    def is_ipv6(self, ip6_addr):
        return network_helper3.is_ipv6(ip6_addr)

    def _has_available_proxypool(self, fqdn):
        """ Returns False, if the proxy address pool of the host is depleted """
        try:
            key      = (host.KEY_HOST_SERVICE, fqdn)
            host_obj = self.host_table.get(key)
            host_id  = host_obj.fqdn
            key      = "proxypool"
            
            if self.pool_table.has(key):
                self.ap = self.pool_table.get(key)
                return self.ap.has_available(host_id)
            
        except Exception as ex:
            self._logger.error("Exception '{}' in _allocate_proxy_address".format(ex))
            return False
        
    def _allocate_proxy_address(self, fqdn):
        """Allocates a proxy IP address to represent remote host in local CES."""
        try:
            key      = (host.KEY_HOST_SERVICE, fqdn)
            host_obj = self.host_table.get(key)
            host_id  = host_obj.fqdn
            key      = "proxypool"
            
            if self.pool_table.has(key):
                self.ap = self.pool_table.get(key)
                pip     = self.ap.allocate(host_id)
                return pip
            
        except Exception as ex:
            self._logger.error("Exception '{}' in _allocate_proxy_address".format(ex))
            return
        


class H2HTransactionOutbound(H2HTransaction):
    def __init__(self, loop=None, sstag=0, dstag=0, cb=None, host_ip="", src_id="", dst_id="", l_cesid="", r_cesid="", policy_mgr= None, host_table=None, cetp_security=None, \
                 cetpstate_table=None, cetp_h2h=None, ces_params=None, interfaces=None, conn_table=None, pool_table=None, network = None, \
                 direction="outbound", name="H2HTransactionOutbound", rtt_time=[], negotiated_params={}):
        self.sstag, self.dstag  = sstag, dstag
        self.cb                 = cb
        self.host_ip            = host_ip                   # IP of the sender host
        self.src_id             = src_id                    # FQDN
        self.dst_id             = dst_id
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.policy_mgr         = policy_mgr
        self.cetpstate_table    = cetpstate_table
        self._loop              = loop
        self.cetp_h2h           = cetp_h2h
        self.ces_params         = ces_params
        self.direction          = direction
        self.host_table         = host_table
        self.pool_table         = pool_table
        self.interfaces         = interfaces
        self.conn_table         = conn_table
        self.cetp_security      = cetp_security
        self.network            = network
        self.negotiated_params  = negotiated_params
        self.rtt                = 0
        self.terminated         = False
        self._name              = name
        self._logger            = logging.getLogger(name)
        self.start_time         = time.time()
        self._logger.setLevel(LOGLEVEL_H2HTransactionOutbound)
        self.h2h_negotiation_status = False
        self.cetp_negotiation_history   = []
        self.test_results           = rtt_time
        self.cb_list            = [cb]

    def load_parameters(self):
        self.completion_t0      = self.ces_params['incomplete_cetp_state_t0']

    @asyncio.coroutine
    def load_policies(self, host_id=None):
        """ Returns the host-policy from the local policy file on success, or None on failure """
        yield from asyncio.sleep(0.000)
        self.opolicy     = self.policy_mgr.get_host_policy(self.direction, host_id = host_id)
        self.opolicy_tmp = self.get_policy_copy(self.opolicy)
        self.policy      = self.opolicy
        return self.policy

    @asyncio.coroutine
    def load_policies2(self, host_id=""):
        """ Downloads the host policy from Policy Management System """
        timeout     = 2
        direction   = "EGRESS"
        url         = "http://100.64.254.24/API/host_cetp_user?"
        params      = {'lfqdn': host_id, 'direction': direction}
        response    = yield from self.policy_mgr.get(url, params=params, timeout=timeout)
        
        if response is not None:
            host_policy      = json.loads(response)
            self.opolicy     = PolicyManager.PolicyCETP(host_policy)
            self.opolicy_tmp = self.get_policy_copy(self.opolicy)
            self.policy      = self.opolicy
            return self.policy


    def has_ongoing_h2h_negotiation(self, src_id, dst_id):
        key = (KEY_HOST_IDS, src_id, dst_id)
        if self.cetpstate_table.has(key):
            h2h_state = self.cetpstate_table.get(key)
            h2h_state.add_cb(self.cb)
            return True

    @asyncio.coroutine
    def _initialize(self):
        """ Loads policies, generates session tags, and initiates event handlers """
        try:
            if self.has_ongoing_h2h_negotiation(self.src_id, self.dst_id):
                return False
            
            self.load_parameters()
            self.sstag = self.generate_session_tags()
            self.cetpstate_table.add(self)
            
            if not self.is_local_host_allowed(self.src_id):
                self._logger.error(" Connection from sender '{}' is not allowed to '{}' behind CES '{}'".format(self.src_id, self.dst_id, self.r_cesid))
                return False
            
            if not self.is_remote_destination_allowed(self.dst_id):
                self._logger.error(" Connection to destination '{}' is not allowed.".format(self.dst_id))
                return False
            
            if not self._has_available_proxypool(self.src_id):
                self._logger.error(" Proxypool of the sender '{}' is depleted.".format(self.src_id))
                return False
            
            host_policy = yield from self.load_policies(host_id = self.src_id)
            
            if host_policy is None:
                self._logger.error("Failure to load policies for host-ID '{}'".format(self.src_id))
                return False
            
            return True
        
        except Exception as ex:
            self._logger.error(" Exception '{}' in initiating the H2H session: ".format(ex))
            return False
    
    def _schedule_completion_check(self):
        # Handler to unregister the incomplete CETP-C2C transaction
        self.unregister_handler = self._loop.call_later(self.completion_t0, self._unregister_cb)
        
    def _unregister_cb(self):
        """ Unregisters the incomplete negotiation upon timeout """
        if not self.is_negotiated():
            self._logger.error(" Incomplete H2H-state towards '{}' expired".format(self.dst_id))
            self._unregister_h2h()
    
    def _unregister_h2h(self):
        self.terminate()
        if not self.is_negotiated():
            #self.cetp_h2h.update_H2H_transaction_count(initiated=False)
            self._execute_dns_callback()
    
    def is_negotiated(self):
        return self.h2h_negotiation_status

    def set_negotiated(self, status=True):
        self.h2h_negotiation_status = status
        
    def add_cb(self, cb):
        self.cb_list.append(cb)
    
    @asyncio.coroutine
    def start_cetp_processing(self):
        """ Returns CETP message containing Policy Offers & Request towards remote-host """
        try:
            initialized = yield from self._initialize()
            
            if not initialized:
                self._logger.error(" Failure in initiating the Host-to-Host session.")
                return None
            
            #self._logger.debug(" Starting H2H session towards '{}' (SST= {} -> DST={})".format(self.dst_id, self.sstag, self.dstag))
            self._logger.info("outbound policy: \n {} {} {}".format(15*'-', self.opolicy, 15*'-'))
            tlvs_to_send = []
            tlvs_to_send.append(self.append_dstep_info())
     
            # Check if sender supports the same id_type as of the destination-id, otherwise maybe not even initiate a transaction? or initiate with a default ID-type?
            # And regardless of id_type being used, FQDN of host shall be made part of the messages exchanged?
            
            # Offered TLVs
            for otlv in self.opolicy.get_offer():
                ret_tlv = self._create_offer_tlv(otlv)
                tlvs_to_send += ret_tlv
                
            # Required TLVs
            for rtlv in self.opolicy.get_required():
                ret_tlv = self._create_request_tlv(rtlv)
                tlvs_to_send += ret_tlv
            
            cetp_msg = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
            self.pprint(cetp_msg, m="Outbound H2H CETP")
            self.last_packet_sent = cetp_msg
            self.cetp_negotiation_history.append(cetp_msg)
            #self.cetp_h2h.update_H2H_transaction_count()
            self._schedule_completion_check()
            return cetp_msg
        
        except:
            utils3.trace()
            self._unregister_h2h()
            return None
    
    def append_dstep_info(self):
        dstep_tlv = {}
        dstep_tlv["ope"], dstep_tlv["group"], dstep_tlv["code"], dstep_tlv["value"] = "info", "control", "dstep", self.dst_id 
        return dstep_tlv
    
    def set_terminated(self):
        if not self.terminated:
            self.terminated = True
            self._unregister_h2h()
        
            if self.is_negotiated():
                self.conn_table.remove(self.conn)
            
            if hasattr(self, 'unregister_handler'):
                self.unregister_handler.cancel()

    def terminate(self):
        """ Execute to unregister H2HTransaction """
        self.terminated = True
        self.cetpstate_table.remove(self)

    def get_remote_cesid(self):
        return self.r_cesid
    
    def _pre_process(self, cetp_msg):
        """ Checks for minimum packet detail & CETP format compliance in the inbound packet """
        try:
            self.get_packet_details(cetp_msg)
            self.query_message      = False

            if len(self.received_tlvs) == 0:
                self._logger.error(" The inbound packet contains no TLV to be processed.")
                return False
                        
            for received_tlv in self.received_tlvs:
                if self._check_tlv(received_tlv, ope="query"):
                    self.query_message = True
                    break

            if not self.query_message:
                for received_tlv in self.received_tlvs:
                    if self._check_tlv(received_tlv, ope="info") and self._check_tlv(received_tlv, group="id") and self._check_tlv(received_tlv, code ="fqdn"):
                        remote_hostid = received_tlv['value']
                        
                        if remote_hostid != self.dst_id:
                            return False
                        
            return True
        
        except Exception as ex:
            self._logger.error(" Exception '{}' in pre-processing the CETP packet".format(ex))
            return False

    @asyncio.coroutine
    def continue_cetp_processing(self, cetp_msg):
        try:
            self._logger.info("Continue establishing H2H session towards '{}' ({} -> {})".format(self.dst_id, self.sstag, 0))
            self._logger.info("Host policy: \n {} {} {}".format(15*'-', self.opolicy, 15*'-'))
            self.pprint(cetp_msg, m="Inbound Response")
            
            error                       = False
            tlvs_to_send, error_tlvs    = [], []
            self.rtt += 1
            
            if self.rtt > NEGOTIATION_RTT_THRESHOLD:                                        # Prevents infinite-exchange of CETP policies.
                self._unregister_h2h()
                return
            
            if not self._pre_process(cetp_msg):
                self._logger.error(" Inbound packet SST={} -> DST={} failed in pre_processing.".format(self.sstag, self.dstag))
                return
            
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
                            if ret_tlv != None:
                                tlvs_to_send += ret_tlv
                                continue
                        
                        if self._check_tlv(received_tlv, cmp="optional"):
                            self._logger.info(" An optional requirement {}.{} is not available locally.".format(received_tlv['group'], received_tlv['code']))
                            ret_tlv = self._get_unavailable_response(received_tlv)
                            tlvs_to_send.append(ret_tlv)
                        else:
                            self._logger.error(" A required TLV {}.{} is not available locally.".format(received_tlv['group'], received_tlv['code']))
                            #error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
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
                            self.opolicy_tmp.del_required(received_tlv)
                        else:
                            # Absorbs failure in case of 'optional' required policy TLV
                            if not self.opolicy.is_mandatory_required(received_tlv):
                                self.opolicy_tmp.del_required(received_tlv)
                            else:
                                self._logger.info(" TLV {}.{} failed verification".format(received_tlv['group'], received_tlv['code']))
                                error_tlvs = [self._get_terminate_tlv(err_tlv = received_tlv)]
                                error=True
                                break
                    else:
                        #self._logger.warning("Unrequested TLV '{}.{}' is received".format(received_tlv["group"], received_tlv["code"]))
                        pass
                
            
            # Evaluation of Policy Matching
            if error:
                self._logger.error(" H2H policy negotiation failed in {} RTT".format(self.rtt))
                self._process_negotiation_failure()
                self.h2h_negotiation_status = False
                
                if self.dstag==0:
                    return                                                                                            # Locally terminate session, as iCES is stateless
                else:
                    self._logger.info(" Responding remote CES with the terminate-TLV")                               # Since remote CES has completed the transaction
                    cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs = error_tlvs)        # Send as 'Info' TLV
                    self.last_packet_sent = cetp_message
                    self.cetp_negotiation_history.append(cetp_message)
                    self.pprint(cetp_message, m="oCES Packet")
                    return cetp_message
            else:
                if self._is_ready():
                    conn_created = yield from self._create_connection()
                    
                    if conn_created:
                        self._logger.info(" '{}'\n H2H policy negotiation succeeded in {} RTT".format(30*'#', self.rtt))
                        self._process_negotiation_success()
                        self.h2h_negotiation_status = True
                        return
                    
                    else:
                        self._logger.error(" Failed to create connection -> Responding host session with the terminate-TLV")
                        self._process_negotiation_failure()
                        tlvs_to_send = [self._get_terminate_tlv()]
                        if len(error_tlvs) != 0:   tlvs_to_send = error_tlvs
                        
                        cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                        self.pprint(cetp_message, m="Outbound Msg")
                        self.h2h_negotiation_status = False
                        return cetp_message
                else:
                    if self.rtt < NEGOTIATION_RTT_THRESHOLD:
                        # Issuing all sender policy requirements
                        for rtlv in self.opolicy.get_required():
                            ret_tlv = self._create_request_tlv(rtlv)
                            tlvs_to_send += ret_tlv
                    
                        tlvs_to_send.append(self.append_dstep_info())
                        cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)           # Sending 'response' as 'info'
                        self.last_packet_sent = cetp_message
                        self.last_packet_received = self.packet
                        self.cetp_negotiation_history.append(cetp_message)
                        self.pprint(cetp_message, m="Sent packet")
                        self.h2h_negotiation_status = None
                        return cetp_message
                    
                    else:
                        self._logger.error(" Inbound packet didn't meet all the policy requirements of the sender-host in {} RTT".format(self.rtt))
                        self._process_negotiation_failure()
                        self.h2h_negotiation_status = False
                        
                        if self.dstag!=0:
                            tlvs_to_send = [self._get_terminate_tlv()]
                            cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                            self.pprint(cetp_message)
                            return cetp_message
        except:
            utils3.trace()
            return None


    def _is_ready(self):
        return len(self.opolicy_tmp.required)==0 and (self.dstag!=0)
    
    def _process_negotiation_failure(self):
        """ Steps to execute on failure of negotiation """
        self.unregister_handler.cancel()
        self._unregister_h2h()
    
    def _process_negotiation_success(self):
        """ Executes DNS callback, AND session-tags management for an established transaction. """
        self.cetpstate_table.reregister(self)
        self.unregister_handler.cancel()
        #self.cetp_h2h.update_H2H_transaction_count(initiated=False)                            # To reduce number of ongoing transactions.
        return True
    
    @asyncio.coroutine
    def _create_connection(self):
        """ Extract the negotiated parameters to create a connection state """
        try:
            self.lid, self.rid              = None, None
            self.lfqdn, self.rfqdn          = self.src_id, self.dst_id                  #self._create_connection_get_fqdns()
            self.lip                        = self.host_ip
            self.lpip                       = self._allocate_proxy_address(self.src_id)
            
            if self.lpip is None:
                return False
            
            self._record_negotiated_params()
            self._logger.info("Negotiated params: {}".format(self.negotiated_params))
            
            hard_ttl, idle_ttl = None, None
            if 'hard_ttl' in self.negotiated_params:
                hard_ttl = self.negotiated_params['hard_ttl']
            if 'idle_ttl' in self.negotiated_params:
                idle_ttl = self.negotiated_params["idle_ttl"]
            
            self.conn = connection.H2HConnection(self.network, self.cetpstate_table, self.ap, self.host_table, self.conn_table, self.lid, self.lip, self.lpip, \
                                                 self.rid, self.lfqdn, self.rfqdn, self.sstag, self.dstag, self.r_cesid, hard_ttl=hard_ttl, idle_ttl=idle_ttl)
            
            yield from self.conn.insert_dataplane_connection()
            self.conn_table.add(self.conn)
            self._execute_dns_callback(r_addr = self.lpip)
            return True
    
        except Exception as ex:
            self._logger.error("Exception in connection creation: '{}'".format(ex))
            return False
    
    
    def _execute_dns_callback(self, r_addr=None):
        """ Executes DNS callback towards host """
        try:
            for cb in self.cb_list:                
                (cb_f, cb_args) = cb
                dns_q, addr = cb_args
                q = dns_q.question[0]
                rdtype = q.rdtype
                    
                if network_helper3.is_ipv4(r_addr) and (rdtype == dns.rdatatype.A):
                    response = dnsutils.make_response_answer_rr(dns_q, self.dst_id, rdtype, r_addr, rdclass=1, ttl=120, recursion_available=True)
                    cb_f(dns_q, addr, response)
                elif network_helper3.is_ipv6(r_addr) and (rdtype == dns.rdatatype.AAAA):
                    response = dnsutils.make_response_answer_rr(dns_q, self.dst_id, rdtype, r_addr, rdclass=1, ttl=120, recursion_available=True)
                    cb_f(dns_q, addr, response)
                else:
                    self._logger.warning("Requested DNS record type and proxy address do not match.")
                    cb_f(dns_q, addr)
                        
        except Exception as ex:
            self._logger.error("Exception in _execute_dns_callback {} for query: {}".format(ex, q))
            utils3.trace()
    
    def terminate_session(self):
        """ Sends a terminate TLV towards remote CES """
        tlvs_to_send = [self._get_terminate_tlv()]
        cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
        self._send(cetp_message)
    
    def _send(self, msg):
        self.cetp_h2h.send(msg)
        
    def is_local_host_allowed(self, hostid):
        """ Checks in the CETPSecurity module if the traffic from the sender is permitted (towards remote CES).. OR  whether the host is blacklisted """
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_BlacklistedLHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_DisabledLHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_LocalHosts_Outbound_Disabled, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_RCES_BlockedHostsByRCES, hostid, key=self.r_cesid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_LCES_FilteredSourcesTowardsRCES, hostid, key=self.r_cesid):
            return False
        return True

    def is_remote_destination_allowed(self, hostid):
        """ Determines whether the traffic to destination is permitted """
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_BlacklistedRHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_RemoteHosts_inbound_Disabled, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_LCES_BlockedHostsOfRCES, hostid, key=self.r_cesid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_RCES_UnreachableRCESDestinations, hostid, key=self.r_cesid):
            return False
        return True
    
    def lookupkeys(self):
        if self.is_negotiated():
            keys = [((KEY_ESTABLISHED_TAGS, self.sstag, self.dstag), True), ((KEY_HOST_IDS, self.src_id, self.dst_id), True), ((KEY_RCESID, self.r_cesid), False)]
        else:
            keys = [((KEY_INITIATED_TAGS, self.sstag, 0), True), ((KEY_HOST_IDS, self.src_id, self.dst_id), True), ((KEY_RCESID, self.r_cesid), False)]

        return keys

        
    def post_h2h_negotiation(self, cetp_message):
        """  Processes a CETP packet received on a negotiated H2H session.  e.g. a 'terminate' TLV, or change in ratelimit of data connection. 
        """
        try:
            self._logger.info(" Post-H2H negotiation packet on (SST={}, DST={})".format(self.sstag, self.dstag))
            self.packet = cetp_message
            tlv_to_send = []
            
            if 'TLV' not in cetp_message:
                return False
            
            for received_tlv in cetp_message['TLV']:
                
                if self._check_tlv(received_tlv, group="control") and self._check_tlv(received_tlv, code="terminate"):
                    self._logger.warning(" Terminate received for an established H2H Session ({}->{}).".format(self.sstag, self.dstag))
                    self.terminate()
                    key = (connection.KEY_MAP_CES_TO_CES, self.sstag, self.dstag)
                    
                    if self.conn_table.has(key):
                        print("Before deleting connection")
                        conn = self.conn_table.get(key)
                        self.conn_table.remove(conn)
                    else:
                        self._logger.error("No H2H connection object is found for ({}->{})".format(self.sstag, self.dstag))
                        #print("After terminate", self.conn_table.connection_dict)
                        
        except Exception as ex:
            self._logger.error("Exception '{}' in post_h2h_negotiation".format(ex))



class H2HTransactionInbound(H2HTransaction):
    def __init__(self, sstag=None, dstag=None, l_cesid="", r_cesid="", policy_mgr= None, cetpstate_table= None, interfaces=None, conn_table=None, cetp_h2h=None, \
                 cetp_security=None, ces_params=None, host_table=None, pool_table=None, network=None, name="H2HTransactionInbound"):
        self.sstag              = sstag
        self.dstag              = dstag
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.policy_mgr         = policy_mgr                # This could be policy client in future use.
        self.cetpstate_table    = cetpstate_table
        self.interfaces         = interfaces
        self.direction          = "inbound"
        self.conn_table         = conn_table
        self.cetp_h2h           = cetp_h2h
        self.cetp_security      = cetp_security
        self.network            = network
        self.ces_params         = ces_params
        self.host_table         = host_table
        self.pool_table         = pool_table
        self.negotiated_params  = {}
        self._name              = name
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransactionInbound)

    @asyncio.coroutine
    def load_policies(self, host_id):
        """ Returns None OR host policy """
        #index = self.policy_mgr.mapping_srcId_to_policy(host_id)
        yield from asyncio.sleep(0.000)
        self.ipolicy     = self.policy_mgr.get_host_policy(self.direction, host_id=host_id)
        self.ipolicy_tmp = self.get_policy_copy(self.ipolicy)
        self.policy      = self.ipolicy
        return self.policy

    @asyncio.coroutine
    def load_policies2(self, host_id):
        """ Download the host policy from Policy management System """         
        url         = "http://100.64.254.24/API/host_cetp_user?"
        direction   = "INGRESS"
        params      = {'lfqdn': host_id, 'direction': direction}
        timeout     = 2
        response    = yield from self.policy_mgr.get(url, params=params, timeout=timeout)
        
        if response is not None:             
            host_policy      = json.loads(response)
            self.ipolicy     = PolicyManager.PolicyCETP(host_policy)
            self.ipolicy_tmp = self.get_policy_copy(self.ipolicy)
            self.policy      = self.ipolicy
            return self.policy
    
    @asyncio.coroutine
    def _pre_process(self, cetp_msg):
        """ Pre-process the inbound packet for the minimum necessary details. """
        try:
            self.get_packet_details(cetp_msg)
            self.src_id, self.dst_id = "", ""
            dstep_tlv                = None
            
            if len(self.received_tlvs) == 0:
                self._logger.debug("Inbound CETP has no TLVs for processing")
                return False
            
            for received_tlv in self.received_tlvs:
                if self._check_tlv(received_tlv, ope="info"):
                    if (received_tlv['group']== "id") and (received_tlv['code']=="fqdn"):
                        self.src_id = received_tlv['value']
                    elif (received_tlv['group']=="control") and (received_tlv['code']=="dstep"):
                        self.dst_id = received_tlv["value"]
                        dstep_tlv = received_tlv
            
            self.received_tlvs.remove(dstep_tlv)
            
            # Enforcing Max length of FQDN = 256
            if (len(self.src_id)==0) or (len(self.src_id)>256):
                return False
            if (len(self.dst_id)==0) or (len(self.dst_id)>256):
                return False
            
            if not self.has_domain(self.dst_id):
                self._logger.warning(" Destination '{}' is not served by local CES '{}'.".format(self.dst_id, self.l_cesid))
                return False
            
            if not self.is_remote_host_allowed(self.src_id):
                self._logger.warning(" Sender '{}' is not allowed to communicate.".format(self.src_id))
                return False
            
            if not self.is_local_destination_allowed(self.dst_id):
                self._logger.warning(" Connection to local destination '{}' is not allowed".format(self.dst_id))
                return False
            
            if not self._has_available_proxypool(self.dst_id):
                self._logger.error(" Proxypool of the destination host running '{}' is depleted.".format(self.dst_id))
                return False
            
            host_policy = yield from self.load_policies(self.dst_id)
            
            if host_policy is None:
                self._logger.error(" Failure to load inbound CETP policy of Local Destination '{}'".format(self.dst_id))
                return False
            
            return True
        
        except Exception as ex:
            self._logger.error(" Exception '{}' in pre-processing the inbound packet.".format(ex))
            return False


    def is_local_destination_allowed(self, hostid):
        """ Determines whether the traffic to destination is permitted """
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_BlacklistedLHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_DisabledLHosts, hostid):
            return False
        #if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_BlockedHostsByRCES, hostid, key=self.r_cesid):
        #    return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_LCES_UnreachableDestinationsForRCES, hostid, key=self.r_cesid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_LocalHosts_Inbound_Disabled, hostid):
            return False
        return True

    def is_remote_host_allowed(self, hostid):
        """ Checks in the CETPSecurity module if the traffic from the sender host is permitted OR denied """
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_BlacklistedRHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_LCES_BlockedHostsOfRCES, hostid, key=self.r_cesid):
            return False
        return True

    @asyncio.coroutine
    def start_cetp_processing(self, cetp_message):
        """ Processes the inbound CETP-packet for negotiating the H2H policies """
        try:
            self._logger.info("{}".format(42*'*') )
            self.pprint(cetp_message, m="H2H Inbound packet")
            tlvs_to_send, error_tlvs = [], []
            negotiation_status  = None
            cetp_response       = ""
            error               = False
            pre_processed       = yield from self._pre_process(cetp_message)
    
            if not pre_processed:
                self._logger.error(" Inbound CETP packet ({}->{}) failed pre-processing()".format(self.sstag, self.dstag))
                negotiation_status = False
                return
            
            # Processing inbound packet
            for received_tlv in self.received_tlvs:
                
                # Processing sender's requests  -- Evaluates whether the sender's requirements could be answered
                if self._check_tlv(received_tlv, ope="query"):
                    if self.ipolicy.has_available(received_tlv):
                        ret_tlv = self._create_response_tlv(received_tlv)
                        if ret_tlv != None:
                            tlvs_to_send += ret_tlv
                            continue
                        
                    if self._check_tlv(received_tlv, cmp="optional"):
                        self._logger.info(" An optional requirement TLV {}.{} is not available locally.".format(received_tlv['group'], received_tlv['code']))
                        ret_tlv = self._get_unavailable_response(received_tlv)
                        tlvs_to_send.append(ret_tlv)
                    else:
                        #self._logger.error(" A required TLV {}.{} is not available locally.".format(received_tlv['group'], received_tlv['code']))
                        error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                        error = True
                        break
                            
                # Checks whether the sender's offer met the policy requirements of destination, and the Offer can be verified.
                elif self._check_tlv(received_tlv, ope="info"):
                    
                    if self.ipolicy.has_required(received_tlv):
                        if self._verify_tlv(received_tlv):
                            self.ipolicy_tmp.del_required(received_tlv)
                        else:
                            # Absorbs failure in case of 'optional' required policy TLV
                            if not self.ipolicy.is_mandatory_required(received_tlv):
                                self.ipolicy_tmp.del_required(received_tlv)
                            else:
                                self._logger.info("TLV {}.{} failed verification".format(received_tlv['group'], received_tlv['code']))
                                error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                                error = True
                                break
                    else:
                        self._logger.info(" A Non-requested TLV {} is received: ".format(received_tlv))
                        pass
        
            if error:
                tlvs_to_send        = error_tlvs
                negotiation_status  = False
                
            else:
                if self._is_ready():
                    # Create H2H connection, if all the  requirements of remote-host are met
                    conn_created = yield from self._create_connection()
                    
                    if conn_created:
                        self._logger.info("{} H2H-policy negotiation succeeded -> Create transaction (SST={}, DST={})".format(42*'#', self.sstag, self.dstag))
                        negotiation_status = True
                        stateful_transansaction     = self._export_to_stateful()            # Create stateful version
                    else:
                        if len(error_tlvs) == 0:
                            error_tlvs = [self._get_terminate_tlv()]
                            
                        negotiation_status = False
                        tlvs_to_send       = error_tlvs
                        
                else:
                    self._logger.info(" {} unsatisfied iCES requirements -> Initiate full query: ".format(len(self.ipolicy_tmp.required)) )
                    tlvs_to_send = []
                    negotiation_status = None
                    
                    for rtlv in self.ipolicy.get_required():            # Generating Full Query message
                        ret_tlv = self._create_request_tlv(rtlv)
                        tlvs_to_send += ret_tlv
    
                    
            cetp_message = self.get_cetp_message(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
            self.pprint(cetp_message, m="CETP Response packet")
            if negotiation_status is True:
                stateful_transansaction.last_packet_sent = cetp_message
            return cetp_message

        except:
            utils3.trace()
            return None
    

    def _is_ready(self):
        return len(self.ipolicy_tmp.required)==0
    
    @asyncio.coroutine
    def _create_connection(self):
        try:
            self.sstag                      = self.generate_session_tags(self.dstag)
            self.lfqdn, self.rfqdn          = self.dst_id, self.src_id
            host_obj                        = self.host_table.get((host.KEY_HOST_SERVICE, self.dst_id))
            self.lid, self.rid              = None, None
            self.lip                        = host_obj.ipv4
            self.lpip                       = self._allocate_proxy_address(self.dst_id)
            
            if self.lpip is None:
                return False
            
            self._record_negotiated_params()
            self._logger.info("Negotiated params: \n ---- \n {} \n ---- ".format(self.negotiated_params))
            
            hard_ttl, idle_ttl = None, None
            if 'hard_ttl' in self.negotiated_params:
                hard_ttl = self.negotiated_params['hard_ttl']
            if 'idle_ttl' in self.negotiated_params:
                idle_ttl = self.negotiated_params["idle_ttl"]
            
            self.conn = connection.H2HConnection(self.network, self.cetpstate_table, self.ap, self.host_table, self.conn_table, self.lid, self.lip, self.lpip, \
                                                 self.rid, self.lfqdn, self.rfqdn, self.sstag, self.dstag, self.r_cesid, hard_ttl=hard_ttl, idle_ttl=idle_ttl)
            
            yield from self.conn.insert_dataplane_connection()
            self.conn_table.add(self.conn)
            return True
        
        except Exception as ex:
            self._logger.error("Exception in connection creation: '{}'".format(ex))
            return False
    

    def _export_to_stateful(self):
        """ Creates connection and complete H2Htransaction to stateful """
        new_transaction = H2HTransactionOutbound(sstag=self.sstag, dstag=self.dstag, policy_mgr= self.policy_mgr, cetpstate_table=self.cetpstate_table, conn_table=self.conn_table, \
                                                 l_cesid=self.l_cesid, r_cesid=self.r_cesid, direction="inbound", src_id=self.src_id, dst_id=self.dst_id, cetp_h2h=self.cetp_h2h, \
                                                 cetp_security=self.cetp_security, network=self.network)
        
        new_transaction.opolicy                 = self.ipolicy
        new_transaction.policy                  = self.policy
        new_transaction.last_received_packet    = self.packet
        new_transaction.h2h_negotiation_status  = True
        new_transaction.conn                    = self.conn
        self.cetpstate_table.add(new_transaction)
        return new_transaction
    


class H2HTransactionLocal(H2HTransaction):
    def __init__(self, loop=None, host_ip="", cb=None, src_id="", dst_id="", dst_ip="", policy_mgr= None, host_table=None, cetpstate_table=None, cetp_h2h=None, \
                 interfaces=None, conn_table=None, pool_table=None, cetp_security=None, network=None, test_results=[], name="H2HTransactionLocal"):
        self._loop              = loop
        self.cb                 = cb
        self.host_ip            = host_ip                   # IP of the sender host
        self.src_id             = src_id                    # FQDN
        self.dst_id             = dst_id
        self.dst_ip             = dst_ip
        self.policy_mgr         = policy_mgr
        self.cetpstate_table    = cetpstate_table
        self.cetp_h2h           = cetp_h2h
        self.host_table         = host_table
        self.interfaces         = interfaces
        self.conn_table         = conn_table
        self.cetp_security      = cetp_security
        self.pool_table         = pool_table
        self.network            = network
        self.l_cesid            = ""
        self.r_cesid            = ""                        # For compatbility with base class
        self.negotiated_params  = {}
        self.test_results       = test_results
        self._name              = name
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransactionLocal)
    
    @asyncio.coroutine
    def load_policies(self, host_id = "", direction = ""):
        yield from asyncio.sleep(0.000)
        policy = self.policy_mgr.get_host_policy( direction, host_id = host_id)
        return policy

    @asyncio.coroutine
    def load_policies2(self, host_id="", direction=""):
        """ Downloads the host policy from Policy Management System """
        timeout     = 2
        url         = "http://100.64.254.24/API/host_cetp_user?"
        params      = {'lfqdn': host_id, 'direction': direction}
        response    = yield from self.policy_mgr.get(url, params=params, timeout=timeout)
        
        if response is not None:
            policy      = json.loads(response)
            host_policy = PolicyManager.PolicyCETP(host_policy)
            return host_policy
        
    @asyncio.coroutine
    def _pre_process(self):
        try:
            sender_permitted        = self.check_outbound_permission(self.src_id)
            destination_permitted   = self.check_inbound_permission(self.dst_id)
            #print("sender_permitted, destination_permitted", sender_permitted, destination_permitted)
            
            if (not sender_permitted) or (not destination_permitted):
                self._logger.warning("Communication from sender <{}> to destination <{}> is not allowed.".format(self.src_id, self.dst_id))
                return False
            
            if not self._has_available_proxypool(self.src_id):
                self._logger.error(" Proxypool of the sender '{}' is depleted.".format(self.src_id))
                return False

            if not self._has_available_proxypool(self.dst_id):
                self._logger.error(" Proxypool of the destination host running '{}' is depleted.".format(self.dst_id))
                return False
            
            self.opolicy = yield from self.load_policies(host_id = self.src_id, direction = "outbound")
            self.ipolicy = yield from self.load_policies(host_id = self.dst_id, direction = "inbound")
            
            if self.opolicy is None or (self.ipolicy is None):
                return False
            
            return True
        
        except Exception as ex:
            self._logger.error("Exception '{}' in pre-processing the packet".format(ex))
            return False
        
    @asyncio.coroutine
    def start_cetp_processing(self):
        """ Starts the CETPLocal policy negotiation """
        error = False
        pre_processed = yield from self._pre_process()
        
        if not pre_processed:
            self._logger.error(" Failure in initiating the local H2H session towards '{}'.".format(self.dst_id))
            return False
        
        # If a host is reaching its ownself or own services, we shall return its own IP address in DNS callback.
        if self.dst_id.endswith(self.src_id):
            self._execute_dns_callback(r_addr=self.host_ip)
            return True
         
        self._logger.info("Local-host policy: \n--- {} ----".format(self.opolicy))
        self._logger.info("Remote-host policy: \n--- {} ----".format(self.ipolicy))
        
        self._logger.info("Match Outbound-Requirements vs Inbound-Available")
        for rtlv in self.opolicy.get_required():
            
            if self.ipolicy.has_available(rtlv):
                resp_tlv = self.ipolicy.get_available(tlv=rtlv)
                # Check if the TLV value is acceptable to the sender host's requirements
                if not self._verify_tlv(resp_tlv, policy=self.opolicy):
                    # Absorbs failure in case of 'optional' required policy TLV
                    if self.opolicy.is_mandatory_required(rtlv):
                        self._logger.error(" TLV '{}.{}' failed verification".format(rtlv['group'], rtlv['code']))
                        error = True
                        break
            else:
                if self.opolicy.is_mandatory_required(rtlv):
                    self._logger.error("Outbound host Requirement '{}.{}' is not met by destination '{}'".format(rtlv['group'], rtlv['code'], self.dst_id))
                    error = True
                    break
                
        if not error:
            self._logger.info("Match Inbound-Requirements vs Outbound-Available")
            for rtlv in self.ipolicy.get_required():
                
                if self.opolicy.has_available(tlv=rtlv):
                    resp_tlv = self.opolicy.get_available(rtlv)
                    if not self._verify_tlv(resp_tlv, policy=self.ipolicy):
                        # Absorbs failure in case of 'optional' required policy TLV
                        if self.opolicy.is_mandatory_required(rtlv):
                            self._logger.error(" TLV {}.{} failed verification".format(resp_tlv['group'], resp_tlv['code']))
                            error = True
                            break
                else:
                    if self.ipolicy.is_mandatory_required(rtlv):
                        self._logger.error("Inbound host requirement '{}.{}' is not met by the sender '{}'".format(rtlv['group'], rtlv['code'], self.src_id))
                        error = True
                        break

        if error:
            self._logger.warning("Local CETP Policy mismatched! Connection refused {} -> {}".format(self.src_id, self.dst_id))
            self._execute_dns_callback()
            #self.dns_state.delete(stateobj)
            return False
        else:
            self._logger.info(" Local CETP Policy matched! Allocate proxy address. {} -> {}".format(self.src_id, self.dst_id))
            lpip = yield from self._create_connection()
            
            if lpip is not None:
                self._execute_dns_callback(r_addr = lpip)           # Returning CES proxy address for DNS response
                return True
            else:
                self._execute_dns_callback()
                return False

        
    @asyncio.coroutine
    def _create_connection(self):
        try:
            lip             = self.host_ip
            host_obj        = self.host_table.get((host.KEY_HOST_SERVICE, self.dst_id))
            rip             = host_obj.ipv4
            lfqdn, rfqdn    = self.src_id, self.dst_id
            lid, rid        = None, None
            lpip            = self._allocate_proxy_address(self.src_id)
            rpip            = self._allocate_proxy_address(self.dst_id)
            
            hard_ttl, idle_ttl = None, None
            if 'hard_ttl' in self.negotiated_params:
                hard_ttl = self.negotiated_params['hard_ttl']
            if 'idle_ttl' in self.negotiated_params:
                idle_ttl = self.negotiated_params["idle_ttl"]
            #self._logger.info("Negotiated params: \n ---- \n {} \n ---- ".format(self.negotiated_params))
            
            if (lpip is None) or (rpip is None):
                self._logger.error("Error assigning proxy addresses: lpip={}, rpip={}".format(lpip, rpip))
                return None
            else:
                self.conn = connection.LocalConnection(self.network, self.ap, self.host_table, lip=lip, lpip=lpip, rip=rip, rpip=rpip, lfqdn=lfqdn, rfqdn=rfqdn, hard_ttl=hard_ttl, idle_ttl=idle_ttl)
                yield from self.conn.insert_dataplane_connection()                
                self.conn_table.add(self.conn)
                return lpip
        
        except Exception as ex:
            self._logger.error(" Exception '{}' in _create_connection()".format(ex))
            return None
        
    def _execute_dns_callback(self, r_addr=None):
        """ Executes DNS callback towards host """
        try:
            (cb_f, cb_args) = self.cb
            dns_q, addr = cb_args
            
            if r_addr is None:
                cb_f(dns_q, addr)
            else:
                response = dnsutils.make_response_answer_rr(dns_q, self.dst_id, dns.rdatatype.A, r_addr, rdclass=1, ttl=120, recursion_available=True)
                cb_f(dns_q, addr, response)
            
        except Exception as ex:
            self._logger.error("Exception in _execute_dns_callback {}".format(ex))


    def check_outbound_permission(self, hostid):
        """ Checks in the CETPSecurity module if traffic from the sender is permitted """
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_BlacklistedLHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_DisabledLHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_LocalHosts_Outbound_Disabled, hostid):
            return False
        return True

    def check_inbound_permission(self, hostid):
        """ Checks in the CETPSecurity module if traffic to the destination host is permitted. """
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_BlacklistedLHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_DisabledLHosts, hostid):
            return False
        if self.cetp_security.has_filtered_domain(CETPSecurity.KEY_LocalHosts_Inbound_Disabled, hostid):
            return False
        return True
