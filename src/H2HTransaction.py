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
import icetpLayering
import ocetpLayering
import cetpOperations
import CETP
import copy

LOGLEVEL_H2HTransaction         = logging.INFO
LOGLEVEL_H2HTransactionOutbound = logging.INFO
LOGLEVEL_H2HTransactionInbound  = logging.INFO
LOGLEVEL_oC2CTransaction        = logging.INFO
LOGLEVEL_iC2CTransaction        = logging.INFO

KEY_ONGOING                     = 1
KEY_ESTABLISHED                 = 2
NEGOTIATION_RTT_THRESHOLD       = 3

DEFAULT_CONNECTION_EXPIRY_TIME  = 31



class H2HTransaction(object):
    def __init__(self, name="H2HTransaction"):
        self.name       = name
        self._logger    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransaction)

    def get_cetp_packet(self, sstag=None, dstag=None, req_tlvs=[], offer_tlvs=[], avail_tlvs=[]):
        """ Default CETP fields for signalling message """
        version         = 1
        cetp_header     = {}
        cetp_header['VER']          = version
        cetp_header['SST']          = sstag
        cetp_header['DST']          = dstag
        if len(req_tlvs):
            cetp_header['query']    = req_tlvs
        if len(offer_tlvs):
            cetp_header['info']     = offer_tlvs
        if len(avail_tlvs):
            cetp_header['response'] = avail_tlvs
        
        return cetp_header

    def _verify_tlv(self, tlv):
        if 'cmp' in tlv:
            if tlv['cmp'] == "NotAvailable":
                return False
        return True
        
    def _get_unavailable_response(self, tlv):
        tlv['cmp'] = 'NotAvailable'
        
    def _get_terminate_tlv(self, err_tlv=None):
        if err_tlv is None:
            err_tlv = {}
            err_tlv['group'], err_tlv['code'], err_tlv['value'] = "control", "terminate", ""
            return err_tlv
        else:
            value = err_tlv
            err_tlv = {}
            err_tlv['group'], err_tlv['code'], err_tlv['value'] = "control", "terminate", value
            return err_tlv
                    
    def _create_response_tlv(self, tlv):
        tlv['value'] = "Some value"
        return tlv

    def pprint(self, packet):
        self._logger.info("CETP Packet")
        for k, v in packet.items():
            if k not in ['query', 'info', 'response']:
                print(k+" : ", v)
        
        for k in ['query', 'info', 'response']:
            if k in packet:
                print(k+":")
                tlvs = packet[k]
                for tlv in tlvs:
                    print('\t', tlv)
        print("\n")



class H2HTransactionOutbound(H2HTransaction):
    def __init__(self, loop=None, sstag=0, dstag=0, dns_q=None, src_id="", dst_id="", local_addr=None, l_cesid="", r_cesid="", remote_addr=None, policy_mgr= None, cetpstate_mgr=None, dns_callback=None, name="H2HTransactionOutbound"):
        self.sstag, self.dstag  = sstag, dstag
        self.dnsmsg             = dns_q
        self.src_id             = src_id                    # FQDN
        self.dst_id             = dst_id
        self.local_addr         = local_addr                # (src_ip, src_port)
        self.remote_addr        = remote_addr
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.policy_mgr         = policy_mgr
        self.cetpstate_mgr      = cetpstate_mgr
        self.dns_cb             = dns_callback
        self._loop              = loop
        self.h2h_negotiation_status = False

        self.name               = name
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransactionOutbound)
        self.start_time         = time.time()

        self.rtt                = 0
        self.cetp_negotiation_history   = []
        self.load_policies(self.src_id)
        self.generate_session_tags(sstag)
        # self.dns_callback   = dns_callback        # Function to execute DNS response
        # self.cb_args        = cb_args             # Arguments required to execute DNS callback.
        if self.dstag == 0:
            self.h2h_handler    = self._loop.call_later(DEFAULT_CONNECTION_EXPIRY_TIME, self.handle_h2h)

    def handle_h2h(self):
        now = time.time()
        if ( (now-self.start_time) > DEFAULT_CONNECTION_EXPIRY_TIME) and (not self.h2h_negotiation_status):
            self.cetpstate_mgr.remove((self.sstag, 0))
            self._logger.info("Removing the H2H-state for dst_id {}".format(self.dst_id))

    
    def load_policies(self, src_id):
        index = self.policy_mgr.mapping_srcId_to_policy(src_id)                # dest-fqdn to policy conversion
        direction = "outbound"
        self.ipolicy, self.ipolicy_tmp  = None, None
        self.opolicy, self.opolicy_tmp  = None, None

        self.opolicy        = self.policy_mgr._get_copy_host_policy(index, direction)
        self.opolicy_tmp    = self.policy_mgr._get_copy_host_policy(index, direction)
        self.ipolicy        = self.policy_mgr._get_copy_host_policy(index, "inbound")
        self.ipolicy_tmp    = self.policy_mgr._get_copy_host_policy(index, "inbound")

    def generate_session_tags(self, sstag):
        if sstag == 0:
            self.sstag = random.randint(0, 2**32)
            self.dstag = self.dstag
        else:
            self.sstag = sstag
            self.dstag = random.randint(0, 2**32)           # later on, add checks for conflicts with other (sstag, dstag)

    def _pre_process(self, msg):
        self.cetp_req, self.cetp_info, self.cetp_resp = [], [], []

        if "query" in self.packet:
            self.cetp_req = self.packet['query']
        if "info" in self.packet:
            self.cetp_info = self.packet['info']
        if "response" in self.packet:
            self.cetp_resp = self.packet['response']
        return True
        self.sanity_checking(msg)   # for min packet details & format    - on response packet


    def sanity_checking(self, msg):
        return True
    
    @asyncio.coroutine
    def start_cetp_processing(self):
        """ Returns CETP message containing [Offer & Request] tlvs towards iCES """
        self.req_tlvs, self.offer_tlvs, self.ava_tlvs = [], [], []
        dstep_tlv = self.append_dstep_info()
        self.offer_tlvs.append(dstep_tlv)        
        # print("self.opolicy: ", self.opolicy)
        # We shall check if src_id supports the id_type as of the destination-id, otherwise maybe not even initiate a transaction? or initiate with a default ID-type?
        # And regardless of id_type being used, FQDN of host shall be made part of the messages exchanged?
        
        for tlv in self.opolicy.get_required():
            tlv["value"] = ""
            self.req_tlvs.append(tlv)
        
        for tlv in self.opolicy.get_offer():
            tlv["value"] = "offer"
            self.offer_tlvs.append(tlv)

        cetp_signaling = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=self.req_tlvs, offer_tlvs=self.offer_tlvs, avail_tlvs=self.ava_tlvs)
        cetp_packet = json.dumps(cetp_signaling)
        self.last_packet_sent = cetp_packet
        self.cetp_negotiation_history.append(cetp_packet)
        self.rtt += 1
        self.cetpstate_mgr.add((self.sstag,0), self)                # Register state in Connection table to continue negotiating h2h-transaction later
        return cetp_packet
        
        #policies = yield from self.get_policies_from_PolicySystem(r_id, r_cesid)

    def append_dstep_info(self):
        dstep_tlv = {}
        dstep_tlv["group"], dstep_tlv["code"], dstep_tlv["value"] = "control", "dstep", self.dst_id 
        return dstep_tlv

    def _cetp_established(self, cetp_packet):
        # It can perhaps execute DNS callback as well
        self.dstag = cetp_packet['DST']
        self.cetpstate_mgr.remove((self.sstag, 0))
        self.cetpstate_mgr.add((self.sstag, self.dstag), self)
    
    def _execute_dns_callback(self, cb_args, resolution=True):
        self._logger.debug(" Executing DNS callback")
        dns_q, addr = cb_args
        self.dns_cb(dns_q, addr, success=resolution)

    def create_transaction_in_dp(self, cetp_msg):
        pass
        #cetp_msg
        #self.create_dataplane_entry(sst, dst, info)

    @asyncio.coroutine
    def get_policies_from_PolicySystem(self, r_hostid, r_cesid):        # Has to be a coroutine in asyncio - PolicyAgent
        pass
        #yield from self.policy_client.send(r_hostid, r_cesid)

    def post_cetp_negotiation(self, cetp_packet):
        pass

    def continue_cetp_processing(self, cetp_packet):
        req_tlvs, offer_tlvs, ava_tlvs = [], [], []
        self.sstag, self.dstag = self.sstag, cetp_packet['SST']                 # self.dstag is sender's SST
        error = False
        self.packet = cetp_packet
        self._logger.info("Continue establishing connection (%d -> %d)" %(self.sstag, self.dstag))
        # self._logger.info(" ---- Outbound policy: ", self.opolicy)
        #self.pprint(cetp_packet)
        
        if self.rtt > NEGOTIATION_RTT_THRESHOLD:
            return False                            # Prevents infinite loop of CETP negotiation, Where remote end repeatedly sends only Requests-TLVs (or incomplete message??)

        # print("Host policy ", self.opolicy)
        if not self._pre_process(cetp_packet):
            self._logger.info("oCES failed pre_process() ")
            return None
        
        # Processing inbound packet
        if len(self.cetp_req):
            # Inbound packet has request TLVs               # Reply with 'response' vector for asked queries (+) Send sender host queries
            for tlv in self.cetp_req:
                if self.opolicy.has_available(tlv):
                    ret_tlvs = self._create_response_tlv(tlv)
                    ava_tlvs.append(ret_tlvs)
                else:
                    self._logger.info("oCES has notAvailable TLV" + tlv['group']+"."+ tlv['code'])
                    self._get_unavailable_response(tlv)
                    ava_tlvs.append(tlv)
                    # I guess it shall locally terminate outgoing connection
                    # OR it can append notavailable with TLV
            
            for tlv in self.opolicy.get_required():         # Issuing sender's policy requirements
                tlv["value"] = ""
                req_tlvs.append(tlv)

            dstep_tlv = self.append_dstep_info()
            ava_tlvs.append(dstep_tlv)
            
            cetp_signaling = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs, offer_tlvs=ava_tlvs, avail_tlvs=[])           # Send 'response' as 'info'
            cetp_packet = json.dumps(cetp_signaling)
            self.last_packet_sent = cetp_packet
            self.cetp_negotiation_history.append(cetp_packet)
            self.rtt += 1
            #self._logger.info("self.rtt: "+ self.rtt)
            return cetp_packet

        # Expectedly CETP message only has CETP responses, which require 1) verification
        # 2) May carry TLV notAvailable message; 3) TLV with wrong value; 4) Missing TLVs (due to rogue CETP messages from other nodes??) exploiting CETP states??
        # Upon success or Failure (Execute processing and then relevant DNS callbacks)
        
        for tlv in self.cetp_resp:
            if (tlv['group'] == 'control') and (tlv['code']=='terminate'):
                self._logger.info("Terminate received for {}.{} with value: ".format(tlv["group"], tlv['code'], tlv['value']) )
                error = True
                break
            elif self.opolicy.has_required(tlv):
                if self._verify_tlv(tlv):
                    self.opolicy_tmp.del_required(tlv)
                else:
                    self._logger.info("TLV {}.{} failed verification".format(tlv['group'], tlv['code']))         # handles TLV NotAvailable & TLV wrong value case
                    ava_tlvs =  []
                    ava_tlvs.append(self._get_terminate_tlv(err_tlv=tlv))
                    error=True
                    break
        
        if self.rtt > NEGOTIATION_RTT_THRESHOLD:
            error = True            # Preventing infinite loop of CETP negotiation

        if len(self.opolicy_tmp.required)>0:
            self._logger.info("oCES requirements are not met")                      # Couldn't meet all the queries, terminate the connection.. A more LAX version may allow another negotiation round 
            error = True

        if error:
            self._logger.info("CETP negotiation failed")
            if self.dstag==0:
                # Return false, and execute DNS failure callback
                cb_args=(self.dnsmsg, self.local_addr)
                self._execute_dns_callback(cb_args, resolution=False)
                return False
            else:
                # Return terminate packet to remote end, as it completed transaction
                self._logger.info("Responding remote end with terminate-TLV")
                cetp_signaling = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, offer_tlvs=ava_tlvs)        # Send as 'Info' TLV
                cetp_packet = json.dumps(cetp_signaling)
                self.last_packet_sent = cetp_packet
                self.cetp_negotiation_history.append(cetp_packet)
                return cetp_packet
        else:                
            self._logger.info("H2H negotiation succeeded --> Executing the DNS callback")
            self._cetp_established(cetp_packet)
            self.h2h_negotiation_status = True
            cb_args=(self.dnsmsg, self.local_addr)
            self._execute_dns_callback(cb_args)
            return None

        """
        l_policy = get_cached_policy()
        if policies_match_both_ways:
            self.create_transaction_in_dp()
            self.dns_callback(dns_response)
        return msg                                                      # resp_msg, error_message, or None.
        """
        



class H2HTransactionInbound(H2HTransaction):
    def __init__(self, packet, sstag=0, dstag=0, l_cesid="", r_cesid="", local_addr=(), remote_addr=(), policy_mgr= None, cetpstate_mgr= None, name="H2HTransactionInbound"):
        self.local_addr         = local_addr
        self.remote_addr        = remote_addr
        self.policy_mgr         = policy_mgr                # This could be policy client in future use.
        self.cetpstate_mgr      = cetpstate_mgr
        self.packet             = packet
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        
        self.name               = name
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransactionInbound)


    def load_policies(self, host_id):
        index = self.policy_mgr.mapping_srcId_to_policy(host_id)
        direction = "inbound"
        self.ipolicy, self.ipolicy_tmp  = None, None
        self.opolicy, self.opolicy_tmp  = None, None
        self.ipolicy        = self.policy_mgr._get_copy_host_policy(index, direction)
        self.ipolicy_tmp    = self.policy_mgr._get_copy_host_policy(index, direction)
        self.opolicy        = self.policy_mgr._get_copy_host_policy(index, "outbound")
        self.opolicy_tmp    = self.policy_mgr._get_copy_host_policy(index, "outbound")
    
    def _pre_process(self):
        self.cetp_req, self.cetp_info, self.cetp_resp = [], [], []
        if 'info' in self.packet:
            self.cetp_info = self.packet['info']
        if len(self.cetp_info)==0:
            return False
        
        destep_tlv = self.get_tlv(self.cetp_info, group='control', code='dstep')
        if destep_tlv == None:
            return False
        
        self.dst_hostId = destep_tlv['value']
        if not self.dst_hostId_is_valid(self.dst_hostId):
            self._logger.info(" Destination host is not available")
            return False
        
        #print("self.dst_hostId", self.dst_hostId)
        self.load_policies(self.dst_hostId)
        if "query" in self.packet:
            self.cetp_req = self.packet['query']
        if "response" in self.packet:
            self.cetp_resp = self.packet['response']
            
        return True
        # self.sanity_checking()      #for min packet details & format
        
    
    def sanity_checking(self, msg):
        return True

    def get_tlv(self, recv_tlv_lst, group=None, code=None):
        for tlv in recv_tlv_lst:
            if (tlv['group']==group) and (tlv['code'] == code):
                return tlv
        return None

    def start_cetp_processing(self, msg):
        """ Processing inbound packet vs destination policies """
        req_tlvs, offer_tlvs, ava_tlvs, error_tlvs = [], [], [], []
        error = False
        cetp_packet   = self.packet
        i_cetp_sstag  = self.packet['SST']
        o_cetp_sstag  = 0
        
        if not self._pre_process():
            self._logger.info("Inbound CETP packet failed CETP processing")
            return None
        
        #self.pprint(self.packet)
        
        # Processing inbound packet
        for tlv in self.cetp_info:                              # Processing 'info-TLVs'            #Can an attacker with Random TLV order disrupt this??
            if tlv["group"] == "control" and tlv["code"]== "terminate":
                self._logger.info("Terminate received for", tlv["group"], ".", tlv['code'], "with value: ", tlv['value'] )
                error = True
                break
            elif self.ipolicy.has_required(tlv):
                if self._verify_tlv(tlv):
                    self.ipolicy_tmp.del_required(tlv)
                else:
                    self._logger.info("TLV", tlv['group'], ".", tlv['code'], "failed verification")
                    terminate_tlv = self._get_terminate_tlv(err_tlv=tlv)
                    error_tlvs.append(terminate_tlv)
                    error = True
                    break
            
        if error:
            cetp_signaling = self.get_cetp_packet(sstag=o_cetp_sstag, dstag=i_cetp_sstag, avail_tlvs=error_tlvs)
            cetp_packet = json.dumps(cetp_signaling)
            return cetp_packet
        
        for tlv in self.cetp_req:                               # Processing 'Req-TLVs'
            if self.ipolicy.has_available(tlv):
                ret_tlvs = self._create_response_tlv(tlv)
                ava_tlvs.append(ret_tlvs)
            else:
                self._logger.info("TLV", tlv['group'], ".", tlv['code'], "is unavailable")
                self._get_unavailable_response(tlv)
                ava_tlvs.append(tlv)
                #error = True

        if len(self.ipolicy_tmp.required)>0:
            self._logger.info("# of iCES requirements not satisfied: ", len(self.ipolicy_tmp.get_required()))
            self._logger.info("Initiate full query")
            # Generating Full Query message
            req_tlvs, offer_tlvs, ava_tlvs = [], [], []
            for tlv in self.ipolicy.get_required():
                tlv["value"] = ""
                req_tlvs.append(tlv)
                o_cetp_sstag=0
                
        
        if (len(self.ipolicy_tmp.required)==0) and not error:
            #All the destination requirements are met -> Accept/Create CETP connection (i.e. by assigning 'SST') and Export to stateful (for post_establishment etc)
            o_cetp_sstag = random.randint(0, 2**32)
            self.sstag, self.dstag = o_cetp_sstag, i_cetp_sstag
            self._logger.info("H2H-policy negotiation succeeded -> Create stateful transaction (SST={}, DST={})".format(self.sstag, self.dstag))
            stateful_transansaction = self._export_to_stateful()
            self.cetpstate_mgr.add((o_cetp_sstag, i_cetp_sstag), stateful_transansaction)
        
        cetp_signaling = self.get_cetp_packet(sstag=o_cetp_sstag, dstag=i_cetp_sstag, req_tlvs=req_tlvs, offer_tlvs=offer_tlvs, avail_tlvs=ava_tlvs)
        #self.pprint(cetp_signaling)
        cetp_packet = json.dumps(cetp_signaling)
        self.last_packet_sent = cetp_packet
        return cetp_packet

        """
        policies = yield from self.get_policies_from_PolicySystem(r_id, r_cesid)
        if policies_match_both_ways:
            self.export_to_stateful(self)
            self.create_transaction_in_dp()
        return msg, error_message etc.
        """

    def _create_response_tlv(self, tlv):
        tlv['value'] = "Some value"
        return tlv

    def dst_hostId_is_valid(self, host):
        """ Emulates that host exists behind CES """
        return True

    def _export_to_stateful(self):
        new_transaction = H2HTransactionOutbound(sstag=self.sstag, dstag=self.dstag, local_addr=self.local_addr, remote_addr=self.remote_addr, policy_mgr= self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr, r_cesid="", src_id="", dst_id="")
        #Create it this way so that we can reuse the existing variables from the Stateless Transaction
        new_transaction.ipolicy = self.ipolicy
        new_transaction.opolicy = self.opolicy
        new_transaction.ipolicy_tmp = []            # Already met
        new_transaction.opolicy_tmp = []
        return new_transaction
    

    def create_transaction_in_dp(self):
        self.create_dataplane_entry(sst, dst, info)

    @asyncio.coroutine
    def get_policies_from_PolicySystem(self, r_hostid, r_cesid):
        yield from self.policy_client.send(r_hostid, r_cesid)

