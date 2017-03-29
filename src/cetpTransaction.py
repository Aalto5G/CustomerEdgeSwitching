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
import copy

LOGLEVEL_H2HTransactionOutbound = logging.INFO
LOGLEVEL_H2HTransactionInbound  = logging.INFO
LOGLEVEL_oC2CTransaction        = logging.INFO
LOGLEVEL_iC2CTransaction        = logging.INFO

LOGLEVELCETP                    = logging.DEBUG
KEY_ONGOING                     = 1
KEY_ESTABLISHED                 = 2

NEGOTIATION_RTT_THRESHOLD       = 3


class CETPConnectionObject(object):
    def __init__(self):
        self.cetp_transactions = {}                     #{(SST,0): A, (SST,DST): B}            #{KEY_ONgoing: [(SST,0): A, (SST,0): B], KEY_Established: [(SST,DST): C, (SST,DST): D]}
        
    def has(self, session_tag):
        return session_tag in self.cetp_transactions
    
    def add(self, session_tag, transaction):
        self.cetp_transactions[session_tag] = transaction
        
    def get(self, session_tag):
        return self.cetp_transactions[session_tag]
    
    def remove(self, session_tag):
        del self.cetp_transactions[session_tag]


LOGLEVEL_H2HTransaction     = logging.INFO

class H2HTransaction(object):
    def __init__(self, name="H2HTransaction"):
        self.name       = name
        self._logger    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransaction)

    def get_cetp_packet(self, sstag=None, dstag=None, req_tlvs=[], offer_tlvs=[], avail_tlvs=[]):
        """ Default CETP fields for signalling message """
        version         = 1
        cetp_header     = {}
        cetp_header['ver']          = version
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
    def __init__(self, sstag=0, dstag=0, dns_q=None, src_id="", dst_id="", local_addr=None, l_cesid="", r_cesid="", remote_addr=None, policy_mgr= None, cetpstate_mgr=None, dns_callback=None, name="H2HTransactionOutbound"):
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

        self.name               = name
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransactionOutbound)

        self.rtt                = 0
        self.cetp_negotiation_history   = []
        self.load_policies(self.src_id)
        self.generate_session_tags(sstag)
        # self.dns_callback   = dns_callback        # Function to execute DNS response
        # self.cb_args        = cb_args             # Arguments required to execute DNS callback.
    
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
        self.pprint(cetp_packet)
        self._logger.info(" ")
        
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
                self._logger.info("Terminate received for"+ tlv["group"]+ "."+ tlv['code']+ "with value: "+ tlv['value'] )
                error = True
                break
            elif self.opolicy.has_required(tlv):
                if self._verify_tlv(tlv):
                    self.opolicy_tmp.del_required(tlv)
                else:
                    self._logger.info("TLV"+ tlv['group']+ "."+ tlv['code']+ "failed verification")         # handles TLV NotAvailable & TLV wrong value case
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
            self._logger.info("Destination host is not available")
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
        
        self.pprint(self.packet)
        
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







class CETP(object):
    pass                        # CETP class will have multiple instances of CETP TLV

class CETPTLV(object):
    def __init__(self):
        self.ope    = None
        self.cmp    = None
        self.ext    = None
        self.group  = None
        self.code   = None
        self.len    = None
        self.value  = None
    
    def get_ope(self):
        return self.ope
    
    def get_group(self):
        return self.group

    def get_code(self):
        return self.code
        
    def get_value(self):
        return self.value

    def set_value(self, value):
        self.value = value
        
    def remove_value(self):
        self.value=None




CES_CODE_TO_POLICY= {'cesid':'cesid',                       'cesid':'cesid',                        #Contains the CES-ID
                    'ttl':'dp_ttl',                         'dp_ttl':'ttl',                         #Contains the TTL of the connection
                    'certificate':'certificate',            'certificate':'certificate',            #CES-Certificate
                    'keepalive_cycle':'keepalive_cycle',    'keepalive_cycle':'keepalive_cycle',    #Contains the keepalive cycle duration
                    'keepalive':'keepalive',                'keepalive':'keepalive',                #Keepalive
                    'fw_version':'fw_version',              'fw_version':'fw_version',              #Contains terminating codes {error, timeout} 
                    'session_limit':'ces_session_limit',    'ces_session_limit':'session_limit',    #Contains waning codes {backoff}
                    'host_ratelimit':'host_ratelimit',      'host_ratelimit':'host_ratelimit',      #Sets the rate limit {packets/s,bytes/s}
                    'caces':'caces',                        'caces':'caces',                        #Contains the CA address for validating a CES
                    'pow_algo':'pow_algo',                  'pow_algo':'pow_algo',                  #Proof-of-work mechanism to push the burden of communication to the sender
                    'pow':'pow',                            'pow':'pow'
                    }


ALL_C2C_CODES = {'cesid', 'ttl', 'cert', 'keepalive_cycle', 'fw_ver', 'session_limit', 'terminate', 'warning', 'host_ratelimit', 'headersignature', \
                 'caces', 'pow', 'keepalive'}


ALL_GROUPS = {'id', 'payload', 'rloc', 'control', 'mobility','ces'}

TLV_GROUP = {'id':'id',                 'id':'id',
             'payload':'payload',       'payload':'payload',
             'rloc':'rloc',             'rloc':'rloc',
             'control':'control',       'control':'control',
             'mobility':'mobility',     'mobility':'mobility',
             'ces':'ces',               'ces':'ces'
             }

SEND_TLV_ID_CODE            = {}
SEND_TLV_RLOC_CODE          = {}
SEND_TLV_PAYLOAD_CODE       = {}

RESPONSE_TLV_ID_CODE        = {}
RESPONSE_TLV_PAYLOAD_CODE   = {}
RESPONSE_TLV_RLOC_CODE      = {}

VERIFY_TLV_ID_CODE        = {}
VERIFY_TLV_PAYLOAD_CODE   = {}
VERIFY_TLV_RLOC_CODE      = {}



SEND_TLV_CONTROL_CODE = {"dstep":cetpOperations.send_ctrl_dstep,
                      "fqdn":cetpOperations.send_ctrl_fqdn,
                      "certificate":cetpOperations.send_ctrl_certificate,
                      "caep":cetpOperations.send_ctrl_caep,
                      "dp_rlocs":cetpOperations.send_ctrl_dp_rlocs,
                      "dp_ttl":cetpOperations.send_ctrl_dp_ttl,
                      "dp_keepalive_cycle":cetpOperations.send_ctrl_dp_keepalive_cycle,
                      "qos":cetpOperations.send_ctrl_qos,
                      "ack":cetpOperations.send_ctrl_ack,
                      "os_version":cetpOperations.send_ctrl_os_version,
                      "policy_caching":cetpOperations.send_ctrl_policy_caching,
                      "dp_proto":cetpOperations.send_ctrl_dp_proto,
                      "dp_port":cetpOperations.send_ctrl_dp_port,
                      "dp_ratelimit":cetpOperations.send_ctrl_dp_ratelimit,
                      "terminate":cetpOperations.send_ctrl_terminate,
                      "warning":cetpOperations.send_ctrl_warning
                      }


"""
"dp_proto", "dp_port", "dp_ratelimit" -- If provided, these informations can help oCES or iCES to filter the unwanted traffic towards the destination domain. 
                                        i.e. Traffic other than this port, protocol, or exceeding the ratelimit.        (Port, proto) can be redundant with use of SFQQDN.
                                        
dp_rloc, dp_ttl, dp_keepalive cycle, qos -- can be added to host policy by network admin.. Based on its SLA with the customer.
"""

SEND_TLV_CES_CODE =  {"cesid":cetpOperations.send_ces_cesid,
                      "ttl":cetpOperations.send_ces_ttl,
                      "certificate":cetpOperations.send_ces_certificate,
                      "keepalive":cetpOperations.send_ces_keepalive,
                      "keepalive_cycle":cetpOperations.send_ces_keepalive_cycle,
                      "fw_version":cetpOperations.send_fw_version,
                      "session_limit":cetpOperations.send_ces_session_limit,
                      "host_ratelimit":cetpOperations.send_ces_host_ratelimit,
                      "caces":cetpOperations.send_ces_caces,
                      "headersignature":cetpOperations.send_ces_headersignature,
                      "pow":cetpOperations.send_ces_pow,
                      "port_filtering":cetpOperations.send_ces_port_filtering,                      
                      "host_filtering":cetpOperations.send_ces_host_filtering,                      
                      "terminate":cetpOperations.send_ces_terminate,
                      "warning":cetpOperations.send_ctrl_warning
                      }

SEND_TLV_GROUP = {TLV_GROUP["id"]:SEND_TLV_ID_CODE,
                  TLV_GROUP["payload"]:SEND_TLV_PAYLOAD_CODE,
                  TLV_GROUP["rloc"]:SEND_TLV_RLOC_CODE,
                  TLV_GROUP["control"]:SEND_TLV_CONTROL_CODE,
                  TLV_GROUP["ces"]:SEND_TLV_CES_CODE
                  }


RESPONSE_TLV_CONTROl_CODE = {"dstep":cetpOperations.response_ctrl_dstep,
                      "fqdn":cetpOperations.response_ctrl_fqdn,
                      "certificate":cetpOperations.response_ctrl_certificate,
                      "caep":cetpOperations.response_ctrl_caep,
                      "dp_rlocs":cetpOperations.response_ctrl_dp_rlocs,
                      "dp_ttl":cetpOperations.response_ctrl_dp_ttl,
                      "dp_keepalive_cycle":cetpOperations.response_ctrl_dp_keepalive_cycle,
                      "qos":cetpOperations.response_ctrl_qos,
                      "ack":cetpOperations.response_ctrl_ack,
                      "os_version":cetpOperations.response_ctrl_os_version,
                      "policy_caching":cetpOperations.response_ctrl_policy_caching,
                      "dp_proto":cetpOperations.response_ctrl_dp_proto,
                      "dp_port":cetpOperations.response_ctrl_dp_port,
                      "dp_ratelimit":cetpOperations.response_ctrl_dp_ratelimit,
                      "terminate":cetpOperations.response_ctrl_terminate,
                      "warning":cetpOperations.response_ctrl_warning
                      }


RESPONSE_TLV_CES_CODE     = { "cesid":cetpOperations.response_ces_cesid,
                              "ttl":cetpOperations.response_ces_ttl,
                              "certificate":cetpOperations.response_ces_certificate,
                              "keepalive":cetpOperations.response_ces_keepalive,
                              "keepalive_cycle":cetpOperations.response_ces_keepalive_cycle,
                              "fw_version":cetpOperations.response_ces_fw_version,
                              "session_limit":cetpOperations.response_ces_session_limit,
                              "host_ratelimit":cetpOperations.response_ces_host_ratelimit,
                              "caces":cetpOperations.response_ces_caces,
                              "headersignature":cetpOperations.response_ces_headersignature,
                              "pow":cetpOperations.response_ces_pow,
                              }

RESPONSE_TLV_GROUP = {TLV_GROUP["id"]:RESPONSE_TLV_ID_CODE,
                   TLV_GROUP["payload"]:RESPONSE_TLV_PAYLOAD_CODE,
                   TLV_GROUP["rloc"]:RESPONSE_TLV_RLOC_CODE,
                   TLV_GROUP["control"]:RESPONSE_TLV_CONTROl_CODE,
                   TLV_GROUP['ces']:RESPONSE_TLV_CES_CODE }


VERIFY_TLV_CONTROl_CODE = {"dstep":cetpOperations.verify_ctrl_dstep,
                      "fqdn":cetpOperations.verify_ctrl_fqdn,
                      "certificate":cetpOperations.verify_ctrl_certificate,
                      "caep":cetpOperations.verify_ctrl_caep,
                      "dp_rlocs":cetpOperations.verify_ctrl_dp_rlocs,
                      "dp_ttl":cetpOperations.verify_ctrl_dp_ttl,
                      "dp_keepalive_cycle":cetpOperations.verify_ctrl_dp_keepalive_cycle,
                      "qos":cetpOperations.verify_ctrl_qos,
                      "ack":cetpOperations.verify_ctrl_ack,
                      "os_version":cetpOperations.verify_ctrl_os_version,
                      "policy_caching":cetpOperations.verify_ctrl_policy_caching,
                      "dp_proto":cetpOperations.verify_ctrl_dp_proto,
                      "dp_port":cetpOperations.verify_ctrl_dp_port,
                      "dp_ratelimit":cetpOperations.verify_ctrl_dp_ratelimit,
                      "terminate":cetpOperations.verify_ctrl_terminate,
                      "warning":cetpOperations.verify_ctrl_warning
                      }


VERIFY_TLV_CES_CODE     = { "cesid":cetpOperations.verify_ces_cesid,
                              "ttl":cetpOperations.verify_ces_ttl,
                              "certificate":cetpOperations.verify_ces_certificate,
                              "keepalive":cetpOperations.verify_ces_keepalive,
                              "keepalive_cycle":cetpOperations.verify_ces_keepalive_cycle,
                              "fw_version":cetpOperations.verify_ces_fw_version,
                              "session_limit":cetpOperations.verify_ces_session_limit,
                              "host_ratelimit":cetpOperations.verify_ces_host_ratelimit,
                              "caces":cetpOperations.verify_ces_caces,
                              "headersignature":cetpOperations.verify_ces_headersignature,
                              "pow":cetpOperations.verify_ces_pow,
                              }


VERIFY_TLV_GROUP = {TLV_GROUP["id"]:VERIFY_TLV_ID_CODE,
                   TLV_GROUP["payload"]:VERIFY_TLV_PAYLOAD_CODE,
                   TLV_GROUP["rloc"]:VERIFY_TLV_RLOC_CODE,
                   TLV_GROUP["control"]:VERIFY_TLV_CONTROl_CODE,
                   TLV_GROUP['ces']:VERIFY_TLV_CES_CODE }



LOGLEVEL_C2CTransaction = logging.INFO

class C2CTransaction(object):
    def __init__(self, name="C2CTransaction"):
        self.name       = name
        self._logger    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_C2CTransaction)

    def get_cetp_packet(self, sstag=None, dstag=None, req_tlvs=[], offer_tlvs=[], avail_tlvs=[]):
        """ Default CETP fields for signalling message """
        version         = 1
        cetp_header     = {}
        cetp_header['ver']          = version
        cetp_header['SST']          = sstag
        cetp_header['DST']          = dstag
        if len(req_tlvs):
            cetp_header['query']    = req_tlvs
        if len(offer_tlvs):
            cetp_header['info']     = offer_tlvs
        if len(avail_tlvs):
            cetp_header['response'] = avail_tlvs
        
        return cetp_header

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

    def _create_offer_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        if (group=="ces") and (code in CES_CODE_TO_POLICY):
            func = SEND_TLV_GROUP[group][code]
            tlv = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, query=False)
            return tlv
                    
    def _create_offer_tlv2(self, group=None, code=None):
        tlv ={}
        tlv['group'], tlv['code'] = group, code
        if (group=="ces") and (code in CES_CODE_TO_POLICY):
            func = SEND_TLV_GROUP[group][code]
            tlv = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, query=False)
            return tlv

    def _create_request_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        if (group=="ces") and (code in CES_CODE_TO_POLICY):
            func = SEND_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, query=True)
            return tlv
        
    def _create_request_tlv2(self, group=None, code=None):
        tlv = {}
        tlv['group'], tlv['code'] = group, code
        if (group=="ces") and (code in CES_CODE_TO_POLICY):
            func = SEND_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, query=True)
            return tlv
    
    def _create_response_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        if (group=="ces") and (code in CES_CODE_TO_POLICY):
            func = RESPONSE_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, ces_params=self.ces_params, l_cesid=self.l_cesid, r_cesid=self.r_cesid)
            return tlv
        
    def _verify_tlv(self, tlv):
        result = True
        group, code = tlv['group'], tlv['code']
        if (group=="ces") and (code in CES_CODE_TO_POLICY):
            func   = VERIFY_TLV_GROUP[group][code]
            result = func(tlv=tlv, code=code, ces_params=self.ces_params, l_cesid=self.l_cesid, r_cesid=self.r_cesid)
        return result


    def pprint(self, packet):
        self._logger.info("CETP Packet")
        for k, v in packet.items():
            if k not in ['query', 'info', 'response']:
                print(str(k)+": "+ str(v))
        
        for k in ['query', 'info', 'response']:
            if k in packet:
                print(k+":")
                tlvs = packet[k]
                for tlv in tlvs:
                    print('\t', tlv)
        print("\n")




LOGLEVEL_oC2CTransaction        = logging.INFO

class oC2CTransaction(C2CTransaction):
    """
    Expected outcome from class is to negotiate CES-to-CES transaction & to report status if CES-to-CES is negotiated.
    """
    def __init__(self, loop, l_cesid="", r_cesid="", c_sstag=0, c_dstag=0, cetp_state_mgr=None, policy_client=None, policy_mgr=None, proto="tls", ces_params=None, direction="outbound", name="oC2CTransaction"):
        self._loop              = loop
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.sstag              = c_sstag
        self.dstag              = c_dstag
        self.cetpstate_mgr      = cetp_state_mgr
        self.policy_client      = policy_client
        self.policy_mgr         = policy_mgr                            # Used in absence of the PolicyAgent to PolicyManagementSystem interaction.
        self.direction          = direction
        self.proto              = proto                                 # Protocol layer for CETPTransport
        self.ces_params         = ces_params
        
        self.name               = name
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oC2CTransaction)
        self.rtt                = 0
        self.cetp_negotiation_history   = []
        # possible to initiate the super class?
        

    def generate_session_tags(self, sstag):
        if sstag == 0:
            self.sstag = random.randint(0, 2**32)
            self.dstag = self.dstag
        else:
            self.sstag = sstag
            self.dstag = random.randint(0, 2**32)           # later on, add checks for conflicts with other (sstag, dstag)
    
    def load_policies(self, l_ceisd, proto, direction):
        """ Retrieves the policies stored in the Policy file"""
        self.ces_policy, self.ces_policy_tmp  = None, None
        self.ces_policy         = self.policy_mgr.get_ces_policy(proto=self.proto, direction=direction)
        self.ces_policy_tmp     = self.policy_mgr.get_ces_policy(proto=self.proto, direction=direction)

    def _initialize(self):
        """ Loads policies, generates session tags"""
        self.generate_session_tags(self.sstag)
        self.load_policies(self.l_cesid, self.proto, self.direction)

    def _pre_process(self, msg):
        return self.sanity_checking(msg) 
 
    def sanity_checking(self, msg):
        """ checks for minimum packet details & format compliance on an inbound packet """
        if len(self.ces_policy.required)==0:                
            self._logger.info(" Local CES has not defined any CES policy requirements -> mandatory to define CES policies (for example 'cesid')")
            return False
        return True


    def general_policy_group_codes(self):
        """
        cesid: cesa.demo.lte.
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

    def initiate_c2c_negotiation(self):
        """ Initiating CES policy offers and requirments towards destination """
        self._logger.info(" Starting CES-to-CES CETP session negotiation (SST={}, DST={}) towards {}".format(self.dstag, self.sstag, self.r_cesid))
        req_tlvs, offer_tlvs = [], []
        self._initialize()
        #self._logger.debug("Outbound policy: ", self.ces_policy.show2())
        # At this stage, ingress filtering is ensured?   - ensuring that only a valid host initiates the CES-to-CES transaction towards remote 'cesid'? 
        
        #print "The TLVs offered"
        for otlv in self.ces_policy.get_offer():
            self._create_offer_tlv(otlv)
            offer_tlvs.append(otlv)

        #print "The TLVs required"
        for rtlv in self.ces_policy.get_required():
            self._create_request_tlv(rtlv)
            req_tlvs.append(rtlv)
        
        #if len(tlv_to_send) == 0:
        #    self._logger.warning("No CES-to-CES policy is defined")                     # Pops up the warning, if no CES-to-CES policy is defined,

        # self.attach_cetp_signature(tlv_to_send)                                       # Signing the CETP header, if required by policy    - Depends on the type of transport layer.
        cetp_packet = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs, offer_tlvs=offer_tlvs)
        self.last_packet_send = cetp_packet
        self.cetpstate_mgr.add((self.sstag,0), self)
        self.start_time = time.time()
        self.pprint(cetp_packet)
        #self._log_tlvs(cetp_packet, "Sent TLV", "oCES")
        #self._logger.debug("cetp_msg: "+ cetp_msg)
        cetp_msg = json.dumps(cetp_packet)
        return cetp_msg

    def validate_signalling_rlocs(self, r_cesid):
        """ Shall store the remote-cesid in a list of trusted CES-IDs """
        pass

    def continue_c2c_negotiation(self, cetp_packet, transport):
        """ Continues CES-to-CES negotiation towards remote CES """
        self._logger.info(" Continuing CES-to-CES CETP negotiation (SST={}, DST={}) towards {}".format(self.dstag, self.sstag, self.r_cesid))
        #self._logger.info(" Outbound policy: ", self.ces_policy.show2())
        negotiation_status = None
        self.transport = transport
        
        self.packet = cetp_packet
        req_tlvs, offer_tlvs, ava_tlvs = [], [], []
        i_req, i_info, i_resp = [], [], []
        self.sstag, self.dstag = cetp_packet['DST'], cetp_packet['SST']
        self.rtt += 1
        error = False
        cetp_resp = ""

        if self.rtt>3:
            self._logger.error(" Failure: CES-to-CES negotiation exceeded {} RTTs".format(self.rtt))
            negotiation_status = False              # Prevents infinite loop of CETP negotiation
            return (negotiation_status, "")
        
        if not self._pre_process(cetp_packet):
            self._logger.error(" CETP packet failed pre_processing() in oCES")
            # How to deal this if a packet is missing fundamental details (src & destination cesid)? Negotiation failure, Drop or blacklist?
            negotiation_status = False
            return (negotiation_status, "")
        
        # Parsing the inbound packet
        if "query" in self.packet:      i_req = self.packet['query']
        if "info" in self.packet:       i_info = self.packet['info']
        if "response" in self.packet:   i_resp = self.packet['response']

        # oCES check whether the inbound CETP message is a request or response.    If request, send policy-response + sender-host Queries.
        # If Response message, verify that it is okay, and accept. Else send terminate-TLV, if iCES has completed (SST, DST)
        
        # Processing inbound packet
        if len(i_req):
            self._logger.debug(" Inbound packet has request TLVs -> 'Respond' the policy queries (+) Send sender-host queries")
            for tlv in i_req:
                if self.ces_policy_tmp.has_available(tlv):
                    ret_tlvs = self._create_response_tlv(tlv)
                    ava_tlvs.append(ret_tlvs)
                else:
                    self._logger.info(" TLV" + tlv['group']+"."+ tlv['code'] + " is not Available.")
                    if 'cmp' in tlv:
                        if tlv['cmp'] == "optional":
                            self._logger.info(" TLV" + tlv['group']+"."+ tlv['code'] + " is not mandatory requirement.")
                            self._get_unavailable_response(tlv)
                            ava_tlvs.append(tlv)
                    else:
                        negotiation_status = False                  # There is no need to send 'terminate' message to a stateless endpoint - Locally terminate the transaction
                        return (negotiation_status, cetp_resp)
                    
            for tlv in self.ces_policy_tmp.get_required():         # Issuing sender's policy requirements
                self._create_request_tlv(tlv)
                req_tlvs.append(tlv)

            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs, offer_tlvs=ava_tlvs, avail_tlvs=[])           # Sending the 'response' as 'info'
            self.last_packet_sent = cetp_message
            self.cetp_negotiation_history.append(cetp_message)
            self._logger.debug("self.rtt: ", self.rtt)
            negotiation_status = None
            self.pprint(cetp_message)
            cetp_packet = json.dumps(cetp_message)
            return (negotiation_status, cetp_packet)
        
        # Expectedly, A CETP message at this stage has policy responses. Such a CETP packet requires: policy match and verification of policy values. 
        # Inbound message can have: 1) Less than required TLVs; 2) TLVs with wrong value; 3) a notAvailable TLV; OR 4) a terminate TLV.
        # This should result in either C2C-negotiation: 1) success; OR 2) Failure -- (Leading to deletion of (oCSST, oCDST) state & an additional terminate-TLV towards iCES -- if iCES became Statefull due to previous message exchanges

        for tlv in i_resp:
            if (tlv['group'] == 'ces') and (tlv['code']=='terminate'):
                self._logger.info(" Terminate received for", tlv["group"], ".", tlv['code'], "with value: ", tlv['value'] )
                error = True
                break
            
            elif self.ces_policy_tmp.has_required(tlv):
                if self._verify_tlv(tlv):
                    self.ces_policy_tmp.del_required(tlv)
                else:
                    # There is need to handle 'notAvailable' TLV and absorbing if its not too stingently required
                    self._logger.info(" TLV", tlv['group'], ".", tlv['code'], "failed verification")         # handles TLV NotAvailable & TLV wrong value case
                    ava_tlvs =  []
                    ava_tlvs.append(self._get_terminate_tlv(err_tlv=tlv))
                    error=True
                    break


        if len(self.ces_policy_tmp.required)>0:
            self._logger.info(" Inbound packet didn't meet all the oCES policy requirements")
            self._logger.debug("A more LAX version may allow another negotiation round")
            error = True

        if error:
            self._logger.error(" CES-to-CES policy negotiation failed in {} RTT".format(self.rtt))
            self._logger.warning(" Execute DNS error callback on the pending h2h-transactions.")
            negotiation_status = False
            self.cetpstate_mgr.remove((self.sstag, 0))      # At this stage oCES tags are still: (SST, 0)
            if self.dstag==0:
                return (negotiation_status, "")             # Failure of C2C negotiation shall lead to DNS NXDOMAIN to all the queued H2H transactions
            else:
                # Return terminate packet to remote end, as it has completed the transaction
                self._logger.info(" Responding remote CES with the terminate-TLV")
                cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, offer_tlvs=ava_tlvs)        # Send as 'Info' TLV
                self.last_packet_sent = cetp_message
                self.cetp_negotiation_history.append(cetp_message)
                self.pprint(cetp_message)
                cetp_packet = json.dumps(cetp_message)
                return (negotiation_status, cetp_packet)
        else:
            self._logger.info(" CES-to-CES policy negotiation succeeded in {} RTT.. Continue H2H transactions".format(self.rtt))
            self._logger.info("{}".format(30*'#') )
            #self.validate_signalling_rlocs(r_cesid)                 # To encode
            self._cetp_established()
            negotiation_status = True
            return (negotiation_status, "")


    # In post-c2c negotiation there can be two kinda methods. 
    # One which are triggered by oCES towards remote CES on demand. Others, which must attend the cetp message from iCES.
    # Post-c2c negotiation is applicable to both 'outbound' and 'inbound' policies.
    
    # Other expected functionalities:
        # rate_limit_cetp_flows(), block_host(), ratelimit_host(), SLA_violated()
        # New_certificate_required(), ssl_renegotiation(), DNS_source_traceback()
    
    # For some policy parameters, CES shall have a default value if the C2C policy doesn't specify them.. To have cross compatibility across fields.
    #self._loop.call_later(self.kalive_timeout, self.send_keepalive)


    def initiate_keepalive(self):
        """ Initiates CES keepalive message towards remote CES """
        self._logger.info(" CES keepalive towards {} (SST={}, DST={})".format(self.r_cesid, self.dstag, self.sstag))
        req_tlvs = []
        tlv = self._create_request_tlv2(group="ces", code="keepalive")
        req_tlvs.append(tlv)
        
        cetp_packet = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs)
        self.trigger_time = time.time()
        #self.pprint(cetp_packet)
        cetp_msg = json.dumps(cetp_packet)
        self.transport.send_cetp(cetp_msg)
        self._loop.call_later(self.keepalive_cycle, self.initiate_keepalive)
        


    def post_c2c_negotiation(self, packet, transport):
        """ Initiates CES keepalive message towards remote CES """
        self._logger.info(" Post-C2C negotiation: CETP packet from CES {} (SST={}, DST={})".format(self.r_cesid, self.dstag, self.sstag))
        self.packet = packet
        self.transport = transport
        ava_tlvs = []

        i_req, i_info, i_resp = [], [], []
        status, error = False, False
        cetp_resp = ""

        # The initiate_keepalive message shall not be triggered, if CES policy doesn't offer or require the 'keepalive' support
        # For periodic sending of keepalive this method is executed in a loop.call_soon() or loop.call_at() -- Another method to execute penalties.
        
        if not self._pre_process(packet):
            self._logger.error(" CETP packet failed pre_processing() in oCES")
            # No idea, how _pre_processing shall be applied in post c2c-negotiation phase.
            status = False
            return (status, "")
        
        # Parsing the inbound packet
        if "query" in self.packet:      i_req = self.packet['query']
        if "info" in self.packet:       i_info = self.packet['info']
        if "response" in self.packet:   i_resp = self.packet['response']

        # Difference b/w negotiation in policy-negotiation & post-policy negotiation
        # Policy-negotiation: Query -> Response -> Verified -> (Accepted silently, or NotAcceptable), Info -> Verified -> (Accepted silently, or NotAcceptable)
        # Post policy-negotiation: Query -> Response -> Verify -> Accepted or Unsupported;      Info -> Might or might not respond -> Send response or unsupported TLV
        # Or it can be so that all policy elements from oCES to iCES are query: So that iCES either notes them or Acts/Responds them as (Accepted or Unsupported).
        # Second option seems much better
        
        # During policy negotiation, some policies must be provided right then and there.    
        # The others are required at later stage. How to differentiate this.    (How to enforce relation across the policy elements?)
        
        # Processing inbound packet
        if len(i_req):
            # This code shall be triggered in the requested CES, in post-c2c negotiation phase.
            self._logger.info(" Inbound packet has {} request TLVs".format(len(i_req)) + " -> Respond the policy queries")
            for tlv in i_req:
                if self.ces_policy.has_available(tlv):
                    ret_tlvs = self._create_response_tlv(tlv)
                    ava_tlvs.append(ret_tlvs)
                else:
                    self._logger.info(" TLV " + tlv['group']+"."+ tlv['code'] + " is not Available.")
                    self._get_unavailable_response(tlv)
                    ava_tlvs.append(tlv)
                    
                    if 'cmp' in tlv:
                        if tlv['cmp'] == "optional":
                            self._logger.info(" TLV" + tlv['group']+"."+ tlv['code'] + " is not mandatory requirement.")
        
        
        offer_tlvs = i_resp + i_info
        if len(offer_tlvs):
            # This code shall be triggered in the requesting CES, in the post-c2c negotiation phase.
            self._logger.debug(" Inbound packet has request TLVs -> 'Respond' the policy queries (+) Send sender-host queries")
            
            for tlv in offer_tlvs:
                if (tlv['group'] == 'ces') and (tlv['code']=='terminate'):
                    self._logger.info(" Terminate received for", tlv["group"], ".", tlv['code'], "with value: ", tlv['value'] )
                    # Could it mean to terminate the support for a particular TLV.
                    status = False                  
                    return (status, cetp_resp)
                
                elif self.ces_policy.has_required(tlv):
                    if self._verify_tlv(tlv):
                        self._logger.debug("TLV is verified -> TLV request has been processed/accepted by the remote CES.")
                        #self.last_packet.queries.satisfied(tlv)    # delete the satisfied query and know that its fulfilled
                    else:
                        self._logger.info("Either TLV failed verification or it is notSupported by remote CES")
                        # Should we even communication (with a CES) a TLV that is not supported? 
                        # If it is too important for us, and support is not available - This shall already fail in policy negotiation
                        # If it is a nice-to-have TLV from CES perspective, but the remote CES does not support it. CES shall never forward this TLV towards the remote CES.
                        self._logger.info(" TLV", tlv['group'], ".", tlv['code'], "failed verification")         # handles TLV wrong value case
                        #self.last_packet.queries.satisfied(tlv, False)    # Unsatisfied policy requirement
                        ava_tlvs =  []
                        #ava_tlvs.append(self._unexpected_payload_in_tlv(err_tlv=tlv))
                        break
        
        if len(ava_tlvs)!=0:
            cetp_packet = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, avail_tlvs=ava_tlvs)
            self.last_seen = time.time()
            #self.pprint(cetp_packet)
            cetp_msg = json.dumps(cetp_packet)
            transport.send_cetp(cetp_msg)


    def _cetp_established(self):
        # It can perhaps execute DNS callback as well
        self.cetpstate_mgr.remove((self.sstag, 0))
        self.cetpstate_mgr.add((self.sstag, self.dstag), self)
        
        # Checks if the support for keepalives is required, AND triggers the periodic execution of keepalives -> using loop.call_at() OR loop.call_later()
        # Objective: Keepalives shall not be triggered, if CES policy doesn't offer or require the 'keepalive' support
        
        for otlv in self.ces_policy.get_required():
            group, code = otlv['group'], otlv['code']
            if code == "keepalive":
                self._logger.info("Keepalive support is required.")
                self.keepalive_cycle = 5                                   # For now, but later on it shall be extracted from the CES policy configuration.
                self._loop.call_later(self.keepalive_cycle, self.initiate_keepalive)


    @asyncio.coroutine
    def get_policies_from_PolicySystem(self, r_hostid, r_cesid):    # Has to be a coroutine in asyncio - PolicyAgent
        yield from asyncio.sleep(0.2)
        #yield from self.policy_client.send(r_hostid, r_cesid)
        
    def get_cached_policy(self):
        pass


LOGLEVEL_iC2CTransaction        = logging.INFO

class iC2CTransaction(C2CTransaction):
    def __init__(self, loop, sstag=0, dstag=0, l_cesid="", r_cesid="", l_addr=(), r_addr=(), policy_mgr= None, policy_client=None, cetpstate_mgr= None, ces_params=None, proto="tcp", name="iC2CTransaction"):
        self._loop              = loop
        self.local_addr         = l_addr
        self.remote_addr        = r_addr
        self.policy_mgr         = policy_mgr                # This could be policy client in future use.
        self.cetpstate_mgr      = cetpstate_mgr
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.proto              = proto
        self.direction          = "inbound"
        self.ces_params         = ces_params
        
        self.name               = name
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iC2CTransaction)
        self.load_policies(self.l_cesid, proto, self.direction)
        
        
    def load_policies(self, l_ceisd, proto, direction):
        """ Retrieves the policies stored in the Policy file"""
        self.ices_policy, self.ices_policy_tmp  = None, None
        self.ices_policy        = self.policy_mgr.get_ces_policy(proto=self.proto, direction=direction)
        self.ices_policy_tmp    = self.policy_mgr.get_ces_policy(proto=self.proto, direction=direction)
        #self.ices_policy_tmp    = copy.deepcopy(self.ices_policy)
        #self.ices_policy_tmp    = self.ices_policy[:]
        
    def is_sender_blacklisted(self, r_cesid):
        """ Checks if the source-address was previously blacklisted due to attack conditions """
        pass

    def process_c2c_transaction(self, cetp_packet):
        """ Negotiating CES-to-CES policies with remote edge """
        """ Extract the remote CESID: 'self.r_cesid' """
        self._logger.info("{}".format(30*'#') )
        negotiation_status  = None
        cetp_response       = ""
        
        src_addr = self.remote_addr[0]
        r_cesid = ""                                                 # This can be only extracted upon decoding the CETP message. 
        if self.is_sender_blacklisted(r_cesid):                      # Remove, if the one after accept() call works fine.
            self._logger.info(" Drop: Sender {} is blacklisted.".format(r_cesid))
            negotiation_status = False
            return (negotiation_status, cetp_response)
        
        self.packet = cetp_packet
        req_tlvs, offer_tlvs, ava_tlvs, error_tlvs = [], [], [], []
        self.sstag, self.dstag = cetp_packet['DST'], cetp_packet['SST']
        error = False
        # iCETPTransport shall have a mechanism, where it checks that it has been 5 seconds since connection establishment, and c2c didn't complete. So, let's close the connecton with oCES.

        # Parsing the inbound packet
        if "query" in self.packet:      i_req = self.packet['query']
        if "info" in self.packet:       i_info = self.packet['info']
        if "response" in self.packet:   i_resp = self.packet['response']

        # Ideally: iCES first checks if its requirements are met... If not met, send full query. If met, then verify the offered/responded policies.. 
        # If verified, only then respond to the remote end's requirements.
        # Support for POW is missing .... + iCES shall allow both 1-RTT & 2-RTT CETP negotiations
        
        for tlv in i_info:                              
            if tlv["group"] == "ces" and tlv["code"]== "terminate":
                self._logger.info(" Terminate received for", tlv["group"], ".", tlv['code'], "with value: ", tlv['value'] )     # IMO, iCES will never receive terminate in stateless mode. Only stateful transaction can/should process the terminate.
                return (None, cetp_response)
             
            elif self.ices_policy_tmp.has_required(tlv):
                if self._verify_tlv(tlv):
                    self.ices_policy_tmp.del_required(tlv)
                else:
                    self._logger.info("TLV " + tlv['group']+ "."+ tlv['code'] + " failed verification")
                    terminate_tlv = self._get_terminate_tlv(err_tlv=tlv)
                    error_tlvs.append(terminate_tlv)
                    error = True
                    break
            else:
                self._logger.info("Unrecognized TLV is received:  " + tlv)
                # Return False, or Ignore    (in this case, for future extension sake??)

            
        if error:
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, avail_tlvs=error_tlvs)
            cetp_packet = json.dumps(cetp_message)
            negotiation_status = False
            return (negotiation_status, cetp_packet)                 # Future item:     Return value shall allow CETPLayering to distinguish (Failure due to policy mismatch from wrong value and hence blacklisting subsequent interactions) OR shall this be handled internally?
        
        if len(self.ices_policy_tmp.required)>0:
            self._logger.info(" {} of unsatisfied iCES requirements: ".format(len(self.ices_policy_tmp.get_required())) )
            self._logger.info(" Initiate full query")
            
            req_tlvs, offer_tlvs, ava_tlvs = [], [], []
            for rtlv in self.ices_policy.get_required():            # Generating Full Query message
                self._create_request_tlv(rtlv)
                req_tlvs.append(rtlv)
            
            negotiation_status = None
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs, offer_tlvs=offer_tlvs, avail_tlvs=ava_tlvs)
            self.pprint(cetp_message)
            cetp_packet = json.dumps(cetp_message)
            return (negotiation_status, cetp_packet)

        # At this stage, The sender's offer has met the iCES policy requirements & Offer has been verified as correct..  Now, we evaluate the sender's requirements.
        
        for tlv in i_req:                                            # Processing 'Req-TLVs'
            if self.ices_policy.has_available(tlv):
                self._create_response_tlv(tlv)
                ava_tlvs.append(tlv)
            else:
                self._logger.info("TLV "+ tlv['group']+ "."+ tlv['code']+ " is unavailable")
                self._get_unavailable_response(tlv)
                error_tlvs.append(tlv)
                error = True
                break
            
        if error:
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, avail_tlvs=error_tlvs)
            cetp_packet = json.dumps(cetp_message)
            negotiation_status = False
            return (negotiation_status, cetp_packet)                 # Future item:     Return value shall allow CETPLayering to distinguish (Failure due to policy mismatch from wrong value and hence blacklisting subsequent interactions) OR shall this be handled internally?
        
        
        #All the destination requirements are met -> Accept/Create CETP connection (i.e. by assigning 'SST') and Export to stateful (for post_establishment etc)
        self.sstag = random.randint(0, 2**32)
        self._logger.info("C2C-policy negotiation succeeded -> Create stateful transaction (SST={}, DST={})".format(self.sstag, self.dstag))
        self._logger.info("{}".format(30*'#') )
        stateful_transansaction = self._export_to_stateful()            # Not implemented yet
        self.cetpstate_mgr.add((self.sstag, self.dstag), stateful_transansaction)
        negotiation_status = True
        self.r_cesid = "cesa.demo.lte"                                  # Dummy value: For now, for testing    -- Needs to be extracted from inbound packet.
        
        cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs, offer_tlvs=offer_tlvs, avail_tlvs=ava_tlvs)
        self.pprint(cetp_message)
        self._logger.info("{}".format(30*'#') )
        cetp_packet = json.dumps(cetp_message)
        self.last_packet_sent = cetp_packet
        return (negotiation_status, cetp_packet)                              # The return value shall be: (status, cetp_message)
        

        # try: except clasues for error handling are missing entirely...

    def _export_to_stateful(self):
        new_transaction = oC2CTransaction(self._loop, l_cesid=self.l_cesid, c_sstag=self.sstag, c_dstag=self.dstag, policy_mgr= self.policy_mgr, cetp_state_mgr=self.cetpstate_mgr, ces_params=self.ces_params, r_cesid="", direction="inbound")
        # Create it this way so that we can reuse the existing variables from the Stateless Transaction
        new_transaction.load_policies(self.l_cesid, self.proto, direction="inbound")
        return new_transaction

    def report_host(self):
        pass
        # (or def enforce_ratelimits():)
        # These methods are invoked to report a misbehaving host to remote CES.

