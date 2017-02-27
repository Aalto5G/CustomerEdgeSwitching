#!/usr/bin/python3.5

import asyncio
import logging
import signal
import socket
import sys
import random
import time
import traceback
import cetpManager
import json
import copy

LOGLEVELCETP = logging.DEBUG

KEY_ONGOING     = 1
KEY_ESTABLISHED = 2

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
        

class PolicyManager(object):
    # Loads policies, and keeps policy elements as CETPTLV objects
    def __init__(self, policy_file=None):
        self._cespolicy                     = None         # asPolicyCETP
        self._hostpolicy                    = None         #_asPolicyCETP
        self.config_file = policy_file
        self.load_policies(self.config_file)
        self.assign_policy_to_host()
        
    def load_policies(self, config_file):
        try:
            f = open(config_file)
            self._config = json.load(f)
            self._cespolicy_lst = self._config["cespolicy"]
            self._hostpolicies_lst = self._config["hostpolicies"]
            self.load_CES_policy()
            self.load_host_policy()
        except Exception:
            return False
        
    def _get_ces_policy(self):
        return self._cespolicy

    def assign_policy_to_host(self):
        self.fqdn_to_policy = {}
        self.fqdn_to_policy['hosta1.demo.lte']   = 1
        self.fqdn_to_policy['hosta2.demo.lte']   = 1
        self.fqdn_to_policy['hosta3.demo.lte']   = 2
        self.fqdn_to_policy['hosta4.demo.lte']   = 0
        self.fqdn_to_policy['hostb1.demo.lte']   = 1
        self.fqdn_to_policy['hostb2.demo.lte']   = 2
        self.fqdn_to_policy['hostb3.demo.lte']   = 0
        self.fqdn_to_policy['hostb4.demo.lte']   = 1
        self.fqdn_to_policy['hostb5.demo.lte']   = 0
        self.fqdn_to_policy['hostb6.demo.lte']   = 1
        self.fqdn_to_policy['hostc1.demo.lte']   = 2
        self.fqdn_to_policy['hostc2.demo.lte']   = 0
        self.fqdn_to_policy['www.google.com']    = 1
        self.fqdn_to_policy['www.aalto.fi']      = 2
    
    def mapping_srcId_to_policy(self, host_id):
        """ Return policy corresponding to a source-id """
        if host_id in self.fqdn_to_policy:
            return self.fqdn_to_policy[host_id]
        else:
            print("No reachability policy exists for this host")
            print("Assgning a random policy for testing sake")
            return 1

    def _get_host_policies(self):
        return self._hostpolicies
    
    def get_ces_policy(self, proto="tcp", direction="outbound"):
        return self._cespolicy[proto][direction]

    def get_host_policy(self, index, direction):
        """ The search key for host-policy number 0 is 'policy-0' """
        key="hostpolicy-%d" %index
        return self._hostpolicies[key][direction]

    def _get_copy_host_policy(self, index, direction):
        key="hostpolicy-%d" %index
        policy = self._hostpolicies[key][direction]
        return copy.deepcopy(policy)

    def load_CES_policy(self):
        self._cespolicy = {}
        for policy_dict in self._cespolicy_lst:
            for transp, transport_policy in policy_dict.items():
                self._cespolicy[transp] = {}
            
                for dir_dict in transport_policy:
                    for direction, direction_policy in dir_dict.items():
                        self._cespolicy[transp][direction] = direction_policy

    def load_host_policy(self):
        self._hostpolicies = {}
        for pol_dict in self._hostpolicies_lst:
            for host_id, host_policy in pol_dict.items():
                self._hostpolicies[host_id] = {}
                for policy_direction, policy in host_policy.items():
                    self._hostpolicies[host_id][policy_direction] = PolicyCETP(policy)
                

class PolicyCETP(object):
    def __init__(self, policy):
        self.policy = policy
        self._initialize()
        
    def _initialize(self):
        if "request" in self.policy:
            self.required = self.policy["request"]
        if "offer" in self.policy:
            self.offer = self.policy["offer"]
        if "available" in self.policy:
            self.available = self.policy["available"]
        # setting value for CETP can be handled in CETP transaction module

    def get_tlv_details(self, tlv):
        cmp, ext, group, code = None, None, None, None
        if "group" in tlv:
            group=tlv["group"]
        if "code" in tlv:
            code = tlv["code"]
        if "cmp" in tlv:
            cmp= tlv["cmp"]
        return (cmp, ext, group, code)
    
    def has_required(self, tlv):
        cmp, ext, group, code = self.get_tlv_details(tlv)
        for pol in self.required:
            if (group in pol["group"]) and (code in pol["code"]):
                return True
        return False
    
    def del_required(self, tlv):
        cmp, ext, group, code = self.get_tlv_details(tlv)
        for pol in self.required:
            if (group in pol["group"]) and (code in pol["code"]):
                self.required.remove(pol)
    
    def has_available(self, tlv):
        cmp, ext, group, code = self.get_tlv_details(tlv)
        for pol in self.available:
            if (group in pol["group"]) and (code in pol["code"]):
                return True
        return False

    def del_available(self, tlv):
        cmp, ext, group, code = self.get_tlv_details(tlv)
        for pol in self.available:
            if (group in pol["group"]) and (code in pol["code"]):
                self.available.remove(pol)

    def get_required(self):
        return self.required
    
    def get_offer(self):
        return self.offer
    
    def get_available(self):
        return self.available                   # Store as CETPTLV field with additional possibility of value field

    def set_required(self, tlv):
        return tlv

    def set_offer(self, tlv):
        return tlv
    
    def set_available(self, tlv):
        return tlv
    
    def get_group_code(self, pol_vector):
        s=""
        for pol in pol_vector:
            if 'cmp' in pol:
                gp, code, cmp = pol['group'], pol['code'], pol['cmp']
                pol_rep = gp+"."+code+"."+cmp
            else:
                gp, code = pol['group'], pol['code']
                pol_rep = gp+"."+code
            s+= pol_rep + ", "
        return s
    
    def show_policy(self):
        str_policy =  "\n"
        for it in ['request', 'offer', 'available']:
            if it in self.policy:
                pol_vector = self.policy[it]
                s = self.get_group_code(pol_vector)
                str_policy += it+ ": " + s +"\n"
                
        return str_policy
    
    def __str__(self):
        return self.show_policy()

    def __repr__(self):
        return self.show_policy()
    
    
class CETPTransaction(object):
    def __init__(self):
        pass

    def get_cetp_packet(self, sstag=None, dstag=None, req_tlvs=[], offer_tlvs=[], avail_tlvs=[]):
        """ Default CETP fields for signalling message """
        version         = 1
        has_control     = 1
        has_payload     = 0
        header_len      = 0                            # initial value
        cetp_header     = {}
        cetp_header['ver']          = version
        cetp_header['Hdr_length']   = header_len
        cetp_header['has_control']  = has_control
        cetp_header['has_payload']  = has_payload
        cetp_header['SST']          = sstag
        cetp_header['DST']          = dstag
        if len(req_tlvs):
            cetp_header['query']    = req_tlvs
        if len(offer_tlvs):
            cetp_header['info']     = offer_tlvs
        if len(avail_tlvs):
            cetp_header['response'] = avail_tlvs
        
        cetp_header['Hdr_length'] = len(cetp_header)            # Must insert it correctly.
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
        print("\nCETP Packet")
        for k, v in packet.items():
            if k not in ['query', 'info', 'response']:
                print(k, " : ", v)
        
        for k in ['query', 'info', 'response']:
            if k in packet:
                print(k)
                tlvs = packet[k]
                for tlv in tlvs:
                    print('\t', tlv)
        print()
    
class CETPStateful(CETPTransaction):
    def __init__(self, sstag=0, dstag=0, dnsmsg=None, src_id="", local_addr=None, l_cesid=None, r_cesid="", dst_id="", remote_addr=None, name="CETP Stateful", policy_mgr= None, cetpstate_mgr=None):
        self.sstag, self.dstag  = sstag, dstag
        self.dnsmsg             = dnsmsg
        self.src_id             = src_id
        self.local_addr         = local_addr                # (src_ip, src_port)
        self.remote_addr        = remote_addr
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.dst_id             = dst_id
        self.name               = name
        self.policy_mgr         = policy_mgr

        self.rtt                = 0
        self.cetpstate_mgr      = cetpstate_mgr
        self.cetp_negotiation_history   = []
        self.load_policies(self.src_id)
        self.generate_tag(sstag)
        
    def load_policies(self, src_id):
        index = self.policy_mgr.mapping_srcId_to_policy(src_id)                # dest-fqdn to policy conversion
        direction = "outbound"
        self.ipolicy, self.ipolicy_tmp  = None, None
        self.opolicy, self.opolicy_tmp  = None, None

        self.opolicy        = self.policy_mgr._get_copy_host_policy(index, direction)
        self.opolicy_tmp    = self.policy_mgr._get_copy_host_policy(index, direction)
        self.ipolicy        = self.policy_mgr._get_copy_host_policy(index, "inbound")
        self.ipolicy_tmp    = self.policy_mgr._get_copy_host_policy(index, "inbound")
    
    def generate_tag(self, sstag):
        if sstag == 0:
            self.sstag = random.randint(0, 2**32)
            self.dstag = self.dstag
        else:
            self.sstag = sstag
            self.dstag = random.randint(0, 2**32)           # later on, add checks for conflicts with other (sstag, dstag)
            
    def _initiate_ces_security(self):
        pass
    
    def _continue_ces_security(self):
        pass
    
    def start_transaction(self):
        """ Offer + Request tlvs to iCES """
        self.req_tlvs, self.offer_tlvs, self.ava_tlvs = [], [], []
        dstep_tlv = self.append_dstep_info()
        self.offer_tlvs.append(dstep_tlv)        
        #print("self.opolicy: ", self.opolicy)
        
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
        self.cetpstate_mgr.add((self.sstag,0), self)                # State in Connection table
        return cetp_packet

    def append_dstep_info(self):
        dstep_tlv = {}
        dstep_tlv["group"], dstep_tlv["code"], dstep_tlv["value"] = "control", "dstep", self.dst_id 
        return dstep_tlv

    def continue_establishing(self, cetp_packet):
        req_tlvs, offer_tlvs, ava_tlvs = [], [], []
        self.sstag, self.dstag = self.sstag, cetp_packet['SST']                 # self.dstag is sender's SST
        error = False
        self.packet = cetp_packet
        print("Continue establishing connection (%d -> %d)" %(self.sstag, self.dstag))
        
        print("--------------------------------------")
        print("\nOutbound policy: ", self.opolicy)
        self.pprint(cetp_packet)
        print()
        
        if self.rtt>6:
            return False                            # Prevents infinite loop of CETP negotiation, Where remote end repeatedly sends only Requests-TLVs (or incomplete message??)

        # print("Host policy ", self.opolicy)
        if not self._pre_process():
            print("oCES failed pre_process() ")
            return None
        
        # Processing inbound packet
        if len(self.cetp_req):
            # Inbound packet has request TLVs               # Reply with 'response' vector for asked queries (+) Send sender host queries
            for tlv in self.cetp_req:
                if self.opolicy.has_available(tlv):
                    ret_tlvs = self._create_response_tlv(tlv)
                    ava_tlvs.append(ret_tlvs)
                else:
                    print("oCES has notAvailable TLV", tlv['group'],".", tlv['code'])
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
            #print("self.rtt: ", self.rtt)
            return cetp_packet

        # Expectedly CETP message only has CETP responses, which require 1) verification
        # 2) May carry TLV notAvailable message; 3) TLV with wrong value; 4) Missing TLVs (due to rogue CETP messages from other nodes??) exploiting CETP states??
        # Upon success or Failure (Execute processing and then relevant DNS callbacks)
        
        for tlv in self.cetp_resp:
            if (tlv['group'] == 'control') and (tlv['code']=='terminate'):
                print("Terminate received for", tlv["group"], ".", tlv['code'], "with value: ", tlv['value'] )
                error = True
                break
            elif self.opolicy.has_required(tlv):
                if self._verify_tlv(tlv):
                    self.opolicy_tmp.del_required(tlv)
                else:
                    print("TLV", tlv['group'], ".", tlv['code'], "failed verification")         # handles TLV NotAvailable & TLV wrong value case
                    ava_tlvs =  []
                    ava_tlvs.append(self._get_terminate_tlv(err_tlv=tlv))
                    error=True
                    break
        
        if self.rtt>5:
            error = True            # Preventing infinite loop of CETP negotiation

        if len(self.opolicy_tmp.required)>0:
            print("oCES requirements are not met")                      # Couldn't meet all the queries, terminate the connection.. A more LAX version may allow another negotiation round 
            error = True

        if error:
            print("CETP negotiation failed")
            if self.dstag==0:
                # Return false, and execute DNS failure callback
                return False
            else:
                # Return terminate packet to remote end, as it completed transaction
                print("Responding remote end with terminate-TLV")
                cetp_signaling = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, offer_tlvs=ava_tlvs)        # Send as 'Info' TLV
                cetp_packet = json.dumps(cetp_signaling)
                self.last_packet_sent = cetp_packet
                self.cetp_negotiation_history.append(cetp_packet)
                return cetp_packet
        else:                
            print("Negotiation succeeded.. Run the DNS callback")
            self._cetp_established(cetp_packet)
            return True


    def _pre_process(self):
        self.cetp_req, self.cetp_info, self.cetp_resp = [], [], []

        if "query" in self.packet:
            self.cetp_req = self.packet['query']
        if "info" in self.packet:
            self.cetp_info = self.packet['info']
        if "response" in self.packet:
            self.cetp_resp = self.packet['response']
            
        return True

    def _cetp_established(self, cetp_packet):
        # It can perhaps execute DNS callback as well
        self.dstag = cetp_packet['DST']
        self.cetpstate_mgr.remove((self.sstag, 0))
        self.cetpstate_mgr.add((self.sstag, self.dstag), self)

    def post_establishment(self, cetp_packet):
        pass


class CETPStateless(CETPTransaction):
    def __init__(self, packet, name="Stateless", local_addr=(), remote_addr=(), policy_mgr= None, cetpstate_mgr= None):
        self.name           = name
        self.local_addr     = local_addr
        self.remote_addr    = remote_addr
        self.policy_mgr     = policy_mgr
        self.cetpstate_mgr  = cetpstate_mgr
        self.packet         = packet

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
            print("Destination host is not available")
            return False
        
        print("self.dst_hostId", self.dst_hostId)
        self.load_policies(self.dst_hostId)
        if "query" in self.packet:
            self.cetp_req = self.packet['query']
        if "response" in self.packet:
            self.cetp_resp = self.packet['response']
            
        return True
        
            
    def get_tlv(self, recv_tlv_lst, group=None, code=None):
        for tlv in recv_tlv_lst:
            if (tlv['group']==group) and (tlv['code'] == code):
                return tlv
        return None
    
    def start_transaction(self):
        """ Processing inbound packet vs destination policies """
        req_tlvs, offer_tlvs, ava_tlvs, error_tlvs = [], [], [], []
        error = False
        cetp_packet   = self.packet
        i_cetp_sstag  = self.packet['SST']
        o_cetp_sstag  = 0

        if not self._pre_process():
            print ("Inbound CETP packet failed CETP processing")
            return None
        
        #print("self.cetp_req: ", self.cetp_req)
        #print("self.cetp_ava: ", self.cetp_info)
        print("--------------------------------------")
        print("\nInbound policy: ", self.ipolicy)
        self.pprint(self.packet)

        
        # Processing inbound packet
        for tlv in self.cetp_info:                              # Processing 'info-TLVs'            #Can an attacker with Random TLV order disrupt this??
            if tlv["group"] == "control" and tlv["code"]== "terminate":
                print("Terminate received for", tlv["group"], ".", tlv['code'], "with value: ", tlv['value'] )
                error = True
                break
            elif self.ipolicy.has_required(tlv):
                if self._verify_tlv(tlv):
                    self.ipolicy_tmp.del_required(tlv)
                else:
                    print("TLV", tlv['group'], ".", tlv['code'], "failed verification")
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
                print("TLV", tlv['group'], ".", tlv['code'], "is unavailable")
                self._get_unavailable_response(tlv)
                ava_tlvs.append(tlv)
                #error = True

        if len(self.ipolicy_tmp.required)>0:
            print("# of iCES requirements not satisfied: ", len(self.ipolicy_tmp.get_required()))
            print("Initiate full query")
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
            stateful_transansaction = self._export_to_stateful()
            self.cetpstate_mgr.add((o_cetp_sstag, i_cetp_sstag), stateful_transansaction)
        
        cetp_signaling = self.get_cetp_packet(sstag=o_cetp_sstag, dstag=i_cetp_sstag, req_tlvs=req_tlvs, offer_tlvs=offer_tlvs, avail_tlvs=ava_tlvs)
        #self.pprint(cetp_signaling)
        cetp_packet = json.dumps(cetp_signaling)
        self.last_packet_sent = cetp_packet
        return cetp_packet

    def _create_response_tlv(self, tlv):
        tlv['value'] = "Some value"
        return tlv

    def dst_hostId_is_valid(self, host):
        """ Emulates that host exists behind CES """
        return True

    def _export_to_stateful(self):
        new_transaction = CETPStateful(sstag=self.sstag, dstag=self.dstag, local_addr=self.local_addr, remote_addr=self.remote_addr, policy_mgr= self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr, r_cesid="", src_id="", dst_id="")
        #Create it this way so that we can reuse the existing variables from the Stateless Transaction
        new_transaction.ipolicy = self.ipolicy
        new_transaction.opolicy = self.opolicy
        new_transaction.ipolicy_tmp = []            # Already met
        new_transaction.opolicy_tmp = []
        return new_transaction
    
