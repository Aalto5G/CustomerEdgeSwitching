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
DEFAULT_STATE_TIMEOUT           = 31



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
        if (group!="control") or ((group=="control") and (code in CETP.CONTROL_CODES)):
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv = func(tlv=tlv, code=code, cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, query=False)
        return tlv

    def _create_offer_tlv2(self, group=None, code=None):
        tlv ={}
        tlv['group'], tlv['code'], tlv["value"] = group, code, ""
        if group=="ces":
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv = func(tlv=tlv, code=code, cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, query=False)
        return tlv

    def _create_request_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        print(self.policy)
        if (group!="control") or ((group=="control") and (code in CETP.CONTROL_CODES)):
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, query=True)
            return tlv

    def _create_request_tlv2(self, group=None, code=None):
        tlv = {}
        tlv['group'], tlv['code'] = group, code
        if (group!="control") or ((group=="control") and (code in CETP.CONTROL_CODES)):
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy, query=True)
            return tlv
    
    def _create_response_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        tlv['ope'] = "response"
        #tlv["value"] = "some-value"
        if (group!="control") or ((group=="control") and (code in CETP.CONTROL_CODES)):
            func = CETP.RESPONSE_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, l_cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy)
            return tlv

    def _verify_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        if (group!="control") or ((group=="control") and (code in CETP.CONTROL_CODES)):
            func   = CETP.VERIFY_TLV_GROUP[group][code]
            result = func(tlv=tlv, code=code, l_cesid=self.l_cesid, r_cesid=self.r_cesid, policy=self.policy)
            return result

    def generate_session_tags(self, dstag=0):
        """ Returns a session-tag of 4-byte length, if sstag is not part of an connecting or ongoing transaction """
        while True:
            sstag = random.randint(0, 2**32)
            if dstag ==0:
                # For oCES, it checks the connecting transactions
                if not self.cetpstate_mgr.has_initiated_transaction((sstag, 0)):
                    return sstag
            
            elif dstag:
                self._logger.info("iCES is requesting source session tag")
                """ iCES checks if upon assigning 'sstag' the resulting (SST, DST) pair will lead to a unique transaction. """
                if not self.cetpstate_mgr.has_established_transaction((sstag, dstag)):                   # Checks connected transactions
                    return sstag
    

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



class H2HTransactionOutbound(H2HTransaction):
    def __init__(self, loop=None, sstag=0, dstag=0, cb_args=None, host_ip="", src_id="", dst_id="", l_cesid="", r_cesid="", policy_mgr= None, \
                 cetpstate_mgr=None, dns_callback=None, cetp_cleint=None, ces_params=None, direction="outbound", name="H2HTransactionOutbound"):
        self.sstag, self.dstag  = sstag, dstag
        self.cb_args            = cb_args
        self.host_ip            = host_ip                   # IP of the sender host
        self.src_id             = src_id                    # FQDN
        self.dst_id             = dst_id
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.policy_mgr         = policy_mgr
        self.cetpstate_mgr      = cetpstate_mgr
        self.dns_cb             = dns_callback              # Function to execute DNS response
        self._loop              = loop
        self.cetp_client        = cetp_cleint
        self.ces_params         = ces_params
        self.direction          = direction
        self.rtt                = 0
        self.name               = name
        self._logger            = logging.getLogger(name)
        self.start_time         = time.time()
        self._logger.setLevel(LOGLEVEL_H2HTransactionOutbound)
        self.h2h_negotiation_status = False
        self.cetp_negotiation_history   = []

    def handle_h2h(self):
        if not self.h2h_negotiation_status:
            self._logger.info(" Incomplete H2H-state towards '{}' expired".format(self.dst_id))
            self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))
            self.cetp_client.update_H2H_transaction_count(initiated=False)
    
    def load_policies(self, l_cesid, r_cesid, src_id, dst_id):
        """ Selection of host policy """
        index = self.policy_mgr.mapping_srcId_to_policy(src_id)                # Choosing policy for sender's (identity)
        src_id = "son1.raimo.aalto.lte"
        self.opolicy, self.opolicy_tmp  = None, None
        self.opolicy        = self.policy_mgr.get_host_policy(self.direction, host_id=src_id)
        self.opolicy_tmp    = self.policy_mgr.get_host_policy(self.direction, host_id=src_id)
        self.ipolicy        = self.policy_mgr.get_host_policy("inbound", host_id=src_id)
        self.ipolicy_tmp    = self.policy_mgr.get_host_policy("inbound", host_id=src_id)
        self.policy         = self.opolicy
        
    def _initialize(self):
        """ Loads policies, generates session tags, and initiates event handlers """
        try:
            self.sstag = self.generate_session_tags()
            self.load_policies(self.l_cesid, self.r_cesid, self.src_id, self.dst_id)
            self.state_timeout = DEFAULT_STATE_TIMEOUT
            if 'state_timeout' in self.ces_params:
                self.state_timeout   = self.ces_params['state_timeout']
        
            # Handler to unregister the incomplete CETP-C2C transaction
            self.h2h_handler = self._loop.call_later(self.state_timeout, self.handle_h2h)
            return True
        
        except Exception as msg:
            self._logger.info(" Exception in initiating the H2H session: {}".format(msg))
            return False
    
    def send_cetp(self, cetp_packet):
        self.cetp_client.send(cetp_packet)
    
    @asyncio.coroutine
    def start_cetp_processing(self):
        """ Returns CETP message containing Policy Offers & Request towards remote-host """
        #try:
        if not self._initialize():
            self._logger.debug(" Failure in initiating the CES-to-CES session.")
            return None
        
        self._logger.info(" Starting H2H session towards '{}' (SST= {} -> DST={})".format(self.dst_id, self.sstag, self.dstag))
        self.req_tlvs, self.offer_tlvs, self.ava_tlvs = [], [], []
        dstep_tlv = self.append_dstep_info()
        self.offer_tlvs.append(dstep_tlv)
        self._logger.info("outbound policy: {}".format(self.opolicy))
        #print("self.opolicy: ", self.opolicy)

        # Check if sender supports the id_type as of the destination-id, otherwise maybe not even initiate a transaction? or initiate with a default ID-type?
        # And regardless of id_type being used, FQDN of host shall be made part of the messages exchanged?
        
        # Offered TLVs
        for otlv in self.opolicy.get_offer():
            tlv = self._create_offer_tlv(otlv)
            self.offer_tlvs.append(tlv)
            
        # Required TLVs
        for rtlv in self.opolicy.get_required():
            tlv = self._create_request_tlv(rtlv)
            self.req_tlvs.append(tlv)
        
        cetp_msg = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=self.req_tlvs, offer_tlvs=self.offer_tlvs, avail_tlvs=self.ava_tlvs)
        cetp_packet = json.dumps(cetp_msg)
        self.pprint(cetp_msg)
        self.last_packet_sent = cetp_packet
        self.cetp_negotiation_history.append(cetp_packet)
        self.cetpstate_mgr.add_initiated_transaction((self.sstag,0), self)                # Registering the H2H state
        self.cetp_client.update_H2H_transaction_count()
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
            ver, sstag, dstag = cetp_msg['VER'], cetp_msg['SST'], cetp_msg['DST']
            if ver!=1:
                self._logger.error(" CETP Version is not supported.")
                return False
        except:
            self._logger.error(" Pre-processing the CETP packet failed.")
            return False
        return True

    def parse_inbound_packet(self, cetp_msg):
        """ Temporary function - to parse the inbound packet into Request/Response/Offer vectors """
        self.cetp_req, self.cetp_info, self.cetp_resp = [], [], []
        if "query" in self.packet:
            self.cetp_req   = self.packet['query']
        if "info" in self.packet:
            self.cetp_info  = self.packet['info']
        if "response" in self.packet:
            self.cetp_resp  = self.packet['response']

   
    def continue_cetp_processing(self, cetp_packet, transport):
        #try: 
        req_tlvs, offer_tlvs, ava_tlvs = [], [], []
        self.sstag, self.dstag = cetp_packet['DST'], cetp_packet['SST']                 # Sender's SST is DST for CES
        self.packet = cetp_packet
        self._logger.info("Continue establishing H2H session towards '{}' ({} -> {})".format(self.dst_id, self.sstag, 0))
        #self._logger.info("Host policy ", self.opolicy)
        error = False

        if not self._pre_process(cetp_packet):
            self._logger.info(" Failed in pre_processing the inbound packet.")
            return None
        
        # Parsing the CETP packet
        self.parse_inbound_packet(cetp_packet)
        self.rtt += 1
        
        if self.rtt > NEGOTIATION_RTT_THRESHOLD:                                        # Prevents infinite-exchange of CETP policies.
            self.cetpstate_mgr.remove_initiated_transaction((self.sstag, self.dstag))
            return False
        
        """
        Processing logic:
            oCES checks whether the inbound CETP message is a request or response message.
            - If its a request message, send response & issue local sender's policy queries.
            - If its a response message, it verifies.     If verified, it Accepts. Otherwise, it sends terminate-TLV, if iCES has already completed (SST, DST).
        """
        
        # Processing inbound packet
        if len(self.cetp_req):
            self._logger.debug(" Respond the inbound host queries && issue sender-host queries")
            for tlv in self.cetp_req:
                if self.opolicy.has_available(tlv):
                    ret_tlv = self._create_response_tlv(tlv)
                    ava_tlvs.append(ret_tlv)
                else:
                    self._logger.info(" TLV {}.{} is notAvailable".format(tlv['group'], tlv['code']))
                    if 'cmp' in tlv:
                        if tlv['cmp'] == "optional":
                            self._logger.info(" TLV {}.{} is not a mandatory requirement.".format(tlv['group'], tlv['code']))
                            self._get_unavailable_response(tlv)
                            ava_tlvs.append(tlv)
                        else: 
                            error= True
                            break
                    else:
                        error = True
                        break
                    
            if error:
                # Locally terminate session, as iCES is stateless
                self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))
                self._execute_dns_callback(resolution=False)
                return False
    
            # Issuing sender's policy requirements
            for rtlv in self.opolicy.get_required():
                tlv = self._create_request_tlv(rtlv)
                req_tlvs.append(tlv)
                
            ava_tlvs.append(self.append_dstep_info())
            cetp_msg = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs, offer_tlvs=ava_tlvs, avail_tlvs=[])           # Sending 'response' as 'info'
            self.last_packet_sent = cetp_msg
            self.last_packet_received = self.packet
            self.cetp_negotiation_history.append(cetp_msg)
            self.pprint(cetp_msg)
            cetp_packet = json.dumps(cetp_msg)
            self.send_cetp(cetp_packet)
            return None
    
        """
        Processing logic:
            A CETP message at this stage has policy responses, and shall be processed for: Matching and Verifying the policy elements. 
            - Inbound message can have: 1) Less than required TLVs; 2) TLVs with wrong value; 3) a notAvailable TLV; OR 4) a terminate TLV.
            - This should result in either C2C-negotiation: 1) success; OR 2) Failure -- (Leading to deletion of (oCSST, oCDST) state & an additional terminate-TLV towards iCES -- if iCES became Statefull due to previous message exchanges
        """
        
        for tlv in self.cetp_resp:
            if (tlv['group'] == 'control') and (tlv['code']=='terminate'):
                self._logger.info(" Terminate-TLV received with value: {}".format(tlv['value']) )
                error = True
                break
            
            elif self.opolicy_tmp.has_required(tlv):
                if self._verify_tlv(tlv):
                    self.opolicy_tmp.del_required(tlv)
                else:
                    self.opolicy_tmp.is_mandatory_required(tlv)
                    # Absorbs failure in case of 'optional' required policy TLV
                    if not self.opolicy_tmp.is_mandatory_required(tlv):
                        self.opolicy_tmp.del_required(tlv)
                        continue
                    self._logger.info(" TLV {}.{} failed verification".format(tlv['group'], tlv['code']))
                    ava_tlvs =  []
                    ava_tlvs.append(self._get_terminate_tlv(err_tlv=tlv))
                    error=True
                    break

        if len(self.opolicy_tmp.required)>0:
            self._logger.info(" Inbound packet didn't meet all the policy requirements of sender-host")
            self._logger.debug("A more LAX version may allow another negotiation round")
            error = True

        if error:
            self._logger.warning(" H2H policy negotiation failed in {} RTT".format(self.rtt))
            self.cetp_client.update_H2H_transaction_count(initiated=False)
            self.h2h_handler.cancel()
            self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))                                        # Since transaction didn't completed at oCES.
            self._execute_dns_callback(resolution=False)

            if self.dstag==0:
                return False
            else:
                # Return terminate packet to remote end, as it has completed the transaction
                self._logger.info(" Responding remote CES with the terminate-TLV")
                cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, offer_tlvs=ava_tlvs)        # Send as 'Info' TLV
                self.last_packet_sent = cetp_message
                self.cetp_negotiation_history.append(cetp_message)
                self.pprint(cetp_message)
                cetp_packet = json.dumps(cetp_message)
                self.send_cetp(cetp_packet)
                return False
        else:
            self._logger.info(" H2H policy negotiation succeeded in {} RTT".format(self.rtt))
            if not self._cetp_established(cetp_packet):
                return False
            
            self.h2h_negotiation_status = True
            self._logger.info("{}".format(42*'*') )
            return True

        #except Exception as msg:
        #    self._logger.info(" Exception in negotiating CETP-H2H session: {}".format(msg))
        #    return (None, "")


    def _cetp_established(self, cetp_packet):
        """ 
        1) Executes DNS callback,    2) Replaces initiated transaction with an established transaction
        3) Checks whether DST assigned by iCES has resulted in an (SST, DST) pair which is unique at oCES. If not, it sends a terminate to iCES.
        """
        self.cetp_client.update_H2H_transaction_count(initiated=False)                            # To reduce number of ongoing transactions.
        self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))
        
        #Checks whether (SST, DST) pair is locally unique.
        if self.cetpstate_mgr.has_established_transaction((self.sstag, self.dstag)):
            self._logger.warning(" Terminating transaction as ({},{}) pair is not unique in CES".format(self.sstag, self.dstag))
            self.terminate_transaction()
            return False
        
        self.cetpstate_mgr.add_established_transaction((self.sstag, self.dstag), self)
        self._execute_dns_callback()
        #self.create_transaction_in_dp()
        
    def _execute_dns_callback(self, resolution=True):
        self._logger.debug(" Executing DNS callback")
        dns_q, addr = self.cb_args
        self.dns_cb(dns_q, addr, success=resolution)

    def terminate_transaction(self):
        """ Sends a terminate TLV and closes the connected transport """
        tlv = self._create_offer_tlv2(group="control", code="terminate")
        terminate_tlv = [tlv]
        cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, offer_tlvs=terminate_tlv)
        cetp_packet = json.dumps(cetp_message)
        self.send_cetp(cetp_packet)
        self._execute_dns_callback(resolution=False)

    def create_transaction_in_dp(self, cetp_msg):
        #self.create_dataplane_entry(sst, dst, info)
        pass
    
    @asyncio.coroutine
    def get_policies_from_PolicySystem(self, r_hostid, r_cesid):        # Has to be a coroutine in asyncio - PolicyAgent
        #yield from self.policy_client.send(r_hostid, r_cesid)
        pass

    def post_h2h_negotiation(self, cetp_packet, transport):
        """ Processes a CETP packet received on a negotiated H2H session.    
            Could contain signal for 'terminating' the established session (Or changing Ratelimit of dataplane connection)
        """
        self._logger.info(" Post-H2H negotiation packet on (SST={}, DST={})".format(self.sstag, self.dstag))
        self.packet = cetp_packet
        i_req, i_info, i_resp, ava_tlvs = [], [], [], []
        
        # Parsing the inbound packet
        if "query" in self.packet:      i_req = self.packet['query']
        if "info" in self.packet:       i_info = self.packet['info']
        if "response" in self.packet:   i_resp = self.packet['response']

        #Processing inbound packet's responses
        offer_tlvs = i_resp + i_info                                            # TBD: Merge to one  -- Better to use 'info'
        if len(offer_tlvs):
            self._logger.debug(" Inbound packet contains Info/responses")
            for tlv in offer_tlvs:
                if (tlv['group'] == 'control') and (tlv['code']=='terminate'):
                    self._logger.info(" Terminate received with value: {}".format(tlv['value']) )
                    self.cetpstate_mgr.remove_established_transaction((self.sstag, self.dstag))
                    self._logger.warning(" H2H Session ({}->{}) terminated.".format(self.sstag, self.dstag))
                


class H2HTransactionInbound(H2HTransaction):
    def __init__(self, sstag=0, dstag=0, l_cesid="", r_cesid="", policy_mgr= None, cetpstate_mgr= None, name="H2HTransactionInbound"):
        self.sstag              = sstag
        self.dstag              = dstag
        self.l_cesid            = l_cesid
        self.r_cesid            = r_cesid
        self.policy_mgr         = policy_mgr                # This could be policy client in future use.
        self.cetpstate_mgr      = cetpstate_mgr
        self.direction          = "inbound"
        self.name               = name
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HTransactionInbound)

    def load_policies(self, host_id):
        index = self.policy_mgr.mapping_srcId_to_policy(host_id)
        self.ipolicy, self.ipolicy_tmp  = None, None
        self.opolicy, self.opolicy_tmp  = None, None
        dst_id = "raimo2.aalto.lte"
        self.ipolicy        = self.policy_mgr.get_host_policy(self.direction, host_id=dst_id)
        self.ipolicy_tmp    = self.policy_mgr.get_host_policy(self.direction, host_id=dst_id)
        self.opolicy        = self.policy_mgr.get_host_policy("outbound", host_id=dst_id)
        self.opolicy_tmp    = self.policy_mgr.get_host_policy("outbound", host_id=dst_id)
        self.policy         = self.ipolicy
    
    def _pre_process(self, cetp_packet):
        """ Pre-process the inbound packet for the minimum necessary details. """
        try:
            ver, sstag, dstag = cetp_packet['VER'], cetp_packet['SST'], cetp_packet['DST']
            if ver!=1:
                self._logger.error(" CETP Version is not supported.")
                return False

            if "info" in cetp_packet:       
                i_info = cetp_packet['info']
            
            destep_tlv = self.get_tlv(i_info, group='control', code='dstep')
            if destep_tlv == None:
                return False

            self.dst_hostId = destep_tlv['value']
            if (len(self.dst_hostId)<=0) or (len(self.dst_hostId)>256):             # Max length of FQDN = 256
                return False
            
            if not self.dst_hostId_is_valid(self.dst_hostId):
                self._logger.info(" Destination host/service is not served by CES.")
                return False
            
            self.load_policies(self.dst_hostId)
            return True
        
        except Exception as msg:
            self._logger.error(" Pre-processing the CETP packet failed: {}".format(msg))
            return False

    
    def get_tlv(self, recv_tlv_lst, group=None, code=None):
        for tlv in recv_tlv_lst:
            if (tlv['group']==group) and (tlv['code'] == code):
                return tlv
        return None

    def start_cetp_processing(self, cetp_packet, transport):
        """ Processes the inbound CETP-packet for negotiating the H2H policies """
        #try:
        self._logger.info("{}".format(42*'*') )
        self._logger.info("Inbound packet: ")
        self.pprint(cetp_packet)
        negotiation_status  = None
        cetp_response       = ""
        error               = False
        self.packet         = cetp_packet
        
        req_tlvs, offer_tlvs, ava_tlvs, error_tlvs = [], [], [], []
        self.sstag, self.dstag = cetp_packet['DST'], cetp_packet['SST']
        #src_addr = self.remote_addr[0]

        if not self._pre_process(cetp_packet):
            self._logger.debug("Inbound packet failed the pre-processing()")
            return False
        
        # Parsing the inbound packet
        if "query" in self.packet:      i_req = self.packet['query']
        if "info" in self.packet:       i_info = self.packet['info']
        if "response" in self.packet:   i_resp = self.packet['response']
    
        for tlv in i_info:
            if tlv["group"] == "control" and tlv["code"]== "terminate":
                self._logger.info(" Terminate received: {}".format(tlv['value']) )                     # In stateless mode, iCES shall not receive terminate TLV.
                return None
             
            elif self.ipolicy_tmp.has_required(tlv):
                if self._verify_tlv(tlv):
                    self.ipolicy_tmp.del_required(tlv)
                else:
                    self._logger.info("TLV {}.{} failed verification".format(tlv['group'], tlv['code']))
                    terminate_tlv = self._get_terminate_tlv(err_tlv=tlv)
                    error_tlvs.append(terminate_tlv)
                    error = True
                    break
            else:
                self._logger.debug("Non-requested TLV {} is received: ".format(tlv))

        if error:
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, avail_tlvs=error_tlvs)
            self.pprint(cetp_message)
            cetp_packet = json.dumps(cetp_message)
            transport.send_cetp(cetp_packet)
            return False
            # Future item:     Return value shall allow CETPLayering to distinguish (Failure due to policy mismatch from wrong value and hence blacklisting subsequent interactions) OR shall this be handled internally?
        
        if len(self.ipolicy_tmp.required)>0:
            self._logger.info(" {} of unsatisfied iCES requirements: ".format(len(self.ipolicy_tmp.get_required())) )
            self._logger.info(" Initiate full query")
            
            req_tlvs, offer_tlvs, ava_tlvs = [], [], []
            for rtlv in self.ipolicy.get_required():            # Generating Full Query message
                tlv = self._create_request_tlv(rtlv)
                req_tlvs.append(tlv)
            
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs)
            self.pprint(cetp_message)
            cetp_packet = json.dumps(cetp_message)
            transport.send_cetp(cetp_packet)
            return None
        
        # At this stage, the sender's offer has met the iCES policy requirements && the Offer has been verified..  Now, we evaluate the sender's requirements.        
        for tlv in i_req:                                            # Processing 'Req-TLVs'
            if self.ipolicy.has_available(tlv):
                self._create_response_tlv(tlv)
                ava_tlvs.append(tlv)
            else:
                self._logger.info("TLV {}.{} is unavailable".format(tlv['group'], tlv['code']))
                if 'cmp' in tlv:
                    if tlv['cmp'] == "optional":
                        self._logger.info(" TLV {}.{} is not a mandatory requirement.".format(tlv['group'], tlv['code']))
                        self._get_unavailable_response(tlv)
                        ava_tlvs.append(tlv)
                    else: 
                        error= True
                        break
                else:
                    error = True
                    break
        
        if error:
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, avail_tlvs=ava_tlvs)
            cetp_packet = json.dumps(cetp_message)
            self.pprint(cetp_message)
            transport.send_cetp(cetp_packet)
            return False
        
        #All the  requirements of remote-CES are also met -> Now Accept/Create CETP connection (i.e. by assigning 'SST') and Export to stateful (for post-negotiation CETP flow etc.)
        self.sstag = self.generate_session_tags(self.dstag)
        self._logger.info("H2H-policy negotiation succeeded -> Create transaction (SST={}, DST={})".format(self.sstag, self.dstag))
        self._logger.info("{}".format(42*'*') )
        stateful_transansaction = self._export_to_stateful()
        
        cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, avail_tlvs=ava_tlvs)
        self.pprint(cetp_message)
        self._logger.info("{}".format(42*'*') )
        cetp_packet = json.dumps(cetp_message)
        self.last_packet_sent = cetp_packet
        transport.send_cetp(cetp_packet)
        return True
    
        #except Exception as msg:
        #    self._logger.info("Exception: {}".format(msg))
        #    return (None, "")
            

    def dst_hostId_is_valid(self, host):
        """ Emulates that host exists behind CES """
        return True

    def _export_to_stateful(self):
        new_transaction = H2HTransactionOutbound(sstag=self.sstag, dstag=self.dstag, policy_mgr= self.policy_mgr, cetpstate_mgr=self.cetpstate_mgr,  \
                                                 l_cesid=self.l_cesid, r_cesid=self.r_cesid, direction="inbound", src_id="", dst_id="")
        new_transaction.opolicy     = self.ipolicy
        new_transaction.opolicy_tmp = self.ipolicy_tmp
        self.cetpstate_mgr.add_established_transaction((self.sstag, self.dstag), new_transaction)
        return new_transaction
    

    def create_transaction_in_dp(self):
        self.create_dataplane_entry(sst, dst, info)

    @asyncio.coroutine
    def get_policies_from_PolicySystem(self, r_hostid, r_cesid):
        yield from self.policy_client.send(r_hostid, r_cesid)

