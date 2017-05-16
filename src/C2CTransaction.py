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

LOGLEVELCETP                    = logging.DEBUG
LOGLEVEL_H2HTransactionOutbound = logging.INFO
LOGLEVEL_H2HTransactionInbound  = logging.INFO
LOGLEVEL_C2CTransaction         = logging.INFO
LOGLEVEL_oC2CTransaction        = logging.INFO
LOGLEVEL_iC2CTransaction        = logging.INFO

DEFAULT_KEEPALIVE_TIMEOUT       = 2
DEFAULT_KEEPALIVE_CYCLE         = 10
DEFAULT_STATE_TIMEOUT           = 31

KEY_ONGOING                     = 1
KEY_ESTABLISHED                 = 2
NEGOTIATION_RTT_THRESHOLD       = 3



"""
General_policy
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


class C2CTransaction(object):
    def __init__(self, name="C2CTransaction"):
        self.name       = name
        self._logger    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_C2CTransaction)

    def get_cetp_packet(self, sstag=None, dstag=None, req_tlvs=[], offer_tlvs=[], avail_tlvs=[]):
        """ Default CETP fields for signalling message """
        version                     = 1
        cetp_header                 = {}
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
        if (group=="ces") and (code in CETP.CES_CODE_TO_POLICY):
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, \
                       cetp_security=self.cetp_security, ces_policy = self.ces_policy, query=False)
        return tlv
                    
    def _create_offer_tlv2(self, group=None, code=None):
        tlv ={}
        tlv['group'], tlv['code'], tlv["value"] = group, code, ""
        if (group=="ces") and (code in CETP.CES_CODE_TO_POLICY):
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, \
                       cetp_security=self.cetp_security, ces_policy = self.ces_policy, query=False)
        return tlv

    def _create_request_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        if (group=="ces") and (code in CETP.CES_CODE_TO_POLICY):
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, \
                        cetp_security=self.cetp_security, ces_policy = self.ces_policy, query=True)
            return tlv
        
    def _create_request_tlv2(self, group=None, code=None):
        tlv = {}
        tlv['group'], tlv['code'] = group, code
        if (group=="ces") and (code in CETP.CES_CODE_TO_POLICY):
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, \
                        cetp_security=self.cetp_security, ces_policy = self.ces_policy, query=True)
            return tlv
    
    def _create_response_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        if (group=="ces") and (code in CETP.CES_CODE_TO_POLICY):
            func = CETP.RESPONSE_TLV_GROUP[group][code]
            tlv  = func(tlv=tlv, code=code, ces_params=self.ces_params, l_cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, \
                        cetp_security=self.cetp_security, ces_policy = self.ces_policy, transaction=self, packet=self.packet)
            return tlv
        
    def _verify_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        if (group=="ces") and (code in CETP.CES_CODE_TO_POLICY):
            func   = CETP.VERIFY_TLV_GROUP[group][code]
            result = func(tlv=tlv, code=code, ces_params=self.ces_params, l_cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, packet=self.packet, \
                          cetp_security=self.cetp_security, ces_policy = self.ces_policy, transaction=self, session_established=self.c2c_negotiation_status)
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
                
    def negotiated_parameters(self):
        s = [self.l_cesid, self.r_cesid, self.ttl, self.evidence_format, self.remote_session_limit]
        return s
                
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



class oC2CTransaction(C2CTransaction):
    """
    Negotiates outbound CES policies with the remote CES.
    Also contains methods to facilitate signalling in the post-c2c negotiation phase between CES nodes.
    """
    def __init__(self, loop, l_cesid="", r_cesid="", c_sstag=0, c_dstag=0, cetpstate_mgr=None, policy_client=None, policy_mgr=None, proto="tls", ces_params=None, \
                 cetp_security=None, transport=None, direction="outbound", name="oC2CTransaction"):
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
        self.remote_addr            = transport.peername
        self.cetp_security          = cetp_security
        self.rtt                    = 0
        self.packet_count           = 0
        self.last_seen              = time.time()
        self.last_packet_received   = None
        self.c2c_negotiation_status = False
        self.terminated             = False
        self.health_report          = True                                  # Indicates if the CES-to-CES keepalive is responded in 'timeout' duration.
        self.keepalive_trigger_time = time.time()
        self._start_time            = time.time()
        self.name                   = name
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oC2CTransaction)
        self.cetp_negotiation_history  = []

    def load_policies(self, l_ceisd, proto, direction):
        """ Retrieves the policies stored in the Policy file"""
        self.ces_policy, self.ces_policy_tmp  = None, None
        self.ces_policy         = self.policy_mgr.get_ces_policy(proto=self.proto, direction=direction)
        self.ces_policy_tmp     = self.policy_mgr.get_ces_policy(proto=self.proto, direction=direction)

    def load_parameters(self):
        # Default values
        self.keepalive_cycle    = DEFAULT_KEEPALIVE_CYCLE
        self.keepalive_timeout  = DEFAULT_KEEPALIVE_TIMEOUT
        self.state_timeout      = DEFAULT_STATE_TIMEOUT
        
        if 'keepalive_cycle' in self.ces_params:
            self.keepalive_cycle    = self.ces_params['keepalive_cycle']
        if 'keepalive_timeout' in self.ces_params:
            self.keepalive_timeout  = self.ces_params['keepalive_timeout']
        if 'state_timeout' in self.ces_params:
            self.state_timeout      = self.ces_params['state_timeout']

    
    def _initialize(self):
        """ Loads policies, generates session tags, and initiates event handlers """
        try:
            self.sstag = self.generate_session_tags()
            self.load_policies(self.l_cesid, self.proto, self.direction)
            self.load_parameters()
            # Event handler to unregister the incomplete CETP-C2C transaction
            self.c2c_handler = self._loop.call_later(self.state_timeout, self.handle_c2c)
            return True
        
        except Exception as msg:
            self._logger.info(" Failure in initiating CES-to-CES session: {}".format(msg))
            return False


    def handle_c2c(self):
        """ Unregisters an incomplete CES-to-CES transaction """
        if not self.c2c_negotiation_status:
            self._logger.debug(" Outbound C2CTransaction did not complete in time.")
            self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))

    def set_terminated(self, terminated=True):
        self.terminated = terminated
        self.cetpstate_mgr.remove_established_transaction((self.sstag, self.dstag))

    def trigger_negotiated_functions(self):
        """ Used by iCES for triggering negotiated functions in (stateful transaction) upon successful CES-to-CES negotiation """
        try:
            self.load_parameters()
            for pol in self.ces_policy.get_required():
                if (pol['group'] == "ces") and (pol['code']=="keepalive"):
                    self._logger.info(" iCES is triggering function to track the C2C keepalives from the client")
                    self._loop.call_later(self.keepalive_cycle, self.track_keepalive)
        except Exception as msg:
            self._logger.info(" Exception in trigger negotiated functions.")
    
    def track_keepalive(self):
        """ Periodically executed by iCES to track keepalive signals of client  """
        now = time.time()
        if (now - self.last_seen) > self.state_timeout+1:
            self._logger.warning(" Remote CES did not send request for keepalive.")
            self.terminate_transport()
        elif self.terminated:
            self._logger.debug(" C2C transaction is terminated -> Delete periodic tracking of keepalive.")
            # I am simply stating, and not doing anything why?
        else:
            self._loop.call_later(self.keepalive_cycle, self.track_keepalive)
            

    def initiate_c2c_negotiation(self):
        """ Initiates CES policy offers and requirments towards 'r_cesid' """
        try:
            if not self._initialize():
                self._logger.debug(" Failure in initiating the CES-to-CES session towards '{}'.".format(self.r_cesid))
                return None
            
            self._logger.info(" Starting CES-to-CES session towards '{}' (SST={} -> DST={})".format(self.sstag, self.dstag, self.r_cesid))
            req_tlvs, offer_tlvs = [], []
            #self._logger.debug("Outbound policy: ", self.ces_policy.show2())
            
            # The offered TLVs
            for otlv in self.ces_policy.get_offer():
                tlv = self._create_offer_tlv(otlv)
                offer_tlvs.append(tlv)
    
            # The required TLVs
            for rtlv in self.ces_policy.get_required():
                tlv = self._create_request_tlv(rtlv)
                req_tlvs.append(tlv)
            
            # Signing the CETP header, if required by policy    - Depends on the type of transport layer.
            # self.attach_cetp_signature(tlv_to_send)
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs, offer_tlvs=offer_tlvs)
            self.pprint(cetp_message)
            self.cetpstate_mgr.add_initiated_transaction((self.sstag,0), self)
            self.last_packet_sent = cetp_message
            self._start_time = time.time()
            self.last_seen = time.time()
            cetp_packet = json.dumps(cetp_message)
            return cetp_packet
        except Exception as msg:
            self._logger.warning(" Exception in initiating C2C negotiation -> {}".format(msg))
            return None
            

    def validate_signalling_rlocs(self, r_cesid):
        """ 
        Shall store the remote-cesid in a list of trusted CES-IDs 
        Such list shall be maintained by a CETPSecurity monitoring module 
        """
        pass
    
    def feedback_report(self):
        """
        # Function for -- CES2CES-FSM, security, remote CES feedback, evidence collection, and other indicators.
        # At some point, we gotta use report_host():  OR enforce_ratelimits():        # Invoking these methods to report a misbehaving host to remote CES.
        """
        pass

    def _pre_process(self, cetp_msg):
        """ Pre-processing check for the version field, session tags & format of TLVs in the inbound packet. 
        """
        try:
            ver, sstag, dstag = cetp_msg['VER'], cetp_msg['SST'], cetp_msg['DST']
            if ver!=1:
                self._logger.error(" CETP Version is not supported.")
                return False
        except:
            self._logger.error(" Pre-processing the CETP packet failed.")
            return False
        return True
         

    def continue_c2c_negotiation(self, cetp_packet, transport):
        """ Continues CES policy negotiation towards remote CES """
        #try:
        self._logger.info(" Continuing CES-to-CES session negotiation (SST={} -> DST={}) towards '{}'".format(self.sstag, 0, self.r_cesid))
        #self._logger.info(" Outbound policy: ", self.ces_policy.show2())
        negotiation_status = None
        error = False
        cetp_resp = ""
        self.packet = cetp_packet
        
        if not self._pre_process(cetp_packet):
            self._logger.info(" CETP packet failed pre_processing() in oCES")
            self.packet_count += 1
            
            if self.packet_count > 10:
                self._logger.warning("C2C state is under flooding attack from malformed packet")      # TBD: in CETPLayering - safety of session tag reserved by a 'CES-ID'                
                #self.cetp_securtiy.report(r_cesid, behavior)                                         # TBD: Reporting repeated failure in pre-processing stage, to security module.
                transport.close()
            return (negotiation_status, cetp_resp)                          # Drop a packet that is missing fundamental details.

        
        self.transport = transport
        self.dstag = cetp_packet['SST']
        self.last_seen = time.time()
        self.packet = cetp_packet
        req_tlvs, offer_tlvs, ava_tlvs = [], [], []
        i_req, i_info, i_resp = [], [], []
        self.rtt += 1

        if self.rtt>3:
            self._logger.info(" CES-to-CES negotiation exceeded {} RTTs".format(self.rtt))
            negotiation_status = False
            return (negotiation_status, cetp_resp)
        
        # Parsing the inbound packet
        if "query" in self.packet:      i_req = self.packet['query']
        if "info" in self.packet:       i_info = self.packet['info']
        if "response" in self.packet:   i_resp = self.packet['response']
        
        """
        Processing logic:
            oCES checks whether the inbound CETP message is a request or response message.
            - If its a request message, send response & issue local sender's policy queries.
            - If its a response message, it verifies.     If verified, it Accepts. Otherwise, it sends terminate-TLV, if iCES has already completed (SST, DST).
        """
        
        # Processing inbound packet's requests
        if len(i_req):
            self._logger.debug(" Respond the inbound queries && Send oCES queries")
            for tlv in i_req:
                if self.ces_policy_tmp.has_available(tlv):
                    ret_tlvs = self._create_response_tlv(tlv)
                    ava_tlvs.append(ret_tlvs)
                else:
                    self._logger.info(" TLV {}.{}  is not Available.".format(tlv['group'], tlv['code']))
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
                # Locally terminate connection, as iCES is stateless
                negotiation_status = False
                self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))
                return (negotiation_status, cetp_resp)
            
            # Issuing sender's policy requirements
            for rtlv in self.ces_policy_tmp.get_required():
                tlv = self._create_request_tlv(rtlv)
                req_tlvs.append(tlv)

            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs, offer_tlvs=ava_tlvs, avail_tlvs=[])           # Sending the 'response' as 'info'
            self.last_packet_sent = cetp_message
            self.last_packet_received = self.packet
            self.cetp_negotiation_history.append(cetp_message)
            self.pprint(cetp_message)
            negotiation_status = None
            cetp_packet = json.dumps(cetp_message)
            return (negotiation_status, cetp_packet)
        
        """
        Processing logic:
            A CETP message at this stage has policy responses, and shall be processed for: Matching and Verifying the policy elements. 
            - Inbound message can have: 1) Less than required TLVs; 2) TLVs with wrong value; 3) a notAvailable TLV; OR 4) a terminate TLV.
            - This should result in either C2C-negotiation: 1) success; OR 2) Failure -- (Leading to deletion of (oCSST, oCDST) state & an additional terminate-TLV towards iCES -- if iCES became Statefull due to previous message exchanges
        """
        
        for tlv in i_resp:
            if (tlv['group'] == 'ces') and (tlv['code']=='terminate'):
                self._logger.info(" Terminate-TLV received with value: {}".format(tlv['value']) )
                error = True
                break
            
            elif self.ces_policy_tmp.has_required(tlv):
                if self._verify_tlv(tlv):
                    self.ces_policy_tmp.del_required(tlv)
                else:
                    # Absorbs failure in case of 'optional' required policy TLV
                    if not self.ces_policy_tmp.is_mandatory_required(tlv):
                        self.ces_policy_tmp.del_required(tlv)
                        continue
                    
                    self._logger.info(" TLV {}.{} failed verification".format(tlv['group'], tlv['code']))
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
            self.c2c_handler.cancel()
            negotiation_status = False
            self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))      # Since transaction didn't completed at oCES.
            if self.dstag==0:
                return (negotiation_status, "")
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
            self._logger.info("{}".format(30*'*') )
            #self.validate_signalling_rlocs(r_cesid)                 # TBD: To encode
            self._cetp_established()
            negotiation_status = True
            return (negotiation_status, "")

        #except Exception as msg:
        #    self._logger.info(" Exception in resolving C2C transaction: {}".format(msg))
        # return                        # What value shall it return in this case?

    def terminate_transport(self, error_tlv=None):
        """ Sends a terminate TLV and closes the connected transport """
        tlv = self._create_offer_tlv2(group="ces", code="terminate")
        terminate_tlv = [tlv]
        cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, offer_tlvs=terminate_tlv)
        cetp_packet = json.dumps(cetp_message)
        self.transport.send_cetp(cetp_packet)
        self.transport.close()

    def _cetp_established(self):
        """ Triggers the negotiated functionalities upon completion of the CES-to-CES negotiation.
        TBD: Encoding of more functions, to deliver promised functionality on C2C signalling channel.
        """
        self.c2c_negotiation_status = True
        self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))
        self.cetpstate_mgr.add_established_transaction((self.sstag, self.dstag), self)
        self.c2c_handler.cancel()
        keepalive_required = False
        self._logger.info("In post-C2C established session.")
        self._logger.info("Negotiated params: {}".format(self.negotiated_parameters()))

        
        if self.last_packet_received != None:
            # Processing the queries received in the last packet from remote (iCES) to meet the requirements.
            if "query" in self.last_packet_received:      i_req = self.last_packet_received['query']
            if "info" in self.last_packet_received:       i_info = self.last_packet_received['info']
            if "response" in self.last_packet_received:   i_resp = self.last_packet_received['response']
        
            # This says that I don't send keepalive, if the other end doesn't request keepalive.
            # The answer shall be that I ll send whatever we negotiated (+ whatever is necessary from my CES perspective).
            
            if len(i_req)>0:
                for rtlv in i_req:
                    if (rtlv['group']=='ces') and (rtlv['code']=="keepalive") and (self.ces_policy.has_available(rtlv)):
                        self._logger.info(" Remote end requires keepalive")     # Can trigger functions based on 'code' value from here.
                        self._loop.call_later(self.keepalive_cycle, self.initiate_keepalive)                        
                    elif (rtlv["group"] == "ces") and (rtlv['code'] == "ttl"):
                        self._verify_tlv(rtlv)
                    
        elif self.rtt==1:
            # A negotiation may complete in 1-RTT, so we must check the support promised by oces-policy (including keepalive).
            self._logger.debug(" Checking the functionality promised by oCES in the first packet to iCES.")
            
            for otlv in self.ces_policy.get_offer():
                if (otlv["group"] == "ces") and (otlv['code'] == "keepalive"):
                    self._logger.info(" oCES must offer keepalive support.")
                    self._loop.call_later(self.keepalive_cycle, self.initiate_keepalive)
                elif (otlv["group"] == "ces") and (otlv['code'] == "ttl"):
                    self._verify_tlv(otlv)
                    
            
                        
    def initiate_keepalive(self):
        """ Initiates CES keepalive message towards remote CES """
        now = time.time()
        if not self.terminated:
            if (now - self.last_seen) >= self.state_timeout:
                self._logger.warning(" Remote CES has not answered any keepalive within negotiated duration.")
                self.terminate_transport()
            else:
                self._logger.info(" Sending CES keepalive towards '{}' (SST={}, DST={})".format(self.r_cesid, self.sstag, self.dstag))
                tlv = self._create_request_tlv2(group="ces", code="keepalive")
                req_tlvs = [tlv]
                
                cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs)
                cetp_packet = json.dumps(cetp_message)
                self.transport.send_cetp(cetp_packet)
                self.keepalive_trigger_time = time.time()
                self.keepalive_response = None
                #self.pprint(cetp_packet)
                self.keepalive_reporter = self._loop.call_later(self.keepalive_timeout, self.report_connection_health)    # Called to check timely arrival of keepalive response.
                self.keepalive_handler  = self._loop.call_later(self.keepalive_cycle, self.initiate_keepalive)            # Calling itself 
    
    
    def report_connection_health(self):
        if self.keepalive_response==None:
            self.health_report = False
            
    def update_last_seen(self):
        now = time.time()
        if (now-self.last_seen) > 5:
            # Upon noticing the traffic from sender, the last seen is updated & the scheduled keepalive is postponed.
            self.keepalive_handler.cancel()                                         # Since a traffic is observed 
            self.keepalive_handler = self._loop.call_later(self.keepalive_cycle, self.initiate_keepalive)
            
        self.last_seen = now 

    def post_c2c_negotiation(self, packet, transport):
        """ 
        Processes a CETP packet received on the negotiated CES-to-CES session.
        The CETP packet could contain: feedback on host, keepalive, ratelimit on host, session limit on CES, terminate instruction for an established H2H session & so on.
        """
        
        self._logger.info(" Post-C2C negotiation packet from {} (SST={}, DST={})".format(self.r_cesid, self.sstag, self.dstag))
        self.packet = packet
        self.transport = transport
        i_req, i_info, i_resp, ava_tlvs = [], [], [], []
        status, error = False, False
        
        cetp_resp = ""
        # Parsing the inbound packet
        if "query" in self.packet:      i_req = self.packet['query']
        if "info" in self.packet:       i_info = self.packet['info']
        if "response" in self.packet:   i_resp = self.packet['response']

        """
        In the post-C2C policy-negotiation phase,
            Requests are generated by the events, thresholds, handlers or security modules etc.    - towards remote CES on demand
            This function shall only prepare to respond to the requests from remote CES. OR responses coming from the remote CES.
        
        # Example of expected functionalities:
            # terminate (host session - for non-compliance), keepalives.
            # new_certificate, new_session_limit, block_host, ratelimit_sender, ratelimit_destination, evidence (Session tags, FQDN), SLA-violation. 
        
        # Difference in CETP Messaging in Negotiation & Post-policy negotiation phase:
            # In Policy-negotiation, CETP exchange is such that: Query -> Response -> Verified -> Accepted/NotAccepted,     Info -> Verified -> Accepted/NotAccepted
            # In Post policy-negotiation, CETP is exchanged such that: Query -> Response -> Verify -> Accepted/NotAccepted;      
                - A CES sends policy 'query' to remote CES, and remote CES either notes them or Acts/Responds to them with values (if Acceptable) or ACKs them).
        """
        
        """
        # In policy template, some policies are meant for initial CES-to-CES negotiation.
        # Others are required at later stage (or on demand). How to differentiate between these policy elements in policy file (and negotiation).
            - Example: blocking a sender host, no more traffic towards a destination, evidence sharing. 
        """
        
        #Processing inbound packet requests
        if len(i_req):
            # To respond the inbound policy queries
            self._logger.info(" Inbound packet has {} request TLVs".format(len(i_req)))
            for tlv in i_req:
                if self.ces_policy.has_available(tlv):
                    ret_tlvs = self._create_response_tlv(tlv)                   # TBD: Any difference of definition in the post-C2C policy-negotiation phase?
                    ava_tlvs.append(ret_tlvs)
                else:
                    self._logger.info(" TLV {}.{} is not Available.".format(tlv['group'], tlv['code']))
                    if 'cmp' in tlv:
                        if tlv['cmp'] == "optional":
                            self._logger.info(" TLV {}.{} is not mandatory requirement.".format(tlv['group'], tlv['code']))
                            continue
                        else:
                            self._get_unavailable_response(tlv)
                            ava_tlvs.append(tlv)
                    else:
                        self._get_unavailable_response(tlv)
                        ava_tlvs.append(tlv)
                    
        
        #Processing inbound packet's responses
        offer_tlvs = i_resp + i_info                                            # TBD: Merge to one  -- Better to use 'info'
        if len(offer_tlvs):
            self._logger.debug(" Inbound packet contains Info/responses")
            
            for tlv in offer_tlvs:
                if (tlv['group'] == 'ces') and (tlv['code']=='terminate'):
                    self._logger.info(" Terminate received with value: {}".format(tlv['value']) )
                    self.set_terminated()
                    transport.close()
                    
                    """
                    Verify the offered TLVs: their value and code/compatibility.    - Simply note the response (against sent queries)
                    We could respond with not acceptable? OR could aggregate all the responses or feedbacks (leave the decison-making discretion to: NW admin or to requesting function (on its next execution)
                    """
                
                elif self.ces_policy.has_required(tlv):                         # TBD: This shall correspond to the requests sent in the last packet to remote CES.
                    # CES will only accept/process the response for the requests it sent to remote CES.
                    if self._verify_tlv(tlv):
                        self._logger.debug("TLV is verified/validated.")
                        #self.last_packet.queries.satisfied(tlv)                # delete the satisfied query and know that its fulfilled
                    else:
                        self._logger.info(" TLV {}.{} failed verification or it is un-supported".format(tlv['group'], tlv['code']) )         # e.g. A nice-to-have TLV
                        # TBD: in policy-negotiation, check 'notAvailable' for 'nice-to-have' TLVs and never request their support.                        
                        # self.last_packet.queries.satisfied(tlv, False)        # Unsatisfied policy requirements
                        break
        
        if len(ava_tlvs)!=0:
            cetp_msg = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, avail_tlvs=ava_tlvs)
            self.pprint(cetp_msg)
            self.last_seen = time.time()
            cetp_packet = json.dumps(cetp_msg)
            transport.send_cetp(cetp_packet)


    @asyncio.coroutine
    def get_policies_from_PolicySystem(self, r_hostid, r_cesid):    # Has to be a coroutine in asyncio - PolicyAgent
        """ Dummy function emulating the delay due to loading of CETP policies."""
        # yield from self.policy_client.send(r_hostid, r_cesid)
        yield from asyncio.sleep(0.005)




LOGLEVEL_iC2CTransaction        = logging.INFO

class iC2CTransaction(C2CTransaction):
    def __init__(self, loop, sstag=0, dstag=0, l_cesid="", r_cesid="", l_addr=(), r_addr=(), policy_mgr= None, policy_client=None, cetpstate_mgr= None, ces_params=None, \
                 cetp_security=None, proto="tcp", transport=None, name="iC2CTransaction"):
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
        self.name                       = name
        self.health_report              = True
        self.c2c_negotiation_status     = False
        self.last_seen                  = time.time()
        self.keepalive_trigger_time     = time.time()
        self.keepalive_timeout          = DEFAULT_KEEPALIVE_TIMEOUT
        self._logger                    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_iC2CTransaction)
        
    def load_policies(self, l_ceisd, proto, direction):
        """ Retrieves the policies stored in the policy file"""
        self.ices_policy, self.ices_policy_tmp  = None, None
        self.ices_policy        = self.policy_mgr.get_ces_policy(proto=self.proto, direction=direction)
        self.ices_policy_tmp    = self.policy_mgr.get_ces_policy(proto=self.proto, direction=direction)
        self.ces_policy         = self.ices_policy
        
    def _pre_process(self, cetp_packet):
        """ 
        Pre-processes to check the version field, session tags & minimum set of required TLVs in the inbound packet 
        Also loads the CES-to-CES CETP policies.
        """
        try:
            ver, sstag, dstag = cetp_packet['VER'], cetp_packet['SST'], cetp_packet['DST']
            if ver!=1:
                self._logger.error(" CETP Version is not supported.")
                return False

            if "info" in cetp_packet:       
                i_info = cetp_packet['info']
            
            for tlv in i_info:
                if (tlv["group"] == "ces") and (tlv["code"]== "cesid"):
                    self.r_cesid = tlv['value']
                    if len(tlv['value'])>256:
                        return False                    # Length of FQDN <= 255

            if len(self.r_cesid)==0:
                self._logger.info(" Minimum packet details are missing")
                return False
        except:
            self._logger.error(" Pre-processing the CETP packet failed.")
            return False
        
        try:
            self.load_policies(self.l_cesid, self.proto, self.direction)
        except Exception as msg:
            self._logger.error(" Loading of CETP-C2C policies failed.")
            return False
        
        return True


    def process_c2c_transaction(self, cetp_packet):
        """ Processes the inbound CETP-packet for negotiating the CES-to-CES (CETP) policies """
        negotiation_status  = None
        cetp_response       = ""
        #time.sleep(7)
        
        if not self._pre_process(cetp_packet):
            self._logger.debug("Inbound packet failed the pre-processing()")
            negotiation_status = False
            return (negotiation_status, cetp_response)
        
        src_addr = self.remote_addr[0]
        self.packet = cetp_packet
        req_tlvs, offer_tlvs, ava_tlvs, error_tlvs = [], [], [], []
        self.sstag, self.dstag = cetp_packet['DST'], cetp_packet['SST']
        error = False

        self._logger.info("{}".format(30*'*') )
        self._logger.info("CES Policy: {}".format(self.ices_policy))

        # Parsing the inbound packet
        if "query" in self.packet:      i_req = self.packet['query']
        if "info" in self.packet:       i_info = self.packet['info']
        if "response" in self.packet:   i_resp = self.packet['response']
        
        """
        iCES first checks if its requirements are met... If not met, iCES sends all queries. If requirements are met, it verifies the offered/responded policies. 
        If all TLVs are verified, only then it responds to the remote end's requirements.
        """
        
        for tlv in i_info:
            if tlv["group"] == "ces" and tlv["code"]== "terminate":
                # iCES being stateless, shall not receive terminate TLV.
                self._logger.info(" Terminate received for {}.{} with value: {}".format(tlv["group"], tlv['code'], tlv['value']) )     
                return (None, cetp_response)
             
            elif self.ices_policy_tmp.has_required(tlv):
                if self._verify_tlv(tlv):
                    self.ices_policy_tmp.del_required(tlv)
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
            cetp_packet = json.dumps(cetp_message)
            negotiation_status = False
            return (negotiation_status, cetp_packet)
            # Future item:     Return value shall allow CETPLayering to distinguish (Failure due to policy mismatch from wrong value and hence blacklisting subsequent interactions) OR shall this be handled internally?
        
        if len(self.ices_policy_tmp.required)>0:
            self._logger.info(" {} of unsatisfied iCES requirements: ".format(len(self.ices_policy_tmp.get_required())) )
            self._logger.info(" Initiate full query")
            
            req_tlvs, offer_tlvs, ava_tlvs = [], [], []
            for rtlv in self.ices_policy.get_required():            # Generating Full Query message
                tlv = self._create_request_tlv(rtlv)
                req_tlvs.append(tlv)
            
            negotiation_status = None
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, req_tlvs=req_tlvs)
            self.pprint(cetp_message)
            cetp_packet = json.dumps(cetp_message)
            return (negotiation_status, cetp_packet)

        # At this stage, the sender's offer has met the iCES policy requirements && the Offer has been verified..  Now, we evaluate the sender's requirements.        
        for tlv in i_req:                                            # Processing 'Req-TLVs'
            if self.ices_policy.has_available(tlv):
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
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, avail_tlvs=error_tlvs)
            cetp_packet = json.dumps(cetp_message)
            negotiation_status = False
            return (negotiation_status, cetp_packet)                 
        
        
        #All the  requirements of remote-CES are also met -> Now Accept/Create CETP connection (i.e. by assigning 'SST') and Export to stateful (for post-negotiation CETP flow etc.)
        self.sstag = self.generate_session_tags(self.dstag)
        self._logger.info("C2C-policy negotiation succeeded -> Create stateful transaction (SST={}, DST={})".format(self.sstag, self.dstag))
        self._logger.info("{}".format(30*'*') )
        stateful_transansaction = self._export_to_stateful()
        negotiation_status = True
        
        cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, avail_tlvs=ava_tlvs)
        self.pprint(cetp_message)
        self._logger.info("{}".format(30*'*') )
        self._logger.info("Negotiated params: {}".format(self.negotiated_parameters()))
        cetp_packet = json.dumps(cetp_message)
        self.last_packet_sent = cetp_packet
        return (negotiation_status, cetp_packet)


    def _export_to_stateful(self):
        new_transaction = oC2CTransaction(self._loop, l_cesid=self.l_cesid, r_cesid=self.r_cesid, c_sstag=self.sstag, c_dstag=self.dstag, policy_mgr= self.policy_mgr, \
                                          cetpstate_mgr=self.cetpstate_mgr, ces_params=self.ces_params, proto=self.proto, transport=self.transport, direction="inbound")
        new_transaction.load_policies(self.l_cesid, self.proto, direction="inbound")
        new_transaction.c2c_negotiation_status = True
        new_transaction.trigger_negotiated_functions()
        self.cetpstate_mgr.add_established_transaction((self.sstag, self.dstag), new_transaction)
        return new_transaction

    def report_host(self):
        # Method for reporting a misbehaving host to remote CES.
        # OR to enforce_ratelimits()
        pass

