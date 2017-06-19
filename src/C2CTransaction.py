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

DEFAULT_KEEPALIVE_TIMEOUT       = 2
DEFAULT_KEEPALIVE_CYCLE         = 20
DEFAULT_STATE_TIMEOUT           = 11
NEGOTIATION_RTT_THRESHOLD       = 3

"""
General_policy
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

    def get_cetp_packet(self, sstag=None, dstag=None, tlvs=[]):
        """ Default CETP fields for signalling message """
        version                     = 1
        cetp_header                 = {}
        cetp_header['VER']          = version
        cetp_header['SST']          = sstag
        cetp_header['DST']          = dstag
        cetp_header['TLV']          = tlvs
        return cetp_header

    def _get_unavailable_response(self, tlv):
        resp_tlv = copy.copy(tlv)
        resp_tlv['cmp'] = 'NotAvailable'
        resp_tlv['ope'] = "info"
        return resp_tlv
        
    def _get_terminate_tlv(self, err_tlv=None):
        terminate_tlv = {}
        terminate_tlv['ope'], terminate_tlv['group'], terminate_tlv['code'], terminate_tlv['value'] = "info", "ces", "terminate", ""
        if err_tlv is not None:
            terminate_tlv['value'] = err_tlv
        return terminate_tlv

    def _create_offer_tlv(self, tlv):
        group, code = tlv['group'], tlv['code']
        if (group=="ces") and (code in CETP.CES_CODE_TO_POLICY):
            func = CETP.SEND_TLV_GROUP[group][code]
            tlv = func(tlv=tlv, code=code, ces_params=self.ces_params, cesid=self.l_cesid, r_cesid=self.r_cesid, r_addr=self.remote_addr, \
                       cetp_security=self.cetp_security, ces_policy = self.ces_policy, query=False)
        return tlv
                    
    def _create_offer_tlv2(self, group=None, code=None, value=None):
        tlv ={}
        tlv['ope'], tlv['group'], tlv['code'] = "info", group, code
        if value!=None:
            tlv["value"] = value
        else:
            tlv["value"] = ""
            
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
        tlv['ope'], tlv['group'], tlv['code'], tlv['value'] = "query", group, code, ""
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
                

class oC2CTransaction(C2CTransaction):
    """
    Negotiates outbound CES policies with the remote CES.
    Also contains methods to facilitate signalling in the post-c2c negotiation phase between CES nodes.
    """
    def __init__(self, loop, l_cesid="", r_cesid="", c_sstag=0, c_dstag=0, cetpstate_mgr=None, policy_client=None, policy_mgr=None, proto="tls", ces_params=None, \
                 cetp_security=None, transport=None, c2c_layer=None, direction="outbound", name="oC2CTransaction"):
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
        self.rtt                    = 0
        self.packet_count           = 0
        self.missed_keepalives      = 0
        self.last_seen              = time.time()
        self.last_packet_received   = None
        self.keepalive_handler      = None
        self.keepalive_scheduled    = False
        self.keepalive_triggered    = True
        self.c2c_negotiation_status = False
        self.terminated             = False
        self.health_report          = True                                  # Indicates if the CES-to-CES keepalive is responded in 'timeout' duration.
        self.keepalive_trigger_time = time.time()
        self._start_time            = time.time()
        self.keepalive_schedule_delay = 0
        self.name                   = name
        self._logger                = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_oC2CTransaction)
        self.cetp_negotiation_history  = []
        self.r_ces_requirements        = []         # To store r_ces requirements

    def load_policies(self, l_cesid):
        """ Retrieves the policies stored in the Policy file"""
        self.ces_policy  = self.policy_mgr.get_ces_policy(proto=self.proto)

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
            self.load_policies(self.l_cesid)
            self.load_parameters()
            # Event handler to unregister the incomplete CETP-C2C transaction
            self.c2c_handler = self._loop.call_later(self.state_timeout, self.handle_c2c)
            return True
        
        except Exception as ex:
            self._logger.info(" Failure in initiating CES-to-CES session: {}".format(ex))
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
                    self._loop.call_later(2, self.initiate_keepalive_functionality)
        except Exception as ex:
            self._logger.info(" Exception in trigger negotiated functions {}".format(ex))
    
    @asyncio.coroutine
    def initiate_c2c_negotiation(self):
        """ Initiates CES policy offers and requirments towards 'r_cesid' """
        try:
            if not self._initialize():
                self._logger.debug(" Failure in initiating the CES-to-CES session towards '{}'.".format(self.r_cesid))
                return None
            
            self._logger.info(" Starting CES-to-CES session towards '{}' (SST={} -> DST={})".format(self.sstag, self.dstag, self.r_cesid))
            tlvs_to_send = []
            req_tlvs, offer_tlvs = [], []
            #self._logger.debug("Outbound policy: ", self.ces_policy.show2())
            
            # The offered TLVs
            for otlv in self.ces_policy.get_offer():
                tlv = self._create_offer_tlv(otlv)
                tlvs_to_send.append(tlv)
    
            # The required TLVs
            for rtlv in self.ces_policy.get_required():
                tlv = self._create_request_tlv(rtlv)
                tlvs_to_send.append(tlv)
            
            # Signing the CETP header, if required by policy    - Depends on the type of transport layer.
            # self.attach_cetp_signature(tlv_to_send)
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
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
        AND, checks whether the inbound packet is a request message.
        """
        try:
            self.query_message = False
            ver, inbound_sstag, inbound_dstag = cetp_msg['VER'], cetp_msg['SST'], cetp_msg['DST']
            self.sstag, self.dstag = inbound_dstag, inbound_sstag
            self.received_tlvs = cetp_msg['TLV']
            self.packet = cetp_msg
            
            if ver!=1:
                self._logger.error(" CETP Version is not supported.")
                return False
            
            for received_tlv in self.received_tlvs:
                if self._check_tlv(received_tlv, ope="query"):
                    self.query_message = True
                    break
            return True
        
        except:
            self._logger.error(" Pre-processing the CETP packet failed.")
            return False
         

    def continue_c2c_negotiation(self, cetp_packet, transport):
        """ Continues CES policy negotiation towards remote CES """
        #try:
        self._logger.info(" Continuing CES-to-CES session negotiation (SST={} -> DST={}) towards '{}'".format(self.sstag, 0, self.r_cesid))
        self._logger.info("Inbound packet")
        self.pprint(cetp_packet)
        #self._logger.info(" Outbound policy: ", self.ces_policy.show2())
        negotiation_status = None
        error = False
        cetp_resp = ""
        satisfied_requriements = 0
        
        if not self._pre_process(cetp_packet):
            self._logger.info(" CETP packet failed pre_processing() in oCES")
            self.packet_count += 1
            
            if self.packet_count > 10:
                self._logger.warning("C2C state is under flooding attack from malformed packet")      # TBD: in CETPLayering - safety of session tag reserved by a 'CES-ID'                
                #self.cetp_securtiy.report(r_cesid, behavior)                                         # TBD: Reporting repeated failure in pre-processing stage, to security module.
                transport.close()
            return (negotiation_status, cetp_resp)                          # Drop a packet that is missing fundamental details.

        
        self.transport = transport
        tlvs_to_send, error_tlvs = [], []
        self.rtt += 1

        if self.rtt>3:
            self._logger.info(" CES-to-CES negotiation exceeded {} RTTs".format(self.rtt))
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
                    self.r_ces_requirements.append(received_tlv)
                    if self.ces_policy.has_available(received_tlv):
                        ret_tlv = self._create_response_tlv(received_tlv)
                        if ret_tlv != None:
                            tlvs_to_send.append(ret_tlv)
                            continue
                        
                    if self._check_tlv(received_tlv, cmp="optional"):
                        self._logger.info(" An optional Request TLV {}.{} is not available.".format(received_tlv['group'], received_tlv['code']))
                        ret_tlv = self._get_unavailable_response(received_tlv)
                        tlvs_to_send.append(ret_tlv)
                    else:
                        error = True
                        break

            #A CETP response message is processed for: Policy Matching and TLV Verification. The message can have: 1) Less than required TLVs; 2) TLVs with wrong value; 3) a notAvailable TLV; OR 4) a terminate TLV.
            elif self._check_tlv(received_tlv, ope="info"):
                if (received_tlv['group'] == 'ces') and (received_tlv['code']=='terminate'):
                    self._logger.info(" Terminate-TLV received with value: {}".format(received_tlv['value']) )
                    error = True
                    break

                elif self.ces_policy.has_required(received_tlv):
                    if self._verify_tlv(received_tlv):
                        satisfied_requriements += 1
                    else:
                        # Absorbs failure in case of 'optional' required policy TLV
                        if not self.ces_policy.is_mandatory_required(received_tlv):
                            satisfied_requriements += 1
                        else:
                            self._logger.info(" TLV {}.{} failed verification".format(received_tlv['group'], received_tlv['code']))
                            tlvs_to_send =  []
                            tlvs_to_send.append(self._get_terminate_tlv(err_tlv=received_tlv))
                            error=True
                            break
                elif not self.ces_policy.has_required(received_tlv):
                    self._logger.info("Unrequrested TLV is received")
                    pass
        
        if error:
            self._logger.error(" CES-to-CES policy negotiation failed in {} RTT".format(self.rtt))
            self._logger.warning(" Execute DNS error callback on the pending h2h-transactions.")
            self.c2c_handler.cancel()
            negotiation_status = False
            self.cetpstate_mgr.remove_initiated_transaction((self.sstag, 0))      # Since transaction didn't completed at oCES.
            if self.dstag==0:
                return (negotiation_status, "")                                   # Locally terminate connection, as iCES is stateless
            else:
                # Return terminate packet to remote end, as it has completed the transaction
                self._logger.info(" Responding remote CES with the terminate-TLV")
                cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)        # Send as 'Info' TLV
                self.last_packet_sent = cetp_message
                self.cetp_negotiation_history.append(cetp_message)
                self.pprint(cetp_message)
                cetp_packet = json.dumps(cetp_message)
                return (negotiation_status, cetp_packet)

        else:
            if (satisfied_requriements == len(self.ces_policy.required)) and (self.dstag!=0):
                self._logger.info(" C2C policy negotiation succeeded in {} RTT.. Continue H2H transactions".format(self.rtt))
                self._logger.info("{}".format(42*'*') )
                self._cetp_established()
                negotiation_status = True
                return (negotiation_status, "")
                
            else:
                self._logger.info(" Inbound packet didn't meet all the policy requirements of sender-host")
                # A more LAX version may allow another negotiation round

                # Issuing oCES Full query                                -- This will not scale to oCES for allowing another RTT, unless we send offers/availables as well.
                for rtlv in self.ces_policy.get_required():
                    tlv = self._create_request_tlv(rtlv)
                    tlvs_to_send.append(tlv)

                negotiation_status = None
                cetp_msg = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)           # Sending 'response' as 'info'
                self.last_packet_sent = cetp_msg
                self.last_packet_received = self.packet
                self.cetp_negotiation_history.append(cetp_msg)
                self.pprint(cetp_msg)
                cetp_packet = json.dumps(cetp_msg)
                return (negotiation_status, cetp_packet)

        #except Exception as msg:
        #    self._logger.info(" Exception in resolving C2C transaction: {}".format(msg))
        # return                        # What value shall it return in this case?


    def terminate_transport(self, error_tlv=None):
        """ Sends a terminate TLV and closes the connected transport """
        terminate_tlv = self._create_offer_tlv2(group="ces", code="terminate", value=error_tlv)
        tlv_to_send = [terminate_tlv]
        cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlv_to_send)
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
        self._logger.info("Negotiated params: {}".format(self.negotiated_parameters()))

        # Processing the queries of remote CES, to trigger functionality
        if len(self.r_ces_requirements) !=0:
            # CES doesn't send keepalive, if the other end doesn't request keepalive.
            # The answer shall be that I ll send whatever we negotiated (+ whatever is necessary from my CES perspective).
            for received_tlv in self.r_ces_requirements:
                if self._check_tlv(received_tlv, ope="query"):
                    if (received_tlv['group']=='ces') and (received_tlv['code']=="keepalive") and (self.ces_policy.has_available(received_tlv)):
                        self._logger.info(" Remote end requires keepalive")     # Can trigger functions based on 'code' value from here.
                        self._loop.call_later(2, self.initiate_keepalive_functionality)         # Prevent its execution more than once.
                        
        elif self.rtt==1:
            # A negotiation may complete in 1-RTT, so CES must support the promised policy offer.
            for otlv in self.ces_policy.get_offer():
                if (otlv["group"] == "ces") and (otlv['code'] == "keepalive"):
                    self._logger.info(" oCES must offer keepalive support.")
                    self._loop.call_later(2, self.initiate_keepalive_functionality)

                    
    def initiate_keepalive_functionality(self):
        """ Schedules keepalive upon inactivity of time 'To' on a link """
        now = time.time()
        if not self.terminated:
            self._loop.call_later(2, self.initiate_keepalive_functionality)
            monitoring_period = 5                                               # TBD: put a value relatable to keepalive cycle.
            if ((now - self.last_seen) > monitoring_period):
                if not self.keepalive_scheduled:
                    self.keepalive_handler  = self._loop.call_later(self.keepalive_cycle-monitoring_period, self.initiate_keepalive)
                    self.keepalive_scheduled = True
            else:
                if self.keepalive_scheduled:
                    self.keepalive_handler.cancel()
                    self.keepalive_scheduled = False

    def initiate_keepalive(self):
        """ Initiates CES keepalive message towards remote CES """
        now = time.time()
        if not self.terminated:
            self._logger.info(" Sending CES keepalive towards '{}' (SST={}, DST={})".format(self.r_cesid, self.sstag, self.dstag))
            keepalive_tlv = self._create_request_tlv2(group="ces", code="keepalive")
            tlvs_to_send = [keepalive_tlv]
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
            #self.pprint(cetp_message)
            self.keepalive_trigger_time = time.time()
            self.keepalive_triggered = True
            self.keepalive_response = None
            self.keepalive_reporter = self._loop.call_later(self.keepalive_timeout, self.report_connection_health)      # Checks for timely arrival of the keepalive response.
            cetp_packet = json.dumps(cetp_message)
            self.transport.send_cetp(cetp_packet)
            
    def update_last_seen(self):
        self.last_seen = time.time()

    def report_misbehavior_evidence(self, h_sstag, h_dstag, r_hostid, misbehavior_evidence):
        """ Reports misbehavior evidence observed in (h_sstag, h_dstag) to the remote CES """
        self._logger.info(" Sending misbehavior evidence towards remote CES '{}' )".format(self.r_cesid, r_hostid))
        evidence = {"h2h_session":(h_sstag, h_dstag), "misbehavior":misbehavior_evidence}             # misbehavior_evidence="FSecure-MalwarePayload"
        evidence_value = json.dumps(evidence)
        evidence_tlv = self._create_request_tlv2(group="ces", code="evidence")
        evidence_tlv["value"] = evidence_value
        tlvs_to_send = [evidence_tlv]
        cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
        cetp_packet = json.dumps(cetp_message)
        #self.pprint(cetp_message)
        self.evidence_acknowledged = False
        self.keepalive_reporter = self._loop.call_later(2, self.check_evidence_acknowledgment)      # Checking acknowledgement of the sent evidence.
        self.transport.send_cetp(cetp_packet)
        
        
    def check_evidence_acknowledgment(self):
        """ Checks whether a sent evidence is received and acknowledged by remote CES. """
        if not self.evidence_acknowledged:
            self._logger.info("Remote CES '{}' has not acknowledged the send evidence.\n\n".format(self.r_cesid))
        else:
            print("Evidence is acknowledged")
            
    
    def report_connection_health(self):
        """ Evaluates whether remote CES is: active; inactive; or dead """
        now = time.time()
        if self.keepalive_response==None:
            # No keep-alive response
            self.health_report = False
            self.missed_keepalives += 1
            self.c2c_layer.report_rtt(self.transport, rtt=2**32)
            
            if self.missed_keepalives >= 3:
                self._logger.warning(" Remote CES has not answered any keepalive within 'To'.")
                self.set_terminated()
                self.terminate_transport()
            else:
                self.keepalive_handler  = self._loop.call_later(3.0, self.initiate_keepalive)          # Sending next keepalive-request
        
        elif self.keepalive_response == True:
            self.missed_keepalives   = 0
            self.keepalive_scheduled = False
            rtt = self.keepalive_response_time - self.keepalive_trigger_time
            self.c2c_layer.report_rtt(self.transport, rtt=rtt)                                         # Report RTT
            
    
    def post_c2c_negotiation(self, packet, transport):
        """ 
        Processes a CETP packet received on the negotiated CES-to-CES session.
        In the post-C2C policy-negotiation phase, A CES could send requests (towards remote CES) triggered by Events, Thresholds, Handlers, Security modules or Admin commands etc.
            # Example: 1) terminate (host session - for non-compliance); 2) keepalives; 3) new_certificate; 4) new session_limit; 5) evidence (session tags, FQDN); 6) block_host; 7) ratelimiting: sender, destination, SLA-violation.
        
        Remote CES either notes these requests, OR Responds to them with ACKs or Acceptable values.      The response is then verified by CES.
        """
        self._logger.info(" Post-C2C negotiation packet from {} (SST={}, DST={})".format(self.r_cesid, self.sstag, self.dstag))
        self.packet = packet
        self.transport = transport
        tlvs_to_send = []
        status, error = False, False
        received_tlvs = []
        
        """
        # In policy template, some policies are meant for initial CES-to-CES negotiation.
        # Others are required at later stage (or on demand). How to differentiate between these policy elements in policy file (and negotiation).
            - Example: blocking a sender host, no more traffic towards a destination, evidence sharing. 
        """
        #time.sleep(20)
        
        if 'TLV' in packet:
            received_tlvs = packet['TLV']
        
        # Processing the inbound request packet
        for received_tlv in received_tlvs:
            if self._check_tlv(received_tlv, ope="query"):
                if (received_tlv["group"]=="ces") and (received_tlv["code"]=="evidence"):
                    self._logger.info(" Misbehavior evidence from remote CES '{}'".format(self.r_cesid))
                    ret_tlv = self._create_response_tlv(received_tlv)
                    if ret_tlv!=None:
                        tlvs_to_send.append(ret_tlv)
                    else:
                        self._logger.warning("Couldn't respond to TLV. Send some kinda warning-TLV indicating mismatch to remote CES?")


                elif (received_tlv["group"]=="ces") and (received_tlv["code"]=="comment"):
                    self._logger.info("General commentary from remote CES")
                    self._logger.info("Comment: '{}'".format(received_tlv['value']))
                
                elif self.ces_policy.has_available(received_tlv):
                    ret_tlv = self._create_response_tlv(received_tlv)
                    if ret_tlv !=None:
                        tlvs_to_send.append(ret_tlv)
                    else:
                        self._logger.info("Invalid TLV received in post-c2c negotiation")
                else:
                    if self._check_tlv(received_tlv, cmp="optional"):
                        self._logger.info(" An optional requirement {}.{} is not available.".format(received_tlv['group'], received_tlv['code']))
                        continue
                    else:
                        self._get_unavailable_response(received_tlv)
                        tlvs_to_send.append(received_tlv)
                        
            elif self._check_tlv(received_tlv, ope="info"):
                if (received_tlv['group'] == 'ces') and (received_tlv['code']=='terminate'):
                    self._logger.info("Closing the C2C session")
                    self._logger.info(" Terminate received with value: {}".format(received_tlv['value']) )
                    self.set_terminated()
                    transport.close()
                    """
                    Verify the offered TLVs: their value and code/compatibility.    - Simply note the response (against sent queries)
                    We could respond with not acceptable? OR could aggregate all the responses or feedbacks (leave the decison-making discretion to: NW admin or to requesting function (on its next execution)
                    """

                elif (received_tlv["group"]=="ces") and (received_tlv["code"]=="evidence"):
                    self._logger.info(" Misbehavior evidence is ACKnowledged by remote CES '{}'".format(self.r_cesid))
                    self.evidence_acknowledged = True
                    print(received_tlv["value"])
                    
                elif self.ces_policy.has_required(received_tlv):                         # TBD: This shall correspond to the requests sent in the last packet to remote CES.
                    # CES will only accept/process the response for the requests it sent to remote CES.
                    if (received_tlv["group"]=="ces") and (received_tlv["code"]=="keepalive"):
                        self.keepalive_response_time    = time.time()
                        self.health_report              = True
                        self.keepalive_response         = True
                        if not self.keepalive_triggered:
                            self.c2c_layer.report_rtt(self.transport, last_seen=self.last_seen)
                        
                    else:
                        if self._verify_tlv(received_tlv):
                            self._logger.debug("TLV is verified/validated.")
                            #self.last_packet.queries.satisfied(tlv)                # delete the satisfied query and know that its fulfilled
                        else:
                            self._logger.info(" TLV {}.{} failed verification or it is un-supported".format(received_tlv['group'], received_tlv['code']) )         # e.g. A nice-to-have TLV
                            # TBD: in policy-negotiation, check 'notAvailable' for 'nice-to-have' TLVs and never request their support.                        
                            # self.last_packet.queries.satisfied(tlv, False)        # Unsatisfied policy requirements
                            break
        
        if len(tlvs_to_send)!=0:
            cetp_msg = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
            #self.pprint(cetp_msg)
            self.last_seen = time.time()
            cetp_packet = json.dumps(cetp_msg)
            transport.send_cetp(cetp_packet)


    def _assign_c2c_layer(self, c2c_layer):
        """ Assigned by the CETP Manager """
        self.c2c_layer = c2c_layer

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
        
    def load_policies(self, l_cesid):
        """ Retrieves the policies stored in the policy file"""
        self.ices_policy, self.ices_policy_tmp  = None, None
        self.ices_policy        = self.policy_mgr.get_ces_policy(proto=self.proto)
        self.ices_policy_tmp    = self.policy_mgr.get_ces_policy(proto=self.proto)
        self.ces_policy         = self.ices_policy

    def _pre_process(self, cetp_packet):
        """ Pre-process the inbound packet for the minimum necessary details, AND loads the CES-to-CES policies. """
        try:
            ver, inbound_sstag, inbound_dstag = cetp_packet['VER'], cetp_packet['SST'], cetp_packet['DST']
            self.sstag, self.dstag = inbound_dstag, inbound_sstag
            self.packet            = cetp_packet
            self.received_tlvs     = cetp_packet['TLV']
            
            if ver!=1:
                self._logger.error(" CETP Version is not supported.")
                return False

            for received_tlv in self.received_tlvs:
                if self._check_tlv(received_tlv, ope="info"):
                    if (received_tlv['group']== "ces") and (received_tlv['code']=="cesid"):
                        self.r_cesid = received_tlv['value']
                        break

            if (len(self.r_cesid)==0) or (len(self.r_cesid)>256):
                self._logger.info(" CES-ID is not correct")
                return False
            
        except:
            self._logger.error(" Pre-processing the CETP packet failed.")
            return False
        
        try:
            self.load_policies(self.l_cesid)
        except Exception as ex:
            self._logger.error(" Loading of CETP-C2C policies failed. '{}'".format(ex))
            return False
        return True

    def process_c2c_transaction(self, cetp_packet):
        """ Processes the inbound CETP-packet for negotiating the CES-to-CES (CETP) policies """
        self._logger.info("{}".format(42*'*') )
        self._logger.info("Inbound packet")
        self.pprint(cetp_packet)
        negotiation_status  = None
        cetp_response       = ""
        #time.sleep(7)
        
        if not self._pre_process(cetp_packet):
            self._logger.debug("Inbound packet failed the pre-processing()")
            negotiation_status = False
            return (negotiation_status, cetp_response)
        
        src_addr = self.remote_addr[0]
        tlvs_to_send, error_tlvs = [], []
        satisfied_requriements = 0
        error = False

        self._logger.info("{}".format(42*'*') )
        self._logger.info("CES Policy: {}".format(self.ices_policy))
        
        # Processing the offers in the inbound packet
        for received_tlv in self.received_tlvs:
            # Checks whether the policy offers of remote CES meet the policy requirements of iCES, and whether the Offer can be verified.
            if self._check_tlv(received_tlv, ope="info"):
                if received_tlv["group"] == "ces" and received_tlv["code"]== "terminate":
                    self._logger.info(" Terminate-TLV received with payload: {}".format(received_tlv['value']) )      # stateless iCES shall not receive terminate TLV.
                    return (None, cetp_response)
                 
                elif self.ices_policy_tmp.has_required(received_tlv):
                    if self._verify_tlv(received_tlv):
                        satisfied_requriements += 1
                    else:
                        # Absorbs failure in case of 'optional' required policy TLV
                        if not self.ices_policy.is_mandatory_required(received_tlv):
                            satisfied_requriements += 1
                        else:
                            self._logger.info("TLV {}.{} failed verification".format(received_tlv['group'], received_tlv['code']))
                            error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                            error = True
                            break
                else:
                    self._logger.debug("Non-requested TLV {} is received: ".format(received_tlv))

        if not error:
            # Process the requests in the inbound packet, only if the oCES made valid offers    (More secure approach)
            for received_tlv in self.received_tlvs:
                # Evaluates whether the remote CES's requirements could be answered
                if self._check_tlv(received_tlv, ope="query"):
                    if self.ices_policy.has_available(received_tlv):
                        ret_tlv = self._create_response_tlv(received_tlv)
                        if ret_tlv!=None:
                            tlvs_to_send.append(ret_tlv)
                            continue
                        
                    if self._check_tlv(received_tlv, cmp="optional"):
                        self._logger.info(" A mandatory required TLV {}.{} is not available.".format(received_tlv['group'], received_tlv['code']))
                        ret_tlv = self._get_unavailable_response(received_tlv)
                        tlvs_to_send.append(ret_tlv)
                    else:
                        self._logger.info(" An optional required TLV {}.{} is not available.".format(received_tlv['group'], received_tlv['code']))
                        error_tlvs = [self._get_terminate_tlv(err_tlv=received_tlv)]
                        error = True
                        break

        if error:
            cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=error_tlvs)
            self.pprint(cetp_message)
            cetp_packet = json.dumps(cetp_message)
            negotiation_status = False
            return (negotiation_status, cetp_packet)
            # Future item:     Return value shall allow CETPLayering to distinguish (Failure due to policy mismatch from wrong value and hence blacklisting subsequent interactions) OR shall this be handled internally?
        else:
            if (satisfied_requriements == len(self.ices_policy.required)):
                #All the  requirements of remote-CES are also met -> Now Accept/Create CETP connection (i.e. by assigning 'SST') and Export to stateful (for post-negotiation CETP flow etc.)
                self.sstag = self.generate_session_tags(self.dstag)
                stateful_transansaction = self._export_to_stateful()
                self._logger.info("C2C-policy negotiation succeeded -> Create stateful transaction (SST={}, DST={})".format(self.sstag, self.dstag))
                self._logger.info("{}".format(42*'*') )
                negotiation_status = True

                cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                self.pprint(cetp_message)
                self._logger.info("Negotiated params: {}".format(self.negotiated_parameters()))
                cetp_packet = json.dumps(cetp_message)
                self.last_packet_sent = cetp_packet
                return (negotiation_status, cetp_packet)
            else:
                self._logger.info(" {} unsatisfied iCES requirements: ".format( len(self.ices_policy.required)-satisfied_requriements) )
                # Generating Full Query message
                tlvs_to_send = []
                for rtlv in self.ices_policy.get_required():            
                    tlv = self._create_request_tlv(rtlv)
                    tlvs_to_send.append(tlv)
                
                negotiation_status = None
                cetp_message = self.get_cetp_packet(sstag=self.sstag, dstag=self.dstag, tlvs=tlvs_to_send)
                cetp_packet = json.dumps(cetp_message)
                self.pprint(cetp_message)
                return (negotiation_status, cetp_packet)


    def _export_to_stateful(self):
        new_transaction = oC2CTransaction(self._loop, l_cesid=self.l_cesid, r_cesid=self.r_cesid, c_sstag=self.sstag, c_dstag=self.dstag, policy_mgr= self.policy_mgr, \
                                          cetpstate_mgr=self.cetpstate_mgr, ces_params=self.ces_params, proto=self.proto, transport=self.transport, direction="inbound", \
                                          cetp_security=self.cetp_security)
        new_transaction.load_policies(self.l_cesid)
        new_transaction.c2c_negotiation_status = True
        new_transaction.trigger_negotiated_functions()
        self.cetpstate_mgr.add_established_transaction((self.sstag, self.dstag), new_transaction)
        return new_transaction

    def report_host(self):
        # Method for reporting a misbehaving host to remote CES.
        # OR to enforce_ratelimits()
        pass
