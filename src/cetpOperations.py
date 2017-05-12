#!/usr/bin/python3.5

import CETP
import C2CTransaction
import H2HTransaction
import sys, os
from email import policy
sys.path.append(os.path.join(os.path.dirname('hashcash.py'), 'lib'))
import hashcash
import hashlib
import time
import copy

ACCEPTABLE_ZEROS = 12


def send_ces_cesid(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[policy_code]
    return tlv
    
def send_ces_ttl(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[policy_code]
    return tlv

def send_fw_version(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[policy_code]
    return tlv

def send_ces_certificate(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        certificate_path = ces_params[policy_code]
        print(certificate_path)
        f = open(certificate_path, 'r')
        crt = f.read()
        tlv["value"] = crt
    return tlv

def send_ces_keepalive(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ""
    return tlv

def send_ces_keepalive_cycle(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[policy_code]
    return tlv

def send_ces_fw_version(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[policy_code]
    return tlv

def send_ces_session_limit(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[policy_code]
    return tlv

def send_ces_host_sessions(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[policy_code]
    return tlv

def send_ces_evidence_share(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[policy_code]
    return tlv

def send_ces_evidence(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[policy_code]
    return tlv

def send_ces_caces(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[policy_code]
    return tlv

def send_ces_headersignature(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[policy_code]
    return tlv


def send_ces_pow(**kwargs):
    tlv, code, ces_params, query, r_cesid, cetp_security, r_addr = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"], kwargs["r_cesid"], kwargs['cetp_security'], kwargs['r_addr']
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    r_ip, r_port = r_addr
    
    if query==True:
        challenge_token = cetp_security.pow_challenge(r_cesid=r_cesid, r_ip=r_ip, r_port=r_port)
        tlv['value'] = challenge_token
    else:
        tlv['value'] = ""
    return tlv

def send_ces_terminate(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        pass
    return tlv

def send_ces_port_filtering(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        pass
    return tlv

def send_ces_host_filtering(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        tlv['value'] = ""
    else:
        pass
    return tlv



def response_ces_cesid(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv['ope'] = 'response'
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_ttl(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv['ope'] = 'response'
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_keepalive(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    tlv['ope'] = 'response'
    tlv["value"] = ""
    return tlv

def response_ces_keepalive_cycle(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv['ope'] = 'response'
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_certificate(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv['ope'] = 'response'
    
    certificate_path = ces_params[policy_code]
    f = open(certificate_path, 'r')
    crt = f.read()
    tlv["value"] = crt
    return tlv
 
def response_ces_fw_version(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv['ope'] = 'response'
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_session_limit(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv['ope'] = 'response'
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_host_sessions(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv['ope'] = 'response'
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_caces(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv['ope'] = 'response'
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_evidence_share(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv['ope'] = 'response'
    tlv["value"] = ""
    return tlv

def response_ces_evidence(**kwargs):
    tlv, code, ces_params, cetp_security = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs['cetp_security']
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    evidence = tlv["value"]
    resp = cetp_security.process_evidence(r_cesid, evidence)
    tlv['ope'] = 'response'
    tlv["value"] = resp             # Could be an ACK
    return tlv

def response_ces_headersignature(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv['ope'] = 'response'
    tlv["value"] = "Not defined yet"
    return tlv

def response_ces_pow(**kwargs):
    tlv, code, ces_params, cetp_security = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["cetp_security"]
    tlv['ope'] = "response"
    try:
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        sender_challenge = tlv["value"]
        pow_resp = cetp_security.respond_pow(challenge = sender_challenge)
        tlv["value"] = pow_resp
        return tlv
    except Exception as msg:
        print(" Exception in responding to POW challenge.")
        return tlv



def verify_ces_cesid(**kwargs):
    tlv, code, ces_params, r_cesid, transaction = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["r_cesid"], kwargs["transaction"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    
    try:
        if 'cmp' in tlv:
            if tlv['cmp'] == "NotAvailable":
                return False
        
        if r_cesid != tlv["value"]:
            return False
    except Exception as msg:
        print("Exception in verifying remote cesid")
        return False
    
    return True


def verify_ces_ttl(**kwargs):
    tlv, code, ces_params, transaction, session_established = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["transaction"], kwargs["session_established"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
        
    r_ces_default_dp_ttl = tlv["value"]
    if r_ces_default_dp_ttl  < 2:
        print("default dp-ttl value is unacceptable")
    
    if session_established:
        l_ces_default_dp_ttl = ces_params["dp_ttl"]
                
        if l_ces_default_dp_ttl > r_ces_default_dp_ttl:
            transaction.default_dp_ttl = r_ces_default_dp_ttl
        else:
            transaction.default_dp_ttl = l_ces_default_dp_ttl
    
    return True

def verify_ces_certificate(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ces_keepalive(**kwargs):
    tlv, code, ces_params, transaction = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["transaction"]
    
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    
    value = tlv["value"]
    if value == "":
        transaction.last_seen = time.time()
        transaction.health_report = True
        transaction.keepalive_response = True
                
    return True

def verify_ces_keepalive_cycle(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    try:
        keepalive_cycle = tlv['value']
        if keepalive_cycle < 2:
            print("Invalid/Unacceptable value of the keepalive cycle.")
            return False
        
    except Exception as msg:
        print("Exception in verifying the ces_keepalive_cycle")
        return False
        
    return True

def verify_ces_certificate(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True
 
def verify_ces_session_limit(**kwargs):
    tlv, code, ces_params, session_established, transaction = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["session_established"], kwargs["transaction"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    try:
        remote_ces_session_limit = tlv['value']
        if remote_ces_session_limit < 1:
            print("Remote CES supports {} simultaneous H2H transactions.".format(ces_session_limit))
            return False

        if session_established:
            transaction.session_limit = remote_ces_session_limit                # CES shall forward no more than these simultaneous sessions towards remote CES
        
    except Exception as msg:
        print("Exception in verify_ces_session_limit")
        return False
        
    return True

def verify_ces_host_sessions(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ces_fw_version(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ces_evidence(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ces_evidence_share(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True


def verify_ces_caces(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ces_headersignature(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ces_pow(**kwargs):
    tlv, code, ces_params, r_cesid, cetp_security, r_addr = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["r_cesid"], kwargs['cetp_security'], kwargs['r_addr']
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    r_ip, r_port = r_addr

    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
        
    value = tlv['value']
    res = cetp_security.verify_pow(r_cesid=r_cesid, r_ip=r_ip, r_port=r_port, response=value)
    return res

def send_rloc(**kwargs):
    tlv, code, query, policy = kwargs["tlv"], kwargs["code"], kwargs["query"], kwargs["policy"]
    if query==True:
        if 'value' in tlv:
            tlv["value"] = ""
    else:
        if 'value' not in tlv:
            tlv["value"] = ""
    return tlv

def send_payload(**kwargs):
    tlv, code, query, policy = kwargs["tlv"], kwargs["code"], kwargs["query"], kwargs["policy"]
    if query==True:
        if 'value' in tlv:
            tlv["value"] = ""
    else:
        if 'value' not in tlv:
            tlv["value"] = ""
    return tlv

def response_rloc(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    return tlv

def response_payload(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    return tlv

def verify_rloc(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    return True

def verify_payload(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    return True

def send_id(**kwargs):
    tlv, code, query, policy = kwargs["tlv"], kwargs["code"], kwargs["query"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def response_id(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    group, code, cmp, ext, response_value = policy.get_policy_to_respond(tlv)
    tlv['ope'] = "response"
    tlv["value"] = response_value
    return tlv

def verify_id(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    group, code, cmp, ext, value = policy.get_tlv_details(tlv)
    
    if cmp =="NotAvailable":
        return False
    
    inbound_id = value
    group, code, cmp, ext, allowed_value = policy.get_policy_to_enforce(tlv)
    #print(inbound_id in allowed_value)
    
    if inbound_id in allowed_value:
        return True
    else:
        return False

def send_ctrl_dstep(**kwargs):
    pass

def send_ctrl_fqdn(**kwargs):
    tlv, code, query, policy = kwargs["tlv"], kwargs["code"], kwargs["query"], kwargs["policy"]
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    if query==True:
        if 'value' in tlv:
            tlv["value"] = ""
    else:
        if 'value' not in tlv:
            tlv["value"] = ""
        
    return tlv
    
def send_ctrl_certificate(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.copy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


def send_ctrl_caep(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    
    new_tlv = copy.copy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def send_ctrl_dp_rlocs(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def send_ctrl_dp_ttl(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


def send_ctrl_dp_keepalive_cycle(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"],  kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def send_ctrl_qos(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def send_ctrl_ack(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.copy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def send_ctrl_os_version(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def send_ctrl_policy_caching(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def send_ctrl_dp_proto(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def send_ctrl_dp_port(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def send_ctrl_dp_ratelimit(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def send_ctrl_terminate(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

def send_ctrl_warning(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


def response_ctrl_dstep(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    policy_code = CETP.CONTROL_CODES[code]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_fqdn(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    policy_code = CETP.CONTROL_CODES[code]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_certificate(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    policy_code = CETP.CONTROL_CODES[code]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_caep(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    #policy_code = CETP.CONTROL_CODES[code]
    
    group, code, cmp, ext, response_value = policy.get_policy_to_respond(tlv)
    #print("response_value", response_value)
    tlv['ope'] = "response"
    tlv["value"] = response_value
    return tlv

def response_ctrl_dp_rlocs(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    policy_code = CETP.CONTROL_CODES[code]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_dp_ttl(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    policy_code = CETP.CONTROL_CODES[code]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_dp_keepalive_cycle(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    policy_code = CETP.CONTROL_CODES[code]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_qos(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_ack(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_os_version(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_policy_caching(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_dp_proto(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_dp_port(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_dp_ratelimit(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_terminate(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    tlv['ope'] = 'response'
    return tlv

def response_ctrl_warning(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    tlv['ope'] = 'response'
    #tlv["value"] = "some-value"
    return tlv


def verify_ctrl_dstep(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_fqdn(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_certificate(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_caep(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_dp_rlocs(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_dp_ttl(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_dp_keepalive_cycle(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_qos(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_ack(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_os_version(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_policy_caching(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_dp_proto(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_dp_port(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_dp_ratelimit(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True


def verify_ctrl_terminate(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ctrl_warning(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    #policy_code = CETP.CONTROL_CODES[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True



