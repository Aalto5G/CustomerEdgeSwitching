#!/usr/bin/python3.5

import CETP
import C2CTransaction
import H2HTransaction
import sys, os
sys.path.append(os.path.join(os.path.dirname('hashcash.py'), 'lib'))
import hashcash
import hashlib
import time

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

def send_ces_host_ratelimit(**kwargs):
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

def response_ces_host_ratelimit(**kwargs):
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
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv['ope'] = 'response'
    tlv["value"] = ""
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
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
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
        if (keepalive_cycle < 2) or (keepalive_cycle > 3600):
            print("The keepalive cycle is either too small or too large.")
            return False
    except Exception as msg:
        print("Exception in verify_ces_keepalive_cycle")
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
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    try:
        ces_session_limit = tlv['value']
        max_simultaneous_ces_sessions = ces_params['max_ces_session_limit']
    
        if (ces_session_limit < 1) or (ces_session_limit > max_simultaneous_ces_sessions):
            print("CES does not support {} simultaneous H2H transactions.".format(ces_session_limit))
            return False
    except Exception as msg:
        print("Exception in verify_ces_session_limit")
        return False
        
    return True

def verify_ces_host_ratelimit(**kwargs):
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


def send_ctrl_dstep(**kwargs):
    pass

def send_ctrl_fqdn(**kwargs):
    pass

def send_ctrl_certificate(**kwargs):
    pass

def send_ctrl_caep(**kwargs):
    pass

def send_ctrl_dp_rlocs(**kwargs):
    pass

def send_ctrl_dp_ttl(**kwargs):
    pass

def send_ctrl_dp_keepalive_cycle(**kwargs):
    pass

def send_ctrl_qos(**kwargs):
    pass

def send_ctrl_ack(**kwargs):
    pass

def send_ctrl_os_version(**kwargs):
    pass

def send_ctrl_policy_caching(**kwargs):
    pass

def send_ctrl_dp_proto(**kwargs):
    pass

def send_ctrl_dp_port(**kwargs):
    pass

def send_ctrl_dp_ratelimit(**kwargs):
    pass

def send_ctrl_terminate(**kwargs):
    pass

def send_ctrl_warning(**kwargs):
    pass


def response_ctrl_dstep(**kwargs):
    pass

def response_ctrl_fqdn(**kwargs):
    pass

def response_ctrl_certificate(**kwargs):
    pass

def response_ctrl_caep(**kwargs):
    pass

def response_ctrl_dp_rlocs(**kwargs):
    pass

def response_ctrl_dp_ttl(**kwargs):
    pass

def response_ctrl_dp_keepalive_cycle(**kwargs):
    pass

def response_ctrl_qos(**kwargs):
    pass

def response_ctrl_ack(**kwargs):
    pass

def response_ctrl_os_version(**kwargs):
    pass

def response_ctrl_policy_caching(**kwargs):
    pass

def response_ctrl_dp_proto(**kwargs):
    pass

def response_ctrl_dp_port(**kwargs):
    pass

def response_ctrl_dp_ratelimit(**kwargs):
    pass

def response_ctrl_terminate(**kwargs):
    pass

def response_ctrl_warning(**kwargs):
    pass


def verify_ctrl_dstep(**kwargs):
    pass

def verify_ctrl_fqdn(**kwargs):
    pass

def verify_ctrl_certificate(**kwargs):
    pass

def verify_ctrl_caep(**kwargs):
    pass

def verify_ctrl_dp_rlocs(**kwargs):
    pass

def verify_ctrl_dp_ttl(**kwargs):
    pass

def verify_ctrl_dp_keepalive_cycle(**kwargs):
    pass

def verify_ctrl_qos(**kwargs):
    pass

def verify_ctrl_ack(**kwargs):
    pass

def verify_ctrl_os_version(**kwargs):
    pass

def verify_ctrl_policy_caching(**kwargs):
    pass

def verify_ctrl_dp_proto(**kwargs):
    pass

def verify_ctrl_dp_port(**kwargs):
    pass

def verify_ctrl_dp_ratelimit(**kwargs):
    pass

def verify_ctrl_terminate(**kwargs):
    pass

def verify_ctrl_warning(**kwargs):
    pass


