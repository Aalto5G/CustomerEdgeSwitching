#!/usr/bin/python3.5

import CETP
import C2CTransaction
import H2HTransaction
import sys, os
sys.path.append(os.path.join(os.path.dirname('hashcash.py'), 'lib'))
import hashcash
import hashlib
import time


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
    tlv, code, ces_params, query, r_cesid = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"], kwargs["r_cesid"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    
    if query==True:
        POW_SECRET = "HammadTAKEsII"                                                              # This must be managed later
        ACCEPTABLE_ZEROS = 15
        ch = r_cesid + ":" + POW_SECRET                             # FOR Now, For testing .. Challenge shall be more complicated (to prevent guessing)
        ch_hash = hashlib.sha256(ch.encode()).hexdigest()
        ch_hash = ch_hash[0:16]
        challenge_token = str(ch_hash)+";"+str(ACCEPTABLE_ZEROS)
        tlv['value'] = challenge_token
    else:
        tlv['value'] = ""                                           # Sender-oriented pow can be supported in Offer, only if a type field in TLV indicates that it is 
                                                                    # sender-oriented pow, so that receiver decodes it differently than request/response pow.. Where the challenge must be verified before verifying POW.
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
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_ttl(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_keepalive(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    tlv["value"] = ""
    return tlv

def response_ces_keepalive_cycle(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_certificate(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    
    certificate_path = ces_params[policy_code]
    f = open(certificate_path, 'r')
    crt = f.read()
    tlv["value"] = crt
    return tlv
 
def response_ces_fw_version(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_session_limit(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_host_ratelimit(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_caces(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv["value"] = ces_params[policy_code]
    return tlv

def response_ces_headersignature(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    tlv["value"] = "Not defined yet"
    return tlv

def response_ces_pow(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    
    value = tlv["value"]
    sender_challenge, ZEROS_IN_RESPONSE = value.split(";")
    h = hashcash.make_token(sender_challenge.encode(), int(ZEROS_IN_RESPONSE))
    pow_resp = str(sender_challenge)+";"+str(h)
    tlv["value"] = pow_resp
    return tlv



def verify_ces_cesid(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
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
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
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
    tlv, code, ces_params, r_cesid = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["r_cesid"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    
    POW_SECRET = "HammadTAKEsII"                                                              # This must be managed later
    ACCEPTABLE_ZEROS = 15
    ch = r_cesid + ":" + POW_SECRET                            # FOR Now, For testing .. Challenge shall be more complicated (to prevent guessing)
    ch_hash = hashlib.sha256(ch.encode()).hexdigest()
    ch_hash = ch_hash[0:16]
    generated_ch = str(ch_hash)
    
    value = tlv['value']
    inbound_challenge, inbound_solution = value.split(";")
    
    if generated_ch != inbound_challenge:
        print("Proof-of-work failed: Inbound challenge is different than sent challenge")
        return False
    else:
        print("Inbound challenge is same as the sent challenge")
        if hashcash.verify_token(inbound_challenge.encode(), inbound_solution) >= ACCEPTABLE_ZEROS:
            print("Proof-of-work verified")
        else:
            print("Failed")
        
    return True






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


