#!/usr/bin/python3.5

import CETP
import C2CTransaction
import H2HTransaction
import sys, os
sys.path.append(os.path.join(os.path.dirname('hashcash.py'), 'lib'))
import hashcash
import hashlib
import time
import copy


def send_ces_cesid(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv

    
def send_ces_ttl(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


def send_ces_certificate(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
        else:
            certificate_path = ces_params[policy_code]
            f = open(certificate_path, 'r')
            crt = f.read()
            new_tlv["value"] = crt
    return new_tlv


def send_ces_keepalive(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


def send_ces_keepalive_cycle(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


def send_ces_fw_version(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


def send_ces_session_limit(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


def send_ces_host_sessions(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


def send_ces_evidence_format(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


def send_ces_evidence(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


def send_ces_caces(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return new_tlv


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


def response_to_wrong_query(tlv):
    tlv["code"] = "terminate"
    return tlv

def response_ces_cesid(**kwargs):
    tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.copy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = "info"
    new_tlv["value"] = response_value
    return new_tlv

def response_ces_ttl(**kwargs):
    tlv, code, ces_params, policy, transaction, cetp_packet = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"], kwargs["transaction"], kwargs["packet"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    remote_default_dp_ttl = None
    try:
        new_tlv = copy.copy(tlv)
        group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)

        # Retrieves the ttl value of remote CES
        if 'TLV' in cetp_packet:
            for rtlv in cetp_packet['TLV']:
                if (rtlv['ope']=="info") and (rtlv['group']=="ces") and (rtlv['code']=="ttl"):
                    remote_default_dp_ttl = int(rtlv["value"])
                    break
        
        # Retrieves the TTL of local CES
        group, code, cmp, ext, l_value = policy.get_available_policy(new_tlv)
        local_ttl = int(l_value)
        new_tlv['value'] = local_ttl
        
        # Selects most restrictive of both values as default TTL for H2H sessions between both CES nodes.
        if remote_default_dp_ttl != None:
            if local_ttl < remote_default_dp_ttl:
                negotiated_ttl = local_ttl
            else:
                negotiated_ttl = remote_default_dp_ttl
                
            transaction.ttl = negotiated_ttl
            tlv["value"] = negotiated_ttl
    
        new_tlv['ope'] = "info"
        return new_tlv
    except:
        print("Exception in response_ces_ttl()")
        return None


def response_ces_keepalive(**kwargs):
    tlv, code, ces_params, policy, transaction = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"], kwargs["transaction"]
    try:
        new_tlv = copy.copy(tlv)
        group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
        transaction.last_seen = time.time()
        new_tlv['ope'] = "info"
        new_tlv['value'] = ""
        return new_tlv
    except Exception as ex:
        print(ex)
        return response_to_wrong_query(tlv)

def response_ces_keepalive_cycle(**kwargs):
    tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.copy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = "info"
    new_tlv["value"] = response_value
    return new_tlv

def response_ces_certificate(**kwargs):
    tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
    try:
        new_tlv = copy.copy(tlv)
        group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        new_tlv['ope'] = "info"
        # tlv["value"] = response_value
    
        certificate_path = ces_params[policy_code]
        f = open(certificate_path, 'r')
        crt = f.read()
        new_tlv["value"] = crt
        return new_tlv
    except Exception as ex:
        print(ex)
        return tlv
 
def response_ces_fw_version(**kwargs):
    tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.copy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = "info"
    new_tlv["value"] = response_value
    return new_tlv

def response_ces_session_limit(**kwargs):
    tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.copy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = "info"
    new_tlv["value"] = response_value
    return new_tlv

def response_ces_host_sessions(**kwargs):
    tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.copy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = "info"
    new_tlv["value"] = response_value
    return new_tlv

def response_ces_caces(**kwargs):
    tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.copy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = "info"
    new_tlv["value"] = response_value
    return new_tlv

def response_ces_evidence_format(**kwargs):
    tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.copy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = "info"
    new_tlv["value"] = response_value
    return new_tlv

def response_ces_evidence(**kwargs):
    tlv, code, ces_params, cetp_security, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["cetp_security"], kwargs["ces_policy"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    evidence = tlv["value"]
    new_tlv = copy.copy(tlv)
    resp = cetp_security.process_evidence(r_cesid, evidence)
    new_tlv['ope'] = "info"
    new_tlv["value"] = response_value                   # Could be an ACKnowledgment/Error to provided evidence
    return new_tlv

def response_ces_headersignature(**kwargs):
    tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    new_tlv = copy.copy(tlv)
    new_tlv['ope'] = "info"
    new_tlv["value"] = "Not defined yet"
    return new_tlv

def response_ces_pow(**kwargs):
    tlv, code, ces_params, cetp_security, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["cetp_security"], kwargs["ces_policy"]
    try:
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        sender_challenge = tlv["value"]
        pow_resp = cetp_security.respond_pow(challenge = sender_challenge)
        new_tlv = copy.copy(tlv)
        new_tlv['ope'] = "info"
        new_tlv["value"] = pow_resp
        return new_tlv
    except Exception as msg:
        print(" Exception in responding to POW challenge.")
        return tlv

def verify_ces_cesid(**kwargs):
    try:
        tlv, code, ces_params, r_cesid, transaction, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["r_cesid"], kwargs["transaction"], kwargs['ces_policy']
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        group, code, cmp, ext, value = policy.get_tlv_details(tlv)
        
        if cmp =="NotAvailable":
            return False
        
        inbound_cesid = value
        l_group, l_code, l_cmp, l_ext, l_value = policy.get_policy_to_enforce(tlv)
        trusted_cesids = l_value
        
        if (r_cesid == tlv["value"]) and (inbound_cesid in trusted_cesids):
            return True
        else:
            return False
    except Exception as ex:
        print("Exception in verifying remote cesid: ", ex)
        return False
    

def verify_ces_ttl(**kwargs):
    try:
        tlv, code, ces_params, transaction, session_established, policy, cetp_packet = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["transaction"], kwargs["session_established"], kwargs['ces_policy'], kwargs['packet']
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        group, code, cmp, ext, value = policy.get_tlv_details(tlv)
        if cmp =="NotAvailable":
            return False
        
        remote_default_dp_ttl = int(value)                                                      # Gets remote-CES ttl
        l_group, l_code, l_cmp, l_ext, allowed_value = policy.get_policy_to_enforce(tlv)        # Gets acceptable limits of ttl value for local-CES  
        min, max = int(allowed_value['min']), int(allowed_value['max'])

        if (remote_default_dp_ttl  < min) or (remote_default_dp_ttl > max):
            print(" Default dp-ttl value is not acceptable")
            return False

        #Compares the DP-TTL value offered by local CES, with remote CES offer, and selects the most restrictive value
        group, code, cmp, ext, l_value = policy.get_available_policy(tlv)
        local_ttl = int(l_value)
        
        if local_ttl < remote_default_dp_ttl:
            transaction.ttl = local_ttl
        else:
            transaction.ttl = remote_default_dp_ttl
        
        return True
        
    except Exception as ex:
        print("Exception in verify_ces_ttl: ", ex)
        return False

def verify_ces_certificate(**kwargs):
    try:
        tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        if 'cmp' in tlv:
            if tlv['cmp'] == "NotAvailable":
                return False
        return True

    except Exception as ex:
        print("Exception in verify_ces_certificate ", ex)
        return False

def verify_ces_keepalive(**kwargs):
    try:
        tlv, code, ces_params, transaction, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["transaction"], kwargs['ces_policy']
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        group, code, cmp, ext, value = policy.get_tlv_details(tlv)
        
        if cmp =="NotAvailable":
            return False
        
        value = tlv["value"]
        if value == "":
            transaction.keepalive_response_time = time.time()
            transaction.health_report = True
            transaction.keepalive_response = True
        
        return True
    except Exception as ex:
        print("Exception in verify_ces_keepalive: ", ex)
        return False
        

def verify_ces_keepalive_cycle(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs['ces_policy']
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        group, code, cmp, ext, value = policy.get_tlv_details(tlv)
        if cmp =="NotAvailable":
            return False
        
        keepalive_cycle = int(value)
        if keepalive_cycle < 2:
            print("Invalid/Unacceptable value of the keepalive cycle.")
            return False
        return True
    
    except Exception as ex:
        print("Exception in verifying the ces_keepalive_cycle", ex)
        return False


def verify_ces_certificate(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True
 
def verify_ces_session_limit(**kwargs):
    tlv, code, ces_params, session_established, transaction, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["session_established"], kwargs["transaction"], kwargs['ces_policy']
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    group, code, cmp, ext, value = policy.get_tlv_details(tlv)
    
    try:
        if cmp =="NotAvailable":
            return False
        
        remote_ces_session_count = int(value)
        l_group, l_code, l_cmp, l_ext, l_value = policy.get_policy_to_enforce(tlv)
        local_session_limit = int(l_value)
        
        if remote_ces_session_count > local_session_limit:
            print("Invalid # of {} simultaneous H2H transactions.".format(ces_session_limit))
            return False

        transaction.remote_session_limit = remote_ces_session_count                # Remote CES shall not forward more than these simultaneous sessions towards this CES
        return True
    
    except Exception as ex:
        print("Exception in verify_ces_session_limit", ex)
        return False

def verify_ces_host_sessions(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        group, code, cmp, ext, value = policy.get_tlv_details(tlv)
        if cmp =="NotAvailable":
            return False
        return True
    
    except Exception as ex:
        print("Exception in verifying the verify_ces_host_sessions", ex)
        return False

def verify_ces_fw_version(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        group, code, cmp, ext, value = policy.get_tlv_details(tlv)
        if cmp =="NotAvailable":
            return False
        
        remote_fw_version = value
        l_group, l_code, l_cmp, l_ext, l_value = policy.get_policy_to_enforce(tlv)
        local_fw_version = l_value
        
        if remote_fw_version != local_fw_version:
            return False
         
        return True
    except Exception as ex:
        print("Exception in verifying the verify_ces_fw_version", ex)
        return False

def verify_ces_evidence(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        group, code, cmp, ext, value = policy.get_tlv_details(tlv)
        if cmp =="NotAvailable":
            return False
        evidence = value
        #TBD     - handling of evidence by CETP security module
        
        return True
    except Exception as ex:
        print("Exception in verifying the verify_ces_evidence", ex)
        return False

def verify_ces_evidence_format(**kwargs):
    try:
        tlv, code, ces_params, policy, transaction = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"], kwargs["transaction"]
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        group, code, cmp, ext, value = policy.get_tlv_details(tlv)
        if cmp =="NotAvailable":
            return False
        
        remote_evidence_format = value
        l_group, l_code, l_cmp, l_ext, l_value  = policy.get_policy_to_enforce(tlv)
        local_evidence_format = l_value
        
        if remote_evidence_format in local_evidence_format:
            transaction.evidence_format = remote_evidence_format
            return True
        else:
            return False
        
    except Exception as ex:
        print("Exception in verifying the verify_ces_evidence_format", ex)
        return False


def verify_ces_caces(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["ces_policy"]
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        group, code, cmp, ext, value = policy.get_tlv_details(tlv)
        if cmp =="NotAvailable":
            return False
        
        return True
    except Exception as ex:
        print("Exception in verifying the verify_ces_fw_version", ex)
        return False

def verify_ces_headersignature(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    policy_code = CETP.CES_CODE_TO_POLICY[code]
    if 'cmp' in tlv:
        if tlv['cmp'] == "NotAvailable":
            return False
    return True

def verify_ces_pow(**kwargs):
    try:
        tlv, code, ces_params, r_cesid, cetp_security, r_addr = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["r_cesid"], kwargs['cetp_security'], kwargs['r_addr']
        policy_code = CETP.CES_CODE_TO_POLICY[code]
        r_ip, r_port = r_addr
    
        if 'cmp' in tlv:
            if tlv['cmp'] == "NotAvailable":
                return False
            
        value = tlv['value']
        res = cetp_security.verify_pow(r_cesid=r_cesid, r_ip=r_ip, r_port=r_port, response=value)
        return res
    
    except Exception as ex:
        print("Exception in verifying the verify_ces_fw_version", ex)
        return False


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
    tlv, policy = kwargs["tlv"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return new_tlv

def response_payload(**kwargs):
    tlv, policy = kwargs["tlv"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return new_tlv


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
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return new_tlv

    
def verify_id(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        group, code, cmp, ext, value = policy.get_tlv_details(tlv)
        
        if cmp =="NotAvailable":    return False
        inbound_id = value
        group, code, cmp, ext, allowed_value = policy.get_policy_to_enforce(tlv)
        #print(allowed_value)
        #print(inbound_id)
        
        if allowed_value==None:
            return True
        
        if len(allowed_value)==0:
            return True
        else:
            if inbound_id in allowed_value:
                return True
        
        return False
        
    except Exception as ex:
        print(ex)
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
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return new_tlv

def response_ctrl_fqdn(**kwargs):
    tlv, policy = kwargs["tlv"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return new_tlv

def response_ctrl_certificate(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return new_tlv

def response_ctrl_caep(**kwargs):
    tlv, policy = kwargs["tlv"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    #print("response_value", response_value)
    new_tlv['ope'] = "info"
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return new_tlv

def response_ctrl_dp_rlocs(**kwargs):
    tlv, policy = kwargs["tlv"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return new_tlv

def response_ctrl_dp_ttl(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return new_tlv

def response_ctrl_dp_keepalive_cycle(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    policy_code = CETP.CONTROL_CODES[code]
    tlv['ope'] = 'info'
    #tlv["value"] = "some-value"
    return tlv

def response_ctrl_qos(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    
    return new_tlv


def response_ctrl_ack(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return new_tlv

    
def response_ctrl_os_version(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return new_tlv

def response_ctrl_policy_caching(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    
    return new_tlv


def response_ctrl_dp_proto(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    
    return new_tlv

def response_ctrl_dp_port(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    
    return new_tlv

def response_ctrl_dp_ratelimit(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    group, code, cmp, ext, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    
    return new_tlv

def response_ctrl_terminate(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    new_tlv['ope'] = 'info'
    return new_tlv

def response_ctrl_warning(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    new_tlv['ope'] = 'info'
    return new_tlv

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



