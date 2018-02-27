#!/usr/bin/python3.5

import sys, os
sys.path.append(os.path.join(os.path.dirname('hashcash.py'), 'lib'))
import hashcash
import hashlib
import time
import copy
import random
import json
import CETP
import C2CTransaction
import H2HTransaction
import CETPSecurity

def send_ces_cesid(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]

    
def send_ces_ttl(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ces_certificate(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
        else:
            certificate_path = ces_params[code]
            f = open(certificate_path, 'r')
            crt = f.read()
            new_tlv["value"] = crt
    return [new_tlv]


def send_ces_keepalive(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ces_keepalive_cycle(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ces_fw_version(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ces_session_limit(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ces_host_sessions(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ces_evidence_format(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ces_evidence(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ces_caces(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ces_headersignature(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    if query==True:
        tlv['value'] = ""
    else:
        tlv["value"] = ces_params[code]
    return [tlv]


def send_ces_pow(**kwargs):
    tlv, code, ces_params, query, r_cesid, cetp_security, r_addr = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"], kwargs["r_cesid"], kwargs['cetp_security'], kwargs['r_addr']
    r_ip, r_port = r_addr
    
    if query==True:
        challenge_token = cetp_security.pow_challenge(r_cesid=r_cesid, r_ip=r_ip, r_port=r_port)
        tlv['value'] = challenge_token
    else:
        tlv['value'] = ""
    return [tlv]

def send_ces_terminate(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    if query==True:
        tlv['value'] = ""
    else:
        pass
    return [tlv]

def send_ces_port_filtering(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    if query==True:
        tlv['value'] = ""
    else:
        pass
    return [tlv]

def send_ces_host_filtering(**kwargs):
    tlv, code, ces_params, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    if query==True:
        tlv['value'] = ""
    else:
        pass
    return [tlv]


def response_ces_cesid(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        new_tlv = copy.copy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = "info"
        new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_cesid()", ex)
        return None

def response_ces_ttl(**kwargs):
    tlv, code, ces_params, policy, transaction, cetp_packet = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"], kwargs["transaction"], kwargs["packet"]
    remote_default_dp_ttl = None
    try:
        new_tlv = copy.copy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)

        # Retrieves the ttl value of remote CES
        if 'TLV' in cetp_packet:
            for rtlv in cetp_packet['TLV']:
                if (rtlv['ope']=="info") and (rtlv['group']=="ces") and (rtlv['code']=="ttl"):
                    remote_default_dp_ttl = int(rtlv["value"])
                    break
        
        # Retrieves the TTL of local CES
        ope, cmp, group, code, l_value = policy.get_available_policy(new_tlv)
        local_ttl = int(l_value)
        new_tlv['value'] = local_ttl
        
        # Selects most restrictive of both values as default TTL for H2H sessions between both CES nodes.
        if remote_default_dp_ttl != None:
            if local_ttl < remote_default_dp_ttl:
                negotiated_ttl = local_ttl
            else:
                negotiated_ttl = remote_default_dp_ttl
            
            transaction.add_negotiated_params(code, negotiated_ttl)
            transaction.ttl = negotiated_ttl
            tlv["value"] = negotiated_ttl
    
        new_tlv['ope'] = "info"
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_ttl()", ex)
        return None


def response_ces_keepalive(**kwargs):
    tlv, code, ces_params, policy, transaction = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"], kwargs["transaction"]
    try:
        new_tlv = copy.copy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = "info"
        new_tlv['value'] = ""
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_keepalive()", ex)
        return None


def response_ces_host_filtering(**kwargs):
    try:
        tlv, r_cesid, ces_params, cetp_security, policy, transaction = kwargs["tlv"], kwargs["r_cesid"], kwargs["ces_params"], kwargs["cetp_security"], kwargs["policy"], kwargs["transaction"]
        new_tlv = copy.copy(tlv)
        ope, cmp, group, code, response_value = policy.get_tlv_details(new_tlv)
        filtering_msg = json.loads(response_value)
        filtering_timeout = cesparams["host_filtering_t0"]
        
        print("filtering_msg: ", filtering_msg)
        if "remote_host" in filtering_msg:
            value = filtering_msg["remote_host"]
            keytype = CETPSecurity.KEY_RCES_BlockedHostsByRCES
            cetp_security.register_filtered_domains(keytype, value, key=r_cesid)
            
        elif "local_domain" in filtering_msg:
            l_domain = filtering_msg["local_domain"]
            value = l_domain
            keytype = CETPSecurity.KEY_RCES_UnreachableRCESDestinations
            cetp_security.register_filtered_domains(keytype, value, key=r_cesid)
            
        new_tlv['ope'] = "info"
        new_tlv['value'] = "ACKED"
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_host_filtering()", ex)
        return None


def response_ces_keepalive_cycle(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        new_tlv = copy.copy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = "info"
        new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_keepalive_cycle()", ex)
        return None

def response_ces_certificate(**kwargs):
    tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
    try:
        new_tlv = copy.copy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = "info"
        # tlv["value"] = response_value
    
        certificate_path = ces_params[code]
        f = open(certificate_path, 'r')
        crt = f.read()
        new_tlv["value"] = crt
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_certificate()", ex)
        return None
 
def response_ces_fw_version(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        new_tlv = copy.copy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = "info"
        new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_fw_version()", ex)
        return None

def response_ces_session_limit(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        new_tlv = copy.copy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = "info"
        new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_session_limit()", ex)
        return None

def response_ces_host_sessions(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        new_tlv = copy.copy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = "info"
        new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_host_sessions()", ex)
        return None

def response_ces_caces(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        new_tlv = copy.copy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = "info"
        new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_caces()", ex)
        return None

def response_ces_evidence_format(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        new_tlv = copy.copy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = "info"
        new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_evidence_format()", ex)
        return None

def response_ces_evidence(**kwargs):
    try:
        tlv, r_cesid, ces_params, cetp_security, policy = kwargs["tlv"], kwargs["r_cesid"], kwargs["ces_params"], kwargs["cetp_security"], kwargs["policy"]
        evidence = tlv["value"]
        new_tlv = copy.copy(tlv)
        if cetp_security.process_inbound_evidence(r_cesid, evidence)==None:
            return None
            
        new_tlv['ope'] = "info"
        new_tlv["value"] = "ACKED"                   # ACK the receipt of evidence -- Could be an ACKnowledgment/Error to provided evidence
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_evidence()", ex)
        return None

def response_ces_headersignature(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        new_tlv = copy.copy(tlv)
        new_tlv['ope'] = "info"
        new_tlv["value"] = "Not defined yet"
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ces_headersignature()", ex)
        return None

def response_ces_pow(**kwargs):
    tlv, code, ces_params, cetp_security, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["cetp_security"], kwargs["policy"]
    try:
        sender_challenge = tlv["value"]
        pow_resp = cetp_security.respond_pow(challenge = sender_challenge)
        if pow_resp == None:
            return None
        
        new_tlv = copy.copy(tlv)
        new_tlv['ope'] = "info"
        new_tlv["value"] = pow_resp
        return [new_tlv]
    except Exception as ex:
        print(" Exception in responding to POW challenge. {}".format(ex))
        return None

def verify_ces_cesid(**kwargs):
    try:
        tlv, code, ces_params, r_cesid, transaction, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["r_cesid"], kwargs["transaction"], kwargs['policy']
        ope, cmp, group, code, value = policy.get_tlv_details(tlv)
        
        if cmp =="notAvailable":
            return False
        
        inbound_cesid = value
        l_ope, l_cmp, l_group, l_code, l_value = policy.get_policy_to_enforce(tlv)
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
        tlv, code, ces_params, transaction, session_established, policy, cetp_packet = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["transaction"], kwargs["session_established"], kwargs['policy'], kwargs['packet']
        ope, cmp, group, code, value = policy.get_tlv_details(tlv)
        if cmp =="notAvailable":
            return False
        
        remote_default_dp_ttl = int(value)                                                      # Gets remote-CES ttl
        l_group, l_code, l_cmp, l_ext, allowed_value = policy.get_policy_to_enforce(tlv)        # Gets acceptable limits of ttl value for local-CES  
        min, max = int(allowed_value['min']), int(allowed_value['max'])

        if (remote_default_dp_ttl  < min) or (remote_default_dp_ttl > max):
            print(" Default dp-ttl value is not acceptable")
            return False

        #Compares the DP-TTL value offered by local CES, with remote CES offer, and selects the most restrictive value
        ret = policy.get_available_policy(tlv)
        l_group, l_code, l_cmp, l_ext, l_value = ret
        local_ttl = int(l_value)
        
        if local_ttl < remote_default_dp_ttl:
            transaction.ttl = local_ttl
            transaction.add_negotiated_params(code, local_ttl)
        else:
            transaction.ttl = remote_default_dp_ttl
            transaction.add_negotiated_params(code, remote_default_dp_ttl)
        
        return True
        
    except Exception as ex:
        print("Exception in verify_ces_ttl: ", ex)
        return False

def verify_ces_certificate(**kwargs):
    try:
        tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
        if 'cmp' in tlv:
            if tlv['cmp'] == "notAvailable":
                return False
        return True

    except Exception as ex:
        print("Exception in verify_ces_certificate ", ex)
        return False

def verify_ces_keepalive(**kwargs):
    try:
        tlv, code, ces_params, transaction, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["transaction"], kwargs['policy']
        ope, cmp, group, code, value = policy.get_tlv_details(tlv)
        
        if cmp =="notAvailable":
            return False
        
        value = tlv["value"]
        if value == "":
            #transaction.keepalive_response_time = time.time()
            transaction.transport_health = True
            #transaction.keepalive_response = True
        
        return True
    except Exception as ex:
        print("Exception in verify_ces_keepalive: ", ex)
        return False
        

def verify_ces_keepalive_cycle(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs['policy']
        ope, cmp, group, code, value = policy.get_tlv_details(tlv)
        if cmp =="notAvailable":
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
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True
 
def verify_ces_session_limit(**kwargs):
    tlv, code, ces_params, session_established, transaction, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["session_established"], kwargs["transaction"], kwargs['policy']
    ope, cmp, group, code, value = policy.get_tlv_details(tlv)
    
    try:
        if cmp =="notAvailable":
            return False
        
        remote_ces_session_count = int(value)
        l_ope, l_cmp, l_group, l_code, l_value = policy.get_policy_to_enforce(tlv)
        local_session_limit = int(l_value)
        
        if remote_ces_session_count > local_session_limit:
            print("Invalid # of {} simultaneous H2H transactions.".format(ces_session_limit))
            return False
        
        transaction.add_negotiated_params(code, remote_ces_session_count)
        transaction.remote_session_limit = remote_ces_session_count                # Remote CES shall not forward more than these simultaneous sessions towards this CES
        return True
    
    except Exception as ex:
        print("Exception in verify_ces_session_limit", ex)
        return False

def verify_ces_host_sessions(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        ope, cmp, group, code, value = policy.get_tlv_details(tlv)
        if cmp =="notAvailable":
            return False
        return True
    
    except Exception as ex:
        print("Exception in verifying the verify_ces_host_sessions", ex)
        return False

def verify_ces_host_filtering(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        return True
    except Exception as ex:
        print("Exception in verifying the verify_ces_host_sessions", ex)
        return False


def verify_ces_fw_version(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        ope, cmp, group, code, value = policy.get_tlv_details(tlv)
        if cmp =="notAvailable":
            return False
        
        remote_fw_version = value
        l_ope, l_cmp, l_group, l_code, l_value = policy.get_policy_to_enforce(tlv)
        local_fw_version = l_value
        
        if remote_fw_version != local_fw_version:
            return False
         
        return True
    except Exception as ex:
        print("Exception in verifying the verify_ces_fw_version", ex)
        return False

def verify_ces_evidence(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        ope, cmp, group, code, value = policy.get_tlv_details(tlv)
        if cmp =="notAvailable":
            return False
        evidence = value
        #TBD     - handling of evidence by CETP security module
        
        return True
    except Exception as ex:
        print("Exception in verifying the verify_ces_evidence", ex)
        return False

def verify_ces_evidence_format(**kwargs):
    try:
        tlv, code, ces_params, policy, transaction = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"], kwargs["transaction"]
        ope, cmp, group, code, value = policy.get_tlv_details(tlv)
        if cmp =="notAvailable":
            return False
        
        remote_evidence_format = value
        l_ope, l_cmp, l_group, l_code, l_value  = policy.get_policy_to_enforce(tlv)
        local_evidence_format = l_value
        
        if remote_evidence_format in local_evidence_format:
            transaction.add_negotiated_params(code, remote_evidence_format)
            transaction.evidence_format = remote_evidence_format
            return True
        else:
            return False
        
    except Exception as ex:
        print("Exception in verifying the verify_ces_evidence_format", ex)
        return False


def verify_ces_caces(**kwargs):
    try:
        tlv, code, ces_params, policy = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["policy"]
        ope, cmp, group, code, value = policy.get_tlv_details(tlv)
        if cmp =="notAvailable":
            return False
        
        return True
    except Exception as ex:
        print("Exception in verifying the verify_ces_fw_version", ex)
        return False

def verify_ces_headersignature(**kwargs):
    tlv, code, ces_params = kwargs["tlv"], kwargs["code"], kwargs["ces_params"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ces_pow(**kwargs):
    try:
        tlv, code, ces_params, r_cesid, cetp_security, r_addr = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["r_cesid"], kwargs['cetp_security'], kwargs['r_addr']
        r_ip, r_port = r_addr
    
        if 'cmp' in tlv:
            if tlv['cmp'] == "notAvailable":
                return False
            
        value = tlv['value']
        res = cetp_security.verify_pow(r_cesid=r_cesid, r_ip=r_ip, r_port=r_port, response=value)
        return res
    
    except Exception as ex:
        print("Exception in verifying the verify_ces_fw_version", ex)
        return False


def send_rloc(**kwargs):
    ret_tlvs = []
    tlv, code, query, policy, interfaces = kwargs["tlv"], kwargs["code"], kwargs["query"], kwargs["policy"], kwargs["interfaces"]

    if query==True:
        if 'value' in tlv:
            tlv["value"] = ""
        return [tlv]
    else:
        #Create an offer TLV
        group, code = tlv["group"], tlv["code"]
        ret_list = interfaces.get_interface_rlocs(rloc_type=code)
        for p in range(0, len(ret_list)):
            new_tlv = copy.deepcopy(tlv)
            new_tlv["value"] = ret_list[p]      # pref, order, rloc, iface_alias
            ret_tlvs.append(new_tlv)
        
        return ret_tlvs


def send_payload(**kwargs):
    tlv, code, query, policy, interfaces = kwargs["tlv"], kwargs["code"], kwargs["query"], kwargs["policy"], kwargs["interfaces"]
    if query==True:
        if 'value' in tlv:
            tlv["value"] = ""
    else:
        ret_value = interfaces.get_payload_preference(code)
        if ret_value is not None:
            tlv["value"] = ret_value
        
        if 'value' not in tlv:
            tlv["value"] = ""
    return [tlv]

def response_rloc(**kwargs):
    try:
        ret_tlvs = []
        tlv, policy, interfaces = kwargs["tlv"], kwargs["policy"], kwargs["interfaces"]
        
        new_tlv = copy.deepcopy(tlv)
        ret = policy.get_available_policy(new_tlv)
        ope, cmp, group, code, response_value = ret        
        ret_list = interfaces.get_interface_rlocs(rloc_type=code)             # Value comes from dataplane-interface definitions
        
        if len(ret_list)==0:
            new_tlv = copy.deepcopy(tlv)
            new_tlv["cmp"] = "notAvailable"
            new_tlv['ope'] = 'info'
            ret_tlvs.append(new_tlv)
        else:
            for p in range(0, len(ret_list)):
                new_tlv = copy.deepcopy(tlv)
                new_tlv["value"] = ret_list[p]      # pref, order, rloc, iface_alias
                new_tlv['ope'] = 'info'
                ret_tlvs.append(new_tlv)
            
        return ret_tlvs
        
    except Exception as ex:
        print("Exception in response_rloc(): ", ex)
        return None

def response_payload(**kwargs):
    try:
        tlv, policy, interfaces = kwargs["tlv"], kwargs["policy"], kwargs["interfaces"]
        new_tlv = copy.deepcopy(tlv)
        ret_tlv = policy.get_available_policy(new_tlv)
        new_tlv["ope"] = "info"
        
        if ret_tlv is None:                                 # Meaning that TLV is not supported by CES
            new_tlv["cmp"] = "notAvailable"
            return [new_tlv]
        
        ope, cmp, group, code, response_value = ret_tlv
        
        if cmp=="notAvailable":
            new_tlv["cmp"] = "notAvailable"
        else:
            ret_value    = interfaces.get_payload_preference(code)
            if ret_value is not None:
                new_tlv["value"] = ret_value

            if 'value' not in new_tlv:
                new_tlv["value"] = ""

        return [new_tlv]

    except Exception as ex:
        print("Exception in response_payload(): ", ex)
        return None


def verify_rloc(**kwargs):
    try:
        #Check whether you have this interface.
        tlv, code, policy, interfaces = kwargs["tlv"], kwargs["code"], kwargs["policy"], kwargs["interfaces"]
        h2h_session = False
        
        if 'value' not in tlv:
            return False
        
        rrloc = tlv["value"]
        #print("rrloc: ", rrloc)
        
        if len(rrloc)==0:
            return False
        if type(rrloc)!=type(list()):
            return False
        
        r_pref, r_order, r_rloc, r_iface = rrloc

        if code=="ipv4":
            if not CETP.is_IPv4(r_rloc):
                print(" Address provided is not IPv4")
                return False
        elif code=="ipv6":
            if not CETP.is_IPv6(r_rloc):
                print(" Address provided is not IPv6")
                return False
        elif code=="eth":
            return True
            
        return True
    except Exception as ex:
        print("Exception in verify_rloc()", ex)
        return False

def verify_payload(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        r_payload = code
        if len(r_payload)==0:
            return False
        
        ope, cmp, group, code, response_value = policy.get_available_policy(tlv)
        l_payload = code
        
        if l_payload!=r_payload:
            return False
        
        return True
    except:
        return False

def send_id(**kwargs):
    tlv, code, query, policy = kwargs["tlv"], kwargs["code"], kwargs["query"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]

def response_id(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value           # There could be a check, whether value offered as ID indeed belongs to the sender.
    return [new_tlv]

    
def verify_id(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        ope, cmp, group, code, value = policy.get_tlv_details(tlv)
        
        if cmp =="notAvailable":    return False
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
        print("verify_id(): ", ex)
        return False

def send_ctrl_dstep(**kwargs):
    pass

def send_ctrl_fqdn(**kwargs):
    tlv, code, query, policy = kwargs["tlv"], kwargs["code"], kwargs["query"], kwargs["policy"]
    if query==True:
        if 'value' in tlv:
            tlv["value"] = ""
    else:
        if 'value' not in tlv:
            tlv["value"] = ""
        
    return [tlv]
    
def send_ctrl_certificate(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    new_tlv = copy.copy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ctrl_caep(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    
    new_tlv = copy.copy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ctrl_dp_ttl(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]


def send_ctrl_dp_keepalive_cycle(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"],  kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]

def send_ctrl_qos(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]

def send_ack(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    new_tlv = copy.copy(tlv)
    if query==True:
        val = random.randint(0,2**32)
        if 'value' not in new_tlv:
            new_tlv["value"] = ""
        new_tlv["value"] = val
        
    else:
        val = random.randint(0,2**32)
        if not ('value' in new_tlv):
            new_tlv["value"] = val
    return [new_tlv]

def send_ctrl_os_version(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]

def send_ctrl_policy_caching(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]

def send_ctrl_dp_proto(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["ces_params"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]

def send_ctrl_dp_port(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]

def send_ctrl_dp_ratelimit(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]

def send_ctrl_terminate(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]

def send_ctrl_warning(**kwargs):
    tlv, code, query = kwargs["tlv"], kwargs["code"], kwargs["query"] 
    new_tlv = copy.deepcopy(tlv)
    if query==True:
        if 'value' in new_tlv:
            del new_tlv["value"]
    else:
        if not ('value' in new_tlv):
            new_tlv["value"] = ""
    return [new_tlv]

def response_ctrl_dstep(**kwargs):
    tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return [new_tlv]

def response_ctrl_fqdn(**kwargs):
    tlv, policy = kwargs["tlv"], kwargs["policy"]
    new_tlv = copy.deepcopy(tlv)
    ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
    new_tlv['ope'] = 'info'
    if response_value==None:
        new_tlv["value"] = ""
    else:
        new_tlv["value"] = response_value
    return [new_tlv]

def response_ctrl_certificate(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = 'info'
        if response_value==None:
            new_tlv["value"] = ""
        else:
            new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ctrl_certificate()", ex)
        return None


def response_ctrl_caep(**kwargs):
    try:
        tlv, policy = kwargs["tlv"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        #print("response_value", response_value)
        new_tlv['ope'] = "info"
        if response_value==None:
            new_tlv["value"] = ""
        else:
            new_tlv["value"] = response_value
        return [new_tlv]

    except Exception as ex:
        print("Exception in response_ctrl_caep()", ex)
        return None


def response_ctrl_dp_ttl(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = 'info'
        if response_value==None:
            new_tlv["value"] = ""
        else:
            new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ctrl_dp_ttl()", ex)
        return None


def response_ctrl_dp_keepalive_cycle(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        tlv['ope'] = 'info'
        #tlv["value"] = "some-value"
        return [tlv]
    except Exception as ex:
        print("Exception in response_ctrl_dp_keepalive_cycle()", ex)
        return None
    
def response_ctrl_qos(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = 'info'
        if response_value==None:
            new_tlv["value"] = ""
        else:
            new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ctrl_qos()", ex)
        return None

def response_ack(**kwargs):
    """ Policy-based provisioning of ACK value. """
    try:
        tlv, code, policy, post_c2c = kwargs["tlv"], kwargs["code"], kwargs["policy"], kwargs["post_c2c"]
        new_tlv = copy.deepcopy(tlv)
        
        if post_c2c is not True:
            ret = policy.get_available_policy(new_tlv)
            if ret == None:
                new_tlv["notAvailable"]
        
        new_tlv['ope'] = 'info'
        return [new_tlv]
    
    except Exception as ex:
        print("Exception in response_ack()", ex)
        return None

def response_ctrl_ack(**kwargs):
    """ Policy-based provisioning of ACK value. """
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        new_tlv['ope'] = 'info'
        return [new_tlv]
    
    except Exception as ex:
        print("Exception in response_ctrl_ack()", ex)
        return None

def response_ctrl_os_version(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = 'info'
        if response_value==None:
            new_tlv["value"] = ""
        else:
            new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ctrl_os_version()", ex)
        return None

def response_ctrl_policy_caching(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = 'info'
        if response_value==None:
            new_tlv["value"] = ""
        else:
            new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ctrl_policy_caching()", ex)
        return None


def response_ctrl_dp_proto(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = 'info'
        if response_value==None:
            new_tlv["value"] = ""
        else:
            new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ctrl_dp_proto()", ex)
        return None


def response_ctrl_dp_port(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = 'info'
        if response_value==None:
            new_tlv["value"] = ""
        else:
            new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ctrl_dp_port()", ex)
        return None

def response_ctrl_dp_ratelimit(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        ope, cmp, group, code, response_value = policy.get_available_policy(new_tlv)
        new_tlv['ope'] = 'info'
        if response_value==None:
            new_tlv["value"] = ""
        else:
            new_tlv["value"] = response_value
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ctrl_dp_ratelimit()", ex)
        return None

def response_ctrl_terminate(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        new_tlv['ope'] = 'info'
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ctrl_terminate()", ex)
        return None
    
def response_ctrl_warning(**kwargs):
    try:
        tlv, code, policy = kwargs["tlv"], kwargs["code"], kwargs["policy"]
        new_tlv = copy.deepcopy(tlv)
        new_tlv['ope'] = 'info'
        return [new_tlv]
    except Exception as ex:
        print("Exception in response_ctrl_warning()", ex)
        return None

def verify_ctrl_dstep(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_fqdn(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_certificate(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_caep(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    
    return True

def verify_ctrl_dp_ttl(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_dp_keepalive_cycle(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_qos(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ack(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_os_version(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_policy_caching(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_dp_proto(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_dp_port(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_dp_ratelimit(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_terminate(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True

def verify_ctrl_warning(**kwargs):
    tlv, code = kwargs["tlv"], kwargs["code"]
    if 'cmp' in tlv:
        if tlv['cmp'] == "notAvailable":
            return False
    return True
