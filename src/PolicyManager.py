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
import C2CTransaction
import H2HTransaction
import ocetpLayering
import icetpLayering
import copy


LOGLEVEL_PolicyCETP         = logging.INFO
LOGLEVEL_PolicyManager      = logging.INFO
LOGLEVEL_HostRegister       = logging.INFO


class HostRegister(object):
    def __init__(self, name="HostRegister"):
        self.load_ip_fqdn_mapping()
        self.name       = name
        self._logger    = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_HostRegister)
        
    def load_ip_fqdn_mapping(self):
        """ Acting as a static Identity assignment server to IP addresses """
        self.ip_fqdn_map = {"127.0.0.1":"son1.raimo.aalto.lte.", "10.0.2.15":"son1.raimo.aalto.lte.", "10.0.2.16":"son2.raimo.aalto.lte."}
 
    def ip_to_fqdn_mapping(self, l_ip):
        if l_ip in self.ip_fqdn_map:
            l_fqdn = self.ip_fqdn_map[l_ip]
            return l_fqdn


class PolicyManager(object):
    # Loads policies, and keeps policy elements as CETPTLV objects
    def __init__(self, l_cesid, policy_file=None, name="PolicyManager"):
        self._cespolicy                     = {}         # key: PolicyCETP()
        self._hostpolicy                    = {}         # key: PolicyCETP()
        self.l_cesid                        = l_cesid
        self._logger                        = logging.getLogger(name)
        self.config_file                    = policy_file
        self._logger.setLevel(LOGLEVEL_PolicyManager)             # Within this class, logger will only handle message with this or higher level.    (Otherwise, default value of basicConfig() will apply)
        self.load_policies(self.config_file)
        self.assign_policy_to_host()
        
    def load_policies(self, config_file):
        try:
            f = open(config_file)
            self._config = json.load(f)
            self.load_CES_policy()
            self.load_host_policy()
        except Exception as ex:
            self._logger.info("Exception in loading policies: {}".format(ex))
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
        #Return policy corresponding to a source-id 
        if host_id in self.fqdn_to_policy:
            return self.fqdn_to_policy[host_id]
        else:
            #self._logger.info("No reachability policy exists for this host")
            self._logger.info("Assgning a random policy for testing sake")
            return 1

    def _get_host_policies(self):
        return self._hostpolicies
    
    def get_ces_policy(self, proto="tcp", direction="outbound"):
        policy_type = "cespolicy"
        l_cesid = self.l_cesid
        key = policy_type+":"+proto+":"+l_cesid
        policy = self._cespolicy[key]
        return copy.deepcopy(policy)
    
    def get_host_policy(self, direction, host_id=""):
        """ The search key for host-policy number 0 is 'policy-0' """
        try:
            policy_type = "hostpolicy"
            if host_id=="":
                host_id="hosta1.demo.lte."
            
            key = policy_type +":"+ direction +":"+ host_id
            policy = self._hostpolicy[key]
            return policy
            #return copy.deepcopy(policy)
        except:
            raise Exception("Destination has no {} policy.".format(direction))

    def load_CES_policy(self):
        for policy in self._config:
            if 'type' in policy:
                if policy['type'] == "cespolicy":
                    policy_type, proto, l_cesid, ces_policy = policy['type'], policy['proto'], policy['cesid'], policy['policy']
                    key = policy_type+":"+proto+":"+l_cesid
                    #print(key)
                    p = PolicyCETP(ces_policy)
                    self._cespolicy[key] = p


    def load_host_policy(self):
        for policy in self._config:
            if 'type' in policy:
                if policy['type'] == "hostpolicy":
                    policy_type, direction, hostid, host_policy = policy['type'], policy['direction'], policy['fqdn'], policy['policy']
                    key = policy_type +":"+ direction +":"+ hostid
                    #print(key)
                    p = PolicyCETP(host_policy)
                    self._hostpolicy[key] = p

    

class PolicyCETP(object):
    def __init__(self, policy, name="PolicyCETP"):
        self.policy         = policy
        self._logger        = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_PolicyCETP)             # Within this class, logger will only handle message with this or higher level.    (Otherwise, default value of basicConfig() will apply)
        self._initialize()
        
    def __copy__(self):
        self._logger.debug("Shallow copying the python policy object.")
        return PolicyCETP(self.policy)
        
    def __deepcopy__(self, memo):
        """
        To copy the policy object by value.. Deepcopy() is useful for compound objects (that contain other objects, like lists or class instances in them)
        Reference implementation: https://pymotw.com/2/copy/
        """
        self._logger.debug("Deep copying the python policy object.")
        not_there = []
        existing = memo.get(self, not_there)
        if existing is not not_there:
            return existing
        
        dup = PolicyCETP(copy.deepcopy(self.policy, memo))
        memo[self] = dup
        return dup
    
    def _initialize(self):
        if "request" in self.policy:
            self.required = self.policy["request"]
        if "offer" in self.policy:
            self.offer = self.policy["offer"]
        if "available" in self.policy:
            self.available = self.policy["available"]
        # setting value for CETP can be handled in CETP transaction module

    def get_response_policy(self, tlv):
        group, code, cmp, ext, value = self.get_tlv_details(tlv)
        for rtlv in self.available:
            if (rtlv["group"] == tlv["group"]) and (rtlv["code"]==tlv["code"]):
                group, code, cmp, ext, value = self.get_tlv_details(rtlv)
                return group, code, cmp, ext, value

    def get_policy_to_enforce(self, tlv):
        group, code, cmp, ext, value = self.get_tlv_details(tlv)
        for rtlv in self.required:
            if (rtlv["group"] == tlv["group"]) and (rtlv["code"]==tlv["code"]):
                group, code, cmp, ext, value = self.get_tlv_details(rtlv)
                return group, code, cmp, ext, value
    
    def get_tlv_details(self, tlv):
        group, code, cmp, ext, value = None, None, None, None, None
        try:
            if "group" in tlv:
                group = tlv["group"]
            if "code" in tlv:
                code  = tlv["code"]
            if "cmp" in tlv:
                cmp   = tlv["cmp"]
            if 'value' in tlv:
                value = tlv['value']
                
            return (group, code, cmp, ext, value)
        
        except Exception as ex:
            self._logger.info("Exception: {}".format(ex))
            return (group, code, cmp, ext, value)
    
    def is_mandatory_required(self, tlv):
        group, code, cmp, ext, value = self.get_tlv_details(tlv)
        for pol in self.required:
            if (group in pol["group"]) and (code in pol["code"]):
                if 'cmp' in pol:
                    if pol['cmp']=="optional":
                        return False
                return True
        return True
    
    def has_required(self, tlv):
        group, code, cmp, ext, value = self.get_tlv_details(tlv)
        for pol in self.required:
            if (group in pol["group"]) and (code in pol["code"]):
                return True
        return False
    
    def del_required(self, tlv):
        group, code, cmp, ext, value = self.get_tlv_details(tlv)
        for pol in self.required:
            if (group in pol["group"]) and (code in pol["code"]):
                self.required.remove(pol)
    
    def has_available(self, tlv):
        group, code, cmp, ext, value = self.get_tlv_details(tlv)
        for pol in self.available:
            if (group in pol["group"]) and (code in pol["code"]):
                return True
        return False

    def del_available(self, tlv):
        group, code, cmp, ext, value = self.get_tlv_details(tlv)
        for pol in self.available:
            if (group in pol["group"]) and (code in pol["code"]):
                self.available.remove(pol)

    def get_required(self):
        return self.required
    
    def get_offer(self):
        return self.offer
    
    def get_available(self):
        return self.available                   # Store as CETPTLV field with additional possibility of value field
    
    def get_tlv_response(self, tlv):
        for atlv in self.get_available():
            if (atlv["group"]==tlv["group"]) and (atlv['code'] == tlv['code']):
                if 'value' in atlv:
                    policy_value = atlv["value"]
                    return policy_value
    
    def set_required(self, tlv):
        return tlv

    def set_offer(self, tlv):
        return tlv
    
    def set_available(self, tlv):
        return tlv
    
    def get_group_code(self, pol_vector):
        s=""
        for pol in pol_vector:
            pol_rep = ""
            if 'cmp' in pol:
                gp, code, cmp = pol['group'], pol['code'], pol['cmp']
                pol_rep = gp+"."+code+"."+cmp
            elif 'value' in pol:
                gp, code, value = pol['group'], pol['code'], pol['value']
                if (type(value) == type(list())) or (type(value) == type(dict())):
                    pol_rep = gp+"."+code
                else:
                    pol_rep = gp+"."+code+": "+value
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
                s = self.get_group_code(pol_vector)
                str_policy += it+ ": " + s +"\n"
        return str_policy
    
    def __str__(self):
        return self.show_policy()

    def __repr__(self):
        return self.show_policy()
    

