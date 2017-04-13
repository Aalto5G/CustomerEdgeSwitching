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

class PolicyManager(object):
    # Loads policies, and keeps policy elements as CETPTLV objects
    def __init__(self, policy_file=None, name="PolicyManager"):
        self._cespolicy                     = None         # asPolicyCETP
        self._hostpolicy                    = None         #_asPolicyCETP
        self._logger                        = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_PolicyManager)             # Within this class, logger will only handle message with this or higher level.    (Otherwise, default value of basicConfig() will apply)

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
            #self._logger.info("No reachability policy exists for this host")
            self._logger.info("Assgning a random policy for testing sake")
            return 1

    def _get_host_policies(self):
        return self._hostpolicies
    
    def get_ces_policy(self, proto="tcp", direction="outbound"):
        policy = self._cespolicy[proto][direction]
        return copy.deepcopy(policy)
    
    def get_host_policy(self, index, direction):
        """ The search key for host-policy number 0 is 'policy-0' """
        key="hostpolicy-%d" %index
        return self._hostpolicies[key][direction]

    def _get_copy_host_policy(self, index, direction):
        key="hostpolicy-%d" %index
        policy = self._hostpolicies[key][direction]
        return copy.deepcopy(policy)                            # Shall always return a copy for use. Else, inbound packet would manipulate policy for subsequent interactions 

    def load_CES_policy(self):
        self._cespolicy = {}
        for policy_dict in self._cespolicy_lst:
            for transp, transport_policy in policy_dict.items():
                self._cespolicy[transp] = {}
            
                for dir_dict in transport_policy:
                    for direction, direction_policy in dir_dict.items():
                        self._cespolicy[transp][direction] = PolicyCETP(direction_policy)

    def load_host_policy(self):
        self._hostpolicies = {}
        for pol_dict in self._hostpolicies_lst:
            for host_id, host_policy in pol_dict.items():
                self._hostpolicies[host_id] = {}
                
                for policy_direction, policy in host_policy.items():
                    self._hostpolicies[host_id][policy_direction] = PolicyCETP(policy)
                



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

    def get_tlv_details(self, tlv):
        cmp, ext, group, code = None, None, None, None
        if "group" in tlv:
            group = tlv["group"]
        if "code" in tlv:
            code  = tlv["code"]
        if "cmp" in tlv:
            cmp   = tlv["cmp"]
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
    

