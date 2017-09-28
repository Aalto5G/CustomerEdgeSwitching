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
import CETPH2H
import CETPC2C
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
        #self.ip_fqdn_map = {"127.0.0.1":"raimo_son1.cesa.fi.", "10.0.3.118":"son1.raimo.aalto.lte.", "10.0.3.219":"raimo.aalto.lte.", "10.0.2.15":"son1.raimo.aalto.lte.", "10.0.2.16":"son2.raimo.aalto.lte."}
        self.ip_fqdn_map = {"10.0.3.111":"hosta1.cesa.lte.", "10.0.3.112":"hosta2.cesa.lte.", "10.0.3.121":"hostb1.cesb.lte.", "10.0.3.122":"hostb2.cesb.lte.", \
                            "10.0.3.189":"raimo_son1.cesa.lte.", "10.0.3.53":"raimo.cesb.lte.", "127.0.0.1":"raimo_son1.cesa.lte."}
 
    def ip_to_fqdn_mapping(self, l_ip):
        if l_ip in self.ip_fqdn_map:
            l_fqdn = self.ip_fqdn_map[l_ip]
            return l_fqdn


class FakeInterfaceDefinition(object):
    """ To be replaced by actual Class defining the CES Network Interfaces """
    def __init__(self, cesid, config_file=None, name="Interfaces"):
        self.cesid = cesid
        self._interfaces = []
        self.register_interfaces(config_file)

    def register_interfaces(self, config_file):
        #r  = pref, order, rloc_type, rloc, iface
        r1, r2, r3 = None, None, None
        if self.cesid=="cesa.lte.":
            r1 = 100, 80, "ipv4", "10.0.3.111",         "ISP"
            r2 = 100, 60, "ipv4", "10.1.3.111",         "IXP"
            r3 = 100, 40, "ipv6", "11:22:33:44:55:66:77:01", "ICP"
        else:
            r1 = 100, 80, "ipv4", "10.0.3.121",         "ISP"
            r2 = 100, 60, "ipv4", "10.1.3.121",         "IXP"
            r3 = 100, 40, "ipv6", "11:22:33:44:55:66:77:902", "ICP"
            
        self._interfaces.append(r1)
        self._interfaces.append(r2)
        self._interfaces.append(r3)
                        
    def get_interfaces(self):
        self._interfaces
        
    def get_interface(self, rloc_type=None, iface=None):
        """ Returns the list of interfaces defined for an RLOC type """
        ret_list = []
        for ifaces in self._interfaces:
            pref, order, r_type, rloc, iface = ifaces
            if r_type == rloc_type:
                iface_info = (pref, order, rloc, iface)
                ret_list.append(iface_info)
        
        return ret_list
    
    

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
        self.fqdn_to_policy['hosta1.cesa.lte']   = 1
        self.fqdn_to_policy['hosta2.cesa.lte']   = 1
        self.fqdn_to_policy['hosta3.cesa.lte']   = 2
        self.fqdn_to_policy['hosta4.cesa.lte']   = 0
        self.fqdn_to_policy['hostb1.cesb.lte']   = 1
        self.fqdn_to_policy['hostb2.cesb.lte']   = 2
        self.fqdn_to_policy['hostb3.cesb.lte']   = 0
        self.fqdn_to_policy['hostb4.cesb.lte']   = 1
        self.fqdn_to_policy['hostb5.cesb.lte']   = 0
        self.fqdn_to_policy['hostb6.cesb.lte']   = 1
        self.fqdn_to_policy['hostc1.cesc.lte']   = 2
        self.fqdn_to_policy['hostc2.cesc.lte']   = 0
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
    
    def get_ces_policy(self, proto="tcp"):
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
                host_id="hosta1.cesa.lte."
            
            key = policy_type +":"+ direction +":"+ host_id
            policy = self._hostpolicy[key]
            return policy
            #return copy.deepcopy(policy)
        except Exception as ex:
            raise Exception("Host '{}' has no '{}' policy.".format(host_id, direction))

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

    def get_available_policy(self, tlv):
        ope, cmp, group, code, value = self.get_tlv_details(tlv)
        for rtlv in self.available:
            if (rtlv["group"] == tlv["group"]) and (rtlv["code"]==tlv["code"]):
                ope, cmp, group, code, value = self.get_tlv_details(rtlv)
                return ope, cmp, group, code, value
        return (ope, cmp, group, code, value)

    def get_policy_to_enforce(self, tlv):
        ope, cmp, group, code, value = self.get_tlv_details(tlv)
        for rtlv in self.required:
            if (rtlv["group"] == tlv["group"]) and (rtlv["code"]==tlv["code"]):
                ope, cmp, group, code, value = self.get_tlv_details(rtlv)
                return ope, cmp, group, code, value
    
    def get_tlv_details(self, tlv):
        ope, cmp, group, code, value = None, None, None, None, None
        # group, code, cmp, ext, value
        try:
            if "ope" in tlv:
                group = tlv["ope"]            
            if "group" in tlv:
                group = tlv["group"]
            if "code" in tlv:
                code  = tlv["code"]
            if "cmp" in tlv:
                cmp   = tlv["cmp"]
            if 'value' in tlv:
                value = tlv['value']
                
            return (ope, cmp, group, code, value)
        
        except Exception as ex:
            self._logger.info("Exception: {}".format(ex))
            return (ope, cmp, group, code, value)
    
    def is_mandatory_required(self, tlv):
        ope, cmp, group, code, value = self.get_tlv_details(tlv)
        for pol in self.required:
            if (group in pol["group"]) and (code in pol["code"]):
                if 'cmp' in pol:
                    if pol['cmp']=="optional":
                        return False
                return True
        return True
    
    def has_required(self, tlv):
        ope, cmp, group, code, value = self.get_tlv_details(tlv)
        for pol in self.required:
            if (group in pol["group"]) and (code in pol["code"]):
                return True
        return False
    
    def del_required(self, tlv):
        ope, cmp, group, code, value = self.get_tlv_details(tlv)
        for pol in self.required:
            if (group in pol["group"]) and (code in pol["code"]):
                self.required.remove(pol)
    
    def has_available(self, tlv):
        ope, cmp, group, code, value = self.get_tlv_details(tlv)
        for pol in self.available:
            if (group in pol["group"]) and (code in pol["code"]):
                return True
        return False

    def del_available(self, tlv):
        ope, cmp, group, code, value = self.get_tlv_details(tlv)
        for pol in self.available:
            if (group in pol["group"]) and (code in pol["code"]):
                self.available.remove(pol)

    def get_required(self, tlv=None):
        if tlv != None:
            pass
        else:
            return self.required
    
    def get_offer(self):
        return self.offer
    
    def get_available(self, tlv=None):
        if tlv != None:
            ope, cmp, group, code, value = self.get_tlv_details(tlv)
            for rtlv in self.available:
                if (rtlv["group"] == tlv["group"]) and (rtlv["code"]==tlv["code"]):
                    return rtlv
        else:
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
                if (type(value) != type(str())):
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
    

