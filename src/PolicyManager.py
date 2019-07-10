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
import aiohttp


LOGLEVEL_PolicyCETP         = logging.INFO
LOGLEVEL_PolicyManager      = logging.INFO

class DPConfigurations(object):
    """ To be replaced by actual Class defining the CES Network Interfaces """
    def __init__(self, cesid, ces_params=None, name="Interfaces"):
        self.cesid            = cesid
        self._rlocs_config    = []
        self._payloads_config = {}                    # Pre-populate with preferences.
        self.register_rlocs(ces_params)
        self.register_payloads(ces_params)

    def register_payloads(self, ces_params):
        pref_list = ces_params["payload_preference"]
        for typ in pref_list:
            self._payloads_config[typ] = pref_list[typ]
            
    def get_payload_preference(self, type):
        if type in self._payloads_config:
            return self._payloads_config[type]
        
    def register_rlocs(self, ces_params):
        rlocs_list = ces_params["rloc_preference"]

        for r in rlocs_list:
            (pref, ord, typ, val, interface) = r.split(",")                             # preference, order, rloc_type, address_value, interface_alias
            self._rlocs_config.append( (int(pref), int(ord), typ, val, interface) )
    
    def get_rlocs(self, rloc_type=None, iface=None):
        """ Returns the list of interfaces defined for an RLOC type """
        ret_list = []
        for ifaces in self._rlocs_config:
            pref, order, r_type, rloc, iface = ifaces
            if r_type == rloc_type:
                iface_info = (pref, order, rloc, iface)
                ret_list.append(iface_info)
        
        return ret_list

    def get_registered_rlocs(self):
        self._rlocs_config

    def get_registered_payloads(self):
        self._payloads_config
        


class PolicyManager(object):
    # Loads policies, and keeps policy elements as CETPTLV objects
    def __init__(self, l_cesid, policy_file=None, name="PolicyManager"):
        self._cespolicy       = {}         # key: PolicyCETP()
        self._hostpolicy      = {}         # key: PolicyCETP()
        self.l_cesid          = l_cesid
        self._logger          = logging.getLogger(name)
        self.config_file      = policy_file
        self._logger.setLevel(LOGLEVEL_PolicyManager)             # Within this class, logger will only handle message with this or higher level.    (Otherwise, default value of basicConfig() will apply)
        self.load_policies(self.config_file)
        
    def load_policies(self, config_file):
        try:
            f = open(config_file)
            self._config = json.load(f)
            self._load_CES_policy()
            self._load_host_policy()
        except Exception as ex:
            self._logger.info("Exception in loading policies: {}".format(ex))
            return False
        
    def _load_CES_policy(self):
        for policy in self._config:
            if 'type' in policy:
                if policy['type'] == "cespolicy":
                    policy_type, proto, l_cesid, ces_policy = policy['type'], policy['proto'], policy['cesid'], policy['policy']
                    key = policy_type+":"+proto+":"+l_cesid
                    #print(key)
                    p = PolicyCETP(ces_policy)
                    self._cespolicy[key] = p


    def _load_host_policy(self):
        for policy in self._config:
            if 'type' in policy:
                if policy['type'] == "hostpolicy":
                    policy_type, direction, hostid, host_policy = policy['type'], policy['direction'], policy['fqdn'], policy['policy']
                    key = policy_type +":"+ direction +":"+ hostid
                    #print(key)
                    p = PolicyCETP(host_policy)
                    self._hostpolicy[key] = p
        
    def _get_ces_policy(self):
        return self._cespolicy

    def _get_host_policies(self):
        return self._hostpolicies
    
    def get_ces_policy(self, proto="tls"):
        try:
            policy_type = "cespolicy"
            l_cesid = self.l_cesid
            key = policy_type+":"+proto+":"+l_cesid
            policy = self._cespolicy[key]
            return copy.deepcopy(policy)
        except Exception as ex:
            self._logger.error("Exception '{}' in loading policy for '{}'".format(ex, self.l_cesid))
            return None
    
    def get_host_policy(self, direction, host_id=""):
        """ The search key for host-policy number 0 is 'policy-0' """
        try:
            policy_type = "hostpolicy"
            key = policy_type +":"+ direction +":"+ host_id
            policy = self._hostpolicy[key]
            return policy
        except Exception as ex:
            self._logger.error("No '{}' policy exists for host_id: '{}'".format(direction, host_id))
            return None

    

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
        ret = self.get_tlv_details(tlv)
        i_ope, i_cmp, i_group, i_code, i_value = ret
        found = False
        
        for rtlv in self.available:
            if rtlv["group"] == i_group and rtlv["code"]== i_code:
                found = True
                a_ope, a_cmp, a_group, a_code, a_value = self.get_tlv_details(rtlv)
                return a_ope, a_cmp, a_group, a_code, a_value
        
        if not found:
            return None
    

    def get_policy_to_enforce(self, tlv):
        ope, cmp, group, code, value = self.get_tlv_details(tlv)
        for rtlv in self.required:
            if (rtlv["group"] == tlv["group"]) and (rtlv["code"]==tlv["code"]):
                ope, cmp, group, code, value = self.get_tlv_details(rtlv)
                return ope, cmp, group, code, value
    
    def get_tlv_details(self, tlv):
        ope, cmp, group, code, value = None, None, None, None, None
        if "ope" in tlv:
            ope = tlv["ope"]            
        if "group" in tlv:
            group = tlv["group"]
        if "code" in tlv:
            code  = tlv["code"]
        if "cmp" in tlv:
            cmp   = tlv["cmp"]
        if 'value' in tlv:
            value = tlv['value']
            
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
            # I can check whether policy is notAvailable.
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
    



LOGLEVEL_RESTPolicyClient = logging.INFO

# Aiohttp-based PolicyAgent in CES to retrieve CETP policies from Policy Management System
# Leveraging https://stackoverflow.com/questions/37465816/async-with-in-python-3-4


class RESTPolicyClient(object):
    def __init__(self, loop, spm_url=None, tcp_conn_limit=1, verify_ssl=False, name="RESTPolicyClient"):
        self._loop              = loop
        self.tcp_conn_limit     = tcp_conn_limit
        self.verify_ssl         = verify_ssl
        self.spm_url            = spm_url
        self.policy_cache       = {}
        self._timeout           = 2.0
        self.name               = name
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_RESTPolicyClient)
        self._logger.info("Initiating RESTPolicyClient towards Policy Management System ")
        self._connect()
        
    def _connect(self):
        try:
            tcp_conn            = aiohttp.TCPConnector(limit=self.tcp_conn_limit, loop=self._loop, verify_ssl=self.verify_ssl)
            self.client_session = aiohttp.ClientSession(connector=tcp_conn)
        except Exception as ex:
            self._logger.error("Failure initiating the rest policy client")
            self._logger.error(ex)

    def close(self):
        self.client_session.close()

    def cache_policy(self, key, policy):
        self.policy_cache[key] = policy

    @asyncio.coroutine
    def get_host_policy(self, params=None, timeout=None):
        """ Initiates host-policy query towards SPM """
        if self.spm_url is not None:
            resp = yield from self.get(self.spm_url, params=params, timeout=timeout)
            return resp
        
        return None

    @asyncio.coroutine
    def get(self, url, params=None, timeout=None):
        if timeout is None:
            timeout = self._timeout
        
        with aiohttp.Timeout(timeout):
            resp = None                                     # To handles issues related to connectivity with url
            try:
                resp = yield from self.client_session.get(url, params=params) 
                if resp.status == 200:
                    policy_response = yield from resp.text()
                    #print(policy_response)
                    return policy_response
                else:
                    return None
            
            except Exception as ex:
                # .close() on exception.
                if resp!=None:
                    resp.close()
                self._logger.error("Exception {} in getting REST response: ".format(ex))
            finally:
                if resp!=None:
                    yield from resp.release()               # .release() - returns connection into free connection pool.


    @asyncio.coroutine
    def delete(self, url, timeout=None):
        if timeout is None:
            timeout = self._timeout
            
        with aiohttp.Timeout(timeout):
            resp = yield from self.client_session.delete(url)
            try:
                return (yield from resp.text())
            except Exception as ex:
                resp.close()
                raise ex
            finally:
                yield from resp.release()


def main(policy_client):
    for i in range(0,1):
        #asyncio.ensure_future(policy_client.get('http://www.sarolahti.fi'))
        url = 'http://100.64.254.24/API/host_cetp_user?'
        params = {'lfqdn':"hosta1.cesa.lte.", 'direction': 'EGRESS'}
        asyncio.ensure_future(policy_client.get(url, params=params, timeout=2))
        #asyncio.ensure_future(policy_client.get('http://www.thomas-bayer.com/sqlrest/'))
        #yield from asyncio.sleep(1)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    tcp_conn_limit = 5
    verify_ssl=False
    policy_client = RESTPolicyClient(loop, tcp_conn_limit, verify_ssl=verify_ssl)
    
    try:
        main(policy_client)
        loop.run_forever()
    except KeyboardInterrupt:
        print('Keyboard Interrupt\n')
    finally:
        # Aiohttp resource cleanup
        loop.stop()
        policy_client.close()
        loop.close()

