#!/usr/bin/python3.5

"""
BSD 3-Clause License

Copyright (c) 2019, Hammad Kabir, Aalto University, Finland
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

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
import string
import sys, os
sys.path.append(os.path.join(os.path.dirname('hashcash.py'), 'lib'))
import hashcash
import hashlib
import cetpManager
import C2CTransaction
import H2HTransaction
import CETPH2H
import CETPC2C
import connection

LOGLEVEL_CETPSecurity       = logging.INFO

#Local CES record
KEY_BlacklistedLHosts                       = 0
KEY_BlacklistedRHosts                       = 1
KEY_DisabledLHosts                          = 2

#Local CES record
KEY_LocalHosts_Inbound_Disabled             = 10
KEY_LocalHosts_Outbound_Disabled            = 11

#Local CES record
KEY_RemoteHosts_inbound_Disabled            = 12
KEY_RemoteHosts_outbound_Disabled           = 13


#Remote CES specific record    (Local-view)
KEY_LCES_BlockedHostsOfRCES                 = 3
KEY_LCES_UnreachableDestinationsForRCES     = 4
KEY_LCES_FilteredSourcesTowardsRCES         = 14

#Remote CES specific record   (Remote view)            - Executed on request of remote CES, and recorded against remote CES
KEY_RCES_BlockedHostsByRCES                 = 5
KEY_RCES_UnreachableRCESDestinations        = 6
KEY_RCES_FilteredSourcesFromRCES            = 15

KEY_Evidence_against_RCES                   = 1
KEY_Evidence_against_RCES_Host              = 2
KEY_Evidence_Reported_by_RCES               = 3
KEY_Evidence_Reported_against_host          = 4


class CETPSecurity:
    def __init__(self, loop, conn_table, ces_params, name="CETPSecurity"):
        self.evidences_against_localhosts    = {}                            # {host-fqdn: [evidence]}
        self.evidences_against_remotehosts   = {}
        self.evidences_against_remoteces     = {}
        self.misbehavior_record              = {}
        self.reporting_ces                   = {}
        self.filtered_domains                = {}
        self.unverifiable_cetp_addrs         = []
        self.unverifiable_cetp_senders       = []
        self.conn_table                      = conn_table
        self.ces_params                      = ces_params
        self._loop                           = loop
        self._logger                         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPSecurity)
        self._initialize_pow()
        # CETPSecurity shall have specific 'CES-to-CES' view & aggregated view of all 'CES-to-CES' interactions


    def register_unverifiable_cetp_sender(self, ip_addr):
        if not self.is_unverifiable_cetp_sender(ip_addr):
            key = ip_addr
            self.unverifiable_cetp_senders.append(key)
            self._loop.call_later(60, self.unregister_unverifiable_cetp_sender, ip_addr)
        
    def unregister_unverifiable_cetp_sender(self, ip_addr):
        if self.is_unverifiable_cetp_sender(ip_addr):
            key = ip_addr
            self.unverifiable_cetp_senders.remove(key)

    def is_unverifiable_cetp_sender(self, ip_addr):
        key = ip_addr
        return key in self.unverifiable_cetp_senders

    def register_unreachable_cetp_addr(self, ip_addr, port, proto):
        if not self.is_unreachable_cetp(ip_addr, port, proto):
            key = (ip_addr, port, proto)
            self.unverifiable_cetp_addrs.append(key)
            self._loop.call_later(30, self.unregister_unreachable_cetp_addr, ip_addr, port, proto)

    def unregister_unreachable_cetp_addr(self, ip_addr, port, proto):
        if self.is_unreachable_cetp(ip_addr, port, proto):
            key = (ip_addr, port, proto)
            self.unverifiable_cetp_addrs.remove(key)
            
    def is_unreachable_cetp(self, ip_addr, port, proto):
        key = (ip_addr, port, proto)
        return key in self.unverifiable_cetp_addrs


    def register_filtered_domains(self, keytype, value, key=None, timeout=None):
        try:
            self.add_filtered_domains(keytype, value, key)
            if timeout is None:
                timeout = self.ces_params["host_filtering_t0"]
            
            self._loop.call_later(timeout, self.remove_filtered_domains, keytype, value, key)

        except Exception as ex:
            self._logger.error("Exception '{}' in 'register_filtered_domains()' ".format(ex))

    
    def add_filtered_domains(self, keytype, value, key=None):
        if keytype in [KEY_RCES_BlockedHostsByRCES, KEY_LCES_BlockedHostsOfRCES, KEY_RCES_UnreachableRCESDestinations, KEY_LCES_UnreachableDestinationsForRCES, KEY_LCES_FilteredSourcesTowardsRCES]:                
            if keytype not in self.filtered_domains:
                self.filtered_domains[keytype] = {}
                self.filtered_domains[keytype][key]=[value]
            else:
                filtered_domains = self.filtered_domains[keytype][key]
                filtered_domains.append(value)
        else:
            if keytype not in self.filtered_domains:
                self.filtered_domains[keytype] = [value]
            else:
                filtered_domains = self.filtered_domains[keytype]
                filtered_domains.append(value)
                
    def remove_filtered_domains(self, keytype, value, key=None):
        if keytype in self.filtered_domains:
            if key==None:
                filtered_domains = self.filtered_domains[keytype]
                
                if value in filtered_domains:
                    filtered_domains.remove(value)
                    if len(filtered_domains)==0:
                        del self.filtered_domains[keytype]
                    
            else:
                if key in self.filtered_domains[keytype]:
                    filtered_domains = self.filtered_domains[keytype][key]
                    if value in filtered_domains:
                        filtered_domains.remove(value)
                        
                        if len(filtered_domains)==0:
                            del self.filtered_domains[keytype][key]
                            
                        if len(self.filtered_domains[keytype])==0:
                            del self.filtered_domains[keytype]
            
            #print("After deletion: ", self.filtered_domains)


    def has_filtered_domain(self, keytype, value, key=None):
        try:
            if keytype in self.filtered_domains:
                if key==None:
                    if value in self.filtered_domains[keytype]:
                        return True
                else:
                    if key in self.filtered_domains[keytype]:
                        if value in self.filtered_domains[keytype][key]:
                            return True
            return False
        except Exception as ex:
            self._logger.warning("Exception '{}'".format(ex))
            return False
        
    def get_filtered_domains(self, keytype, key=None):
        try:
            if key!=None:
                filtered_domains = self.filtered_domains[keytype][key]
            else:
                filtered_domains = self.filtered_domains[keytype]
            return filtered_domains
        except Exception as ex:
            self._logger.info("Exception '{}'".format(ex))
            return None
    
    def record_evidence(self, keytype, key_ces, key_host, evidence):
        """ Record misbehavior evidences """
        if keytype in [KEY_Evidence_against_RCES_Host, KEY_Evidence_Reported_by_RCES]:
            if keytype not in self.misbehavior_record:
                self.misbehavior_record[keytype] = {}
                self.misbehavior_record[keytype][key_ces]
                self.misbehavior_record[keytype][key_ces][key_host]
                self.misbehavior_record[keytype][key_ces][key_host] = [evidence]
            else:
                filtered_domains = self.filtered_domains[keytype][key_ces]
                filtered_domains.append(value)
        else:
            if keytype not in self.filtered_domains:
                self.filtered_domains[keytype] = [value]
            else:
                filtered_domains = self.filtered_domains[keytype]
                filtered_domains.append(value)


    def process_inbound_evidence(self, r_cesid, evidence):
        """ Processes the evidence received from 'r_cesid' """
        try:
            outcome = self.check_format_compliance(evidence)
            if outcome == False:    return None
            session_tags, misbehavior = outcome
            inbound_sstag, inbound_dstag = session_tags[0], session_tags[1]
            sstag, dstag = inbound_dstag, inbound_sstag
            key     = (connection.KEY_MAP_CES_TO_CES, sstag, dstag)
            
            if self.conn_table.has(key):
                conn     = self.conn_table.get(key)                
                l_hostid = conn.remoteFQDN                                      # For inbound evidence, the destination-domain is the local host
                self.add_evidence_against_local_hosts(l_hostid, misbehavior)
                self.record_reporting_ces_node(r_cesid, misbehavior)
                # Additionally, it is possibile to trigger some action (i.e. terminate flow etc.) upon receiving evidence against a host (or its session)
                return True

        except Exception as ex:
            self._logger.warning("Exception '{}' in processing inbound evidence".format(ex))
        return None
            

    def add_evidence_against_local_hosts(self, l_hostid, evidence):
        if l_hostid in self.evidences_against_localhosts:
            evidence_list = self.evidences_against_localhosts[l_hostid]
            evidence_list.append(evidence)
        else:
            self.evidences_against_localhosts[l_hostid] = [evidence]
        #print(self.evidences_against_localhosts)

    def record_reporting_ces_node(self, r_cesid, evidence):
        if r_cesid in self.reporting_ces:
            evidence_list = self.reporting_ces[r_cesid]
            evidence_list.append(evidence)
        else:
            self.reporting_ces[r_cesid] = [evidence]
        #print(self.reporting_ces)            
        

    
    def check_format_compliance(self, evidence):
        """ Checks whether the provided evidence complies to negotiated format, e.g. IOC evidence exchange format. """
        try:
            evd = json.loads(evidence)
            session_tags, misbehavior = evd["h2h_session"], evd["misbehavior"]
            return (session_tags, misbehavior)
        except:
            return False
    
    def check_misbehavior_threshold(self, l_hostid):
        """ Checks whether the aggregated evidences against an FQDN have exceeded threshold. """
        return False

    def record_misbehavior_evidence(self, r_cesid, r_hostid, evidence):
        self.add_evidence_against_remote_host(r_cesid, r_hostid, evidence)
        self.add_evidence_against_remote_ces(r_cesid, evidence)
    
    def add_evidence_against_remote_host(self, r_cesid, r_hostid, evidence):
        if r_hostid in self.evidences_against_remotehosts:
            evidence_list = self.evidences_against_remotehosts[r_hostid]
            evidence_list.append(evidence)
        else:
            self.evidences_against_remotehosts[r_hostid] = [evidence]
        #print(self.evidences_against_remotehosts)
        
    def add_evidence_against_remote_ces(self, r_cesid, evidence):
        if r_cesid in self.evidences_against_remoteces:
            evidence_list = self.evidences_against_remoteces[r_cesid]
            evidence_list.append(evidence)
        else:
            self.evidences_against_remoteces[r_cesid] = [evidence]
        #print(self.evidences_against_remoteces)
            
    
    def check_aggregation_threshold(self, host_fqdn):
        """ Checks if num. of evidences against host-fqdn have reached a threshold 
        Also includes the number of reporting entities in decision making, & proportionates accordingly.    - Policy controlled numbers.
        """
        pass

    def dataplane_evidence(self, session_tags, evidence):
        """ Gets evidence of malware/misbehavior from Data-plane against session-tags, which must be translated to remote-fqdn """
        pass
    
    def evidence_against_remotehost(self, r_cesid, r_fqdn, evidence):
        """ Aggregates evidence of malware/misbheavior observed by Data-plane against remote-host fqdn """
        pass

    def c2c_signalling_evidence(self, r_cesid, evidence):
        """ Non-compliance observed at CETP-C2C signalling level from remote-CES 
        Blacklisted host appears in cetp-signalling, traffic towards a restricted/forbidden domain, Exceeding session limits.
        For minor-misbehaviors, count evidences towards 'r_cesid'
        """
        pass
    
    def report_to_local_ces_admin(self):
        """ Reports local-CES of a misbehaving local-host, remote-host, or remote-CES """
        pass
    
    def evidence_against_remote_ces(self, r_cesid):
        """ Aggregates number (and severity) of non-compliance observed from remote-CES """
        pass
    
    def report_evidence_to_remote_CES(self, r_cesid, evidence):
        """ Sends evidence report to a remote CES for one of its served-hosts """
        pass
    
    def trigger_terminate(self, r_cesid):
        """ Triggers closing of CETP-signalling channel/channels towards remote-CES """
        pass
    
    
    """ Function for dynamic management of POW  """
    
    def _initialize_pow(self):
        """ Initializing parameters for POW """
        self.acceptable_zeros               = 12                            # Difficult level - could be policy_controlled
        self.secret_lifespan                = 240
        self.pow_secret_management          = {}
        self.pow_transition_status          = (False, time.time())
        self.load_secret()
        
    def load_secret(self):
        secret_length                       = random.randint(21,32)
        self.pow_secret                     = ''.join(random.choice(string.ascii_lowercase) for i in range(secret_length))
        self.pow_secret_management[self.pow_secret] = time.time()
        
    def get_pow_secret(self):
        self.update_pow_secret()
        return self.pow_secret
    
    def pow_challenge(self, **kwargs):
        try:
            r_ip, r_port, r_cesid = kwargs['r_ip'], kwargs['r_port'], kwargs['r_cesid']
            pow_secret = self.get_pow_secret()
            ch = r_ip + ":" + str(r_port) + ":" + r_cesid + ":" + pow_secret
            ch_hash = hashlib.sha256(ch.encode()).hexdigest()
            ch_hash = ch_hash[0:16]
            challenge_token = str(ch_hash)+";"+str(self.acceptable_zeros)
            return challenge_token
        
        except Exception as ex:
            self._logger.info(" Error in generating the POW challenge.")
            self._logger.info(ex)

        
    def respond_pow(self, *args, **kwargs):
        """ Responds to the POW challenge """
        try:
            sender_challenge = kwargs['challenge']
            pow_challenge, ZEROS_IN_RESPONSE = sender_challenge.split(";")
            h = hashcash.make_token(pow_challenge.encode(), int(ZEROS_IN_RESPONSE))
            pow_resp = str(pow_challenge)+";"+str(h)
            return pow_resp
                
        except Exception as ex:
            self._logger.info(" Exception '{}' in responding to the POW challenge.".format(ex))
            return None
    
    
    def verify_pow(self, *args, **kwargs):
        """ Verifies the POW challenge && Response """
        try:
            response, r_cesid, r_ip, r_port = kwargs['response'], kwargs['r_cesid'], kwargs['r_ip'], kwargs['r_port']
            inbound_challenge, inbound_solution = response.split(";")
            ch = r_ip + ":" + str(r_port) + ":" + r_cesid + ":" + self.get_pow_secret()
            ch_hash = hashlib.sha256(ch.encode()).hexdigest()
            generated_ch = str(ch_hash[0:16])
            
            if (generated_ch != inbound_challenge):
                if (not self.pow_transition_status[0]):
                    self._logger.info(" POW failed challenge verification.")
                    return False
                else:
                    for secret in self.pow_secret_management:
                        if secret != self.pow_secret:
                            pow_secret = secret
                    
                    ch = r_ip + ":" + str(r_port) + ":" + r_cesid + ":" + pow_secret
                    ch_hash = hashlib.sha256(ch.encode()).hexdigest()
                    generated_ch = str(ch_hash[0:16])
                    
                    if generated_ch != inbound_challenge:
                        self._logger.info(" POW failed challenge verification.")
                        return False
                    
            return self.pow_verification(inbound_challenge, inbound_solution)
        
        except Exception as ex:
            self._logger.info(" Exception '{}' in verifying the POW challenge.".format(ex))
            return False
    
    def pow_verification(self, inbound_challenge, inbound_solution):
        """ POW verification process """
        if hashcash.verify_token(inbound_challenge.encode(), inbound_solution) >= self.acceptable_zeros:
            self._logger.info("POW is verified.")
            return True
        else:
            self._logger.info(" POW failed verification.")
            return False
            
    def update_pow_secret(self):
        """
        If SECRET has passed certain timeout, then set the current SECRET to a new value.
        After the transition period has expired, the old pow-secret is deleted.
        """
        if (time.time()-self.pow_secret_management[self.pow_secret]) > self.secret_lifespan:
            self.load_secret()
            self.pow_transition_status = (True, time.time())
        
        transition_status, transition_time = self.pow_transition_status
                
        if transition_status and (time.time() > transition_time +2):
            self.transition_triggered = (False, time.time())
            secret_to_remove = []
            for it in self.pow_secret_management:
                if it != self.pow_secret:
                    secret_to_remove.append(it)
            
            for it in secret_to_remove:
                del self.pow_secret_management[it]            
    
    