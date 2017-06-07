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
import string
import sys, os
sys.path.append(os.path.join(os.path.dirname('hashcash.py'), 'lib'))
import hashcash
import hashlib


LOGLEVEL_CETPSecurity       = logging.INFO


class CETPSecurity:
    def __init__(self, ces_params, name="CETPSecurity"):
        self.localhost_evidences             = {}                            # {host-fqdn: [evidence]}
        self.remotehost_evidence             = {}
        self.remote_ces_evidence             = {}
        self.ces_params                      = ces_params
        self._logger                         = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_CETPSecurity)
        self._initialize_pow()
        
    # CETPSecurity shall have specific 'CES-to-CES' view & aggregated view of all 'CES-to-CES' interactions
    
    def process_evidence(self, r_cesid, evidence):
        """ Processes the evidence received from 'r_cesid' """
        self.remote_ces_evidence[r_cesid] = evidence
        # parse to retrieve the ID/FQDN of the host for which the evidence is received.        # ID could be a 'host-id' or 'cesid' itself
        # Evidence could reveal more about the type of misbehavior observed from CES.
    
    def evidence_against_localhost(self, host_fqdn, r_cesid, evidence):
        """ Gets evidence against local-host's fqdn from remote-CES.
        Aggregates evidences against local-host's fqdn && counts number of evidences from 'r_cesid'
        Accepts evidence if it meets a (standard) format, i.e. IOC. Otherwise, No.
        """
        pass
    
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
    
    