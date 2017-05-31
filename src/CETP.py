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
import CETPC2C
import CETPH2H
import cetpOperations
import copy

KEY_INITIATED_CETP                  = 0
KEY_ESTABLISHED_CETP                = 1
LOGLEVELCETP                        = logging.DEBUG

class CETPConnectionObject(object):
    def __init__(self):
        self.cetp_transactions                          = {}                     #{(SST,0): A, (SST,DST): B}            #{KEY_ONgoing: [(SST,0): A, (SST,0): B], KEY_Established: [(SST,DST): C, (SST,DST): D]}
        self.cetp_transactions[KEY_INITIATED_CETP]      = {}
        self.cetp_transactions[KEY_ESTABLISHED_CETP]    = {}
    
    def has_initiated_transaction(self, session_tag):
        keytype = KEY_INITIATED_CETP
        return self._has(keytype, session_tag)
        
    def has_established_transaction(self, session_tag):
        keytype = KEY_ESTABLISHED_CETP
        return self._has(keytype, session_tag)
    
    def add_initiated_transaction(self, session_tag, transaction):
        keytype = KEY_INITIATED_CETP
        self._add(keytype, session_tag, transaction)
        
    def add_established_transaction(self, session_tag, transaction):
        keytype = KEY_ESTABLISHED_CETP
        self._add(keytype, session_tag, transaction)
        
    def remove_initiated_transaction(self, session_tag):
        keytype = KEY_INITIATED_CETP
        if self._has(keytype, session_tag):
            self._remove(keytype, session_tag)

    def remove_established_transaction(self, session_tag):
        keytype = KEY_ESTABLISHED_CETP
        if self._has(keytype, session_tag):
            self._remove(keytype, session_tag)
            
    def get_initiated_transaction(self, session_tag):
        keytype = KEY_INITIATED_CETP
        if self.has_initiated_transaction(session_tag):
            return self._get(keytype, session_tag)

    def get_established_transaction(self, session_tag):
        keytype = KEY_ESTABLISHED_CETP
        if self.has_established_transaction(session_tag):
            return self._get(keytype, session_tag)

    def _has(self, keytype, session_tag):
        if keytype in self.cetp_transactions:
            return session_tag in self.cetp_transactions[keytype]
        return False

    def _add(self, keytype, session_tag, transaction):
        self.cetp_transactions[keytype][session_tag] = transaction
        
    def _get(self, keytype, session_tag):
        return self.cetp_transactions[keytype][session_tag]
    
    def _remove(self, keytype, session_tag):
        del self.cetp_transactions[keytype][session_tag]
        

class CETP(object):
    pass                        # CETP class will have multiple instances of CETP TLV

class CETPTLV(object):
    def __init__(self):
        self.ope    = None
        self.cmp    = None
        self.ext    = None
        self.group  = None
        self.code   = None
        self.len    = None
        self.value  = None
    
    def get_ope(self):
        return self.ope
    
    def get_group(self):
        return self.group

    def get_code(self):
        return self.code
        
    def get_value(self):
        return self.value

    def set_value(self, value):
        self.value = value
        
    def remove_value(self):
        self.value=None


CES_CODE_TO_POLICY= {
                    'cesid':'cesid',                       'cesid':'cesid',                         #Contains the CES-ID
                    'ttl':'dp_ttl',                         'dp_ttl':'ttl',                         #Contains the TTL of the connection
                    'certificate':'certificate',            'certificate':'certificate',            #CES-Certificate
                    'keepalive_cycle':'keepalive_cycle',    'keepalive_cycle':'keepalive_cycle',    #Contains the keepalive cycle duration
                    'keepalive':'keepalive',                'keepalive':'keepalive',                #Keepalive
                    'fw_version':'fw_version',              'fw_version':'fw_version',              #Contains terminating codes {error, timeout} 
                    'session_limit':'ces_session_limit',    'ces_session_limit':'session_limit',    #Contains waning codes {backoff}
                    'host_sessions':'host_sessions',        'host_sessions':'host_sessions',        #Sets the rate limit {packets/s,bytes/s}
                    'caces':'caces',                        'caces':'caces',                        #Contains the CA address for validating a CES
                    'pow_algo':'pow_algo',                  'pow_algo':'pow_algo',                  #Proof-of-work mechanism to push the burden of communication to the sender
                    'pow':'pow',                            'pow':'pow',
                    'evidence_format':'evidence_format',    'evidence_format':'evidence_format',
                    'evidence':'evidence',                  'evidence':'evidence',
                    'host_filtering':'host_filtering',      'host_filtering':'host_filtering'
                    }

CONTROL_CODES = {'caep':'caep',     'caep':'caep',
                 'ack':'ack',       'ack':'ack'
                }

ALL_C2C_CODES = {'cesid', 'ttl', 'cert', 'keepalive_cycle', 'fw_ver', 'session_limit', 'terminate', 'warning', 'host_sessions', 'headersignature', \
                 'caces', 'pow', 'keepalive'}


ALL_GROUPS = {'id', 'payload', 'rloc', 'control', 'mobility','ces'}

TLV_GROUP = {'id':'id',                 'id':'id',
             'payload':'payload',       'payload':'payload',
             'rloc':'rloc',             'rloc':'rloc',
             'control':'control',       'control':'control',
             'mobility':'mobility',     'mobility':'mobility',
             'ces':'ces',               'ces':'ces'
             }


VERIFY_TLV_RLOC_CODE      = {"ipv4":cetpOperations.verify_rloc,
                       "ipv6":cetpOperations.verify_rloc,
                       "eth":cetpOperations.verify_rloc}


VERIFY_TLV_PAYLOAD_CODE   = {#"all"cetpOperations.verify_payload,
                          "ipv4":cetpOperations.verify_payload,
                          "ipv6":cetpOperations.verify_payload,
                          "eth":cetpOperations.verify_payload}



SEND_TLV_PAYLOAD_CODE   = {#"all"cetpOperations.send_payload,
                          "ipv4":cetpOperations.send_payload,
                          "ipv6":cetpOperations.send_payload,
                          "eth":cetpOperations.send_payload}

SEND_TLV_RLOC_CODE      = {#"all"cetpOperations.send_rloc,
                       "ipv4":cetpOperations.send_rloc,
                       "ipv6":cetpOperations.send_rloc,
                       "eth":cetpOperations.send_rloc}

RESPONSE_TLV_PAYLOAD_CODE = {#"all"cetpOperations.response_payload,
                          "ipv4":cetpOperations.response_payload,
                          "ipv6":cetpOperations.response_payload,
                          "eth":cetpOperations.response_payload}

RESPONSE_TLV_RLOC_CODE = {#"all"cetpOperations.response_rloc,
                       "ipv4":cetpOperations.response_rloc,
                       "ipv6":cetpOperations.response_rloc,
                       "eth":cetpOperations.response_rloc}


SEND_TLV_ID_CODE        = {"fqdn":cetpOperations.send_id,
                         "maid":cetpOperations.send_id,
                         "moc":cetpOperations.send_id,
                         "hash":cetpOperations.send_id,
                         "temp":cetpOperations.send_id,
                         "random":cetpOperations.send_id,
                         "bbbbid":cetpOperations.send_id,
                         "msisdn":cetpOperations.send_id,
                         "sip_uri":cetpOperations.send_id,
                         "impu":cetpOperations.send_id
                         }


RESPONSE_TLV_ID_CODE     = {"fqdn":cetpOperations.response_id,
                         "maid":cetpOperations.response_id,
                         "moc":cetpOperations.response_id,
                         "hash":cetpOperations.response_id,
                         "temp":cetpOperations.response_id,
                         "random":cetpOperations.response_id,
                         "bbbbid":cetpOperations.response_id,
                         "msisdn":cetpOperations.response_id,
                         "sip_uri":cetpOperations.response_id,
                         "impu":cetpOperations.response_id
                         }


VERIFY_TLV_ID_CODE       = {"fqdn":cetpOperations.verify_id,
                         "maid":cetpOperations.verify_id,
                         "moc":cetpOperations.verify_id,
                         "hash":cetpOperations.verify_id,
                         "temp":cetpOperations.verify_id,
                         "random":cetpOperations.verify_id,
                         "bbbbid":cetpOperations.verify_id,
                         "msisdn":cetpOperations.verify_id,
                         "sip_uri":cetpOperations.verify_id,
                         "impu":cetpOperations.verify_id
                         }


SEND_TLV_CONTROL_CODE = {"dstep":cetpOperations.send_ctrl_dstep,
                      "fqdn":cetpOperations.send_ctrl_fqdn,
                      "certificate":cetpOperations.send_ctrl_certificate,
                      "caep":cetpOperations.send_ctrl_caep,
                      "dp_rlocs":cetpOperations.send_ctrl_dp_rlocs,
                      "dp_ttl":cetpOperations.send_ctrl_dp_ttl,
                      "dp_keepalive_cycle":cetpOperations.send_ctrl_dp_keepalive_cycle,
                      "qos":cetpOperations.send_ctrl_qos,
                      "ack":cetpOperations.send_ctrl_ack,
                      "os_version":cetpOperations.send_ctrl_os_version,
                      "policy_caching":cetpOperations.send_ctrl_policy_caching,
                      "dp_proto":cetpOperations.send_ctrl_dp_proto,
                      "dp_port":cetpOperations.send_ctrl_dp_port,
                      "dp_ratelimit":cetpOperations.send_ctrl_dp_ratelimit,
                      "terminate":cetpOperations.send_ctrl_terminate,
                      "warning":cetpOperations.send_ctrl_warning,
                      }


"""
"dp_proto", "dp_port", "dp_ratelimit" -- If provided, these informations can help oCES or iCES to filter the unwanted traffic towards the destination domain. 
                                        i.e. Traffic other than this port, protocol, or exceeding the ratelimit.        (Port, proto) can be redundant with use of SFQQDN.
                                        
dp_rloc, dp_ttl, dp_keepalive cycle, qos -- can be added to host policy by network admin.. Based on its SLA with the customer.
"""

SEND_TLV_CES_CODE =  {"cesid":cetpOperations.send_ces_cesid,
                      "ttl":cetpOperations.send_ces_ttl,
                      "certificate":cetpOperations.send_ces_certificate,
                      "keepalive":cetpOperations.send_ces_keepalive,
                      "keepalive_cycle":cetpOperations.send_ces_keepalive_cycle,
                      "fw_version":cetpOperations.send_ces_fw_version,
                      "session_limit":cetpOperations.send_ces_session_limit,
                      "host_sessions":cetpOperations.send_ces_host_sessions,
                      "caces":cetpOperations.send_ces_caces,
                      "headersignature":cetpOperations.send_ces_headersignature,
                      "pow":cetpOperations.send_ces_pow,
                      "port_filtering":cetpOperations.send_ces_port_filtering,                      
                      "host_filtering":cetpOperations.send_ces_host_filtering,                      
                      "terminate":cetpOperations.send_ces_terminate,
                      "warning":cetpOperations.send_ctrl_warning,
                      "evidence_format":cetpOperations.send_ces_evidence_format,
                      "evidence":cetpOperations.send_ces_evidence
                      }

SEND_TLV_GROUP = {TLV_GROUP["id"]:SEND_TLV_ID_CODE,
                  TLV_GROUP["payload"]:SEND_TLV_PAYLOAD_CODE,
                  TLV_GROUP["rloc"]:SEND_TLV_RLOC_CODE,
                  TLV_GROUP["control"]:SEND_TLV_CONTROL_CODE,
                  TLV_GROUP["ces"]:SEND_TLV_CES_CODE
                  }


RESPONSE_TLV_CONTROl_CODE = {"dstep":cetpOperations.response_ctrl_dstep,
                      "fqdn":cetpOperations.response_ctrl_fqdn,
                      "certificate":cetpOperations.response_ctrl_certificate,
                      "caep":cetpOperations.response_ctrl_caep,
                      "dp_rlocs":cetpOperations.response_ctrl_dp_rlocs,
                      "dp_ttl":cetpOperations.response_ctrl_dp_ttl,
                      "dp_keepalive_cycle":cetpOperations.response_ctrl_dp_keepalive_cycle,
                      "qos":cetpOperations.response_ctrl_qos,
                      "ack":cetpOperations.response_ctrl_ack,
                      "os_version":cetpOperations.response_ctrl_os_version,
                      "policy_caching":cetpOperations.response_ctrl_policy_caching,
                      "dp_proto":cetpOperations.response_ctrl_dp_proto,
                      "dp_port":cetpOperations.response_ctrl_dp_port,
                      "dp_ratelimit":cetpOperations.response_ctrl_dp_ratelimit,
                      "terminate":cetpOperations.response_ctrl_terminate,
                      "warning":cetpOperations.response_ctrl_warning
                      }


RESPONSE_TLV_CES_CODE     = { "cesid":cetpOperations.response_ces_cesid,
                              "ttl":cetpOperations.response_ces_ttl,
                              "certificate":cetpOperations.response_ces_certificate,
                              "keepalive":cetpOperations.response_ces_keepalive,
                              "keepalive_cycle":cetpOperations.response_ces_keepalive_cycle,
                              "fw_version":cetpOperations.response_ces_fw_version,
                              "session_limit":cetpOperations.response_ces_session_limit,
                              "host_sessions":cetpOperations.response_ces_host_sessions,
                              "caces":cetpOperations.response_ces_caces,
                              "headersignature":cetpOperations.response_ces_headersignature,
                              "pow":cetpOperations.response_ces_pow,
                              "evidence_format":cetpOperations.response_ces_evidence_format,
                              "evidence":cetpOperations.response_ces_evidence
                              }

RESPONSE_TLV_GROUP = {TLV_GROUP["id"]:RESPONSE_TLV_ID_CODE,
                   TLV_GROUP["payload"]:RESPONSE_TLV_PAYLOAD_CODE,
                   TLV_GROUP["rloc"]:RESPONSE_TLV_RLOC_CODE,
                   TLV_GROUP["control"]:RESPONSE_TLV_CONTROl_CODE,
                   TLV_GROUP['ces']:RESPONSE_TLV_CES_CODE }


VERIFY_TLV_CONTROl_CODE = {"dstep":cetpOperations.verify_ctrl_dstep,
                      "fqdn":cetpOperations.verify_ctrl_fqdn,
                      "certificate":cetpOperations.verify_ctrl_certificate,
                      "caep":cetpOperations.verify_ctrl_caep,
                      "dp_rlocs":cetpOperations.verify_ctrl_dp_rlocs,
                      "dp_ttl":cetpOperations.verify_ctrl_dp_ttl,
                      "dp_keepalive_cycle":cetpOperations.verify_ctrl_dp_keepalive_cycle,
                      "qos":cetpOperations.verify_ctrl_qos,
                      "ack":cetpOperations.verify_ctrl_ack,
                      "os_version":cetpOperations.verify_ctrl_os_version,
                      "policy_caching":cetpOperations.verify_ctrl_policy_caching,
                      "dp_proto":cetpOperations.verify_ctrl_dp_proto,
                      "dp_port":cetpOperations.verify_ctrl_dp_port,
                      "dp_ratelimit":cetpOperations.verify_ctrl_dp_ratelimit,
                      "terminate":cetpOperations.verify_ctrl_terminate,
                      "warning":cetpOperations.verify_ctrl_warning
                      }


VERIFY_TLV_CES_CODE     = { "cesid":cetpOperations.verify_ces_cesid,
                              "ttl":cetpOperations.verify_ces_ttl,
                              "certificate":cetpOperations.verify_ces_certificate,
                              "keepalive":cetpOperations.verify_ces_keepalive,
                              "keepalive_cycle":cetpOperations.verify_ces_keepalive_cycle,
                              "fw_version":cetpOperations.verify_ces_fw_version,
                              "session_limit":cetpOperations.verify_ces_session_limit,
                              "host_sessions":cetpOperations.verify_ces_host_sessions,
                              "caces":cetpOperations.verify_ces_caces,
                              "headersignature":cetpOperations.verify_ces_headersignature,
                              "pow":cetpOperations.verify_ces_pow,
                              "evidence_format":cetpOperations.verify_ces_evidence_format,
                              "evidence":cetpOperations.verify_ces_evidence
                              }


VERIFY_TLV_GROUP = {TLV_GROUP["id"]:VERIFY_TLV_ID_CODE,
                   TLV_GROUP["payload"]:VERIFY_TLV_PAYLOAD_CODE,
                   TLV_GROUP["rloc"]:VERIFY_TLV_RLOC_CODE,
                   TLV_GROUP["control"]:VERIFY_TLV_CONTROl_CODE,
                   TLV_GROUP['ces']:VERIFY_TLV_CES_CODE }


