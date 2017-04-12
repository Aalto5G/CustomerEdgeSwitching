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
import icetpLayering
import ocetpLayering
import cetpOperations
import copy

LOGLEVELCETP                    = logging.DEBUG

class CETPConnectionObject(object):
    def __init__(self):
        self.cetp_transactions = {}                     #{(SST,0): A, (SST,DST): B}            #{KEY_ONgoing: [(SST,0): A, (SST,0): B], KEY_Established: [(SST,DST): C, (SST,DST): D]}
        
    def has(self, session_tag):
        return session_tag in self.cetp_transactions
    
    def add(self, session_tag, transaction):
        self.cetp_transactions[session_tag] = transaction
        
    def get(self, session_tag):
        return self.cetp_transactions[session_tag]
    
    def remove(self, session_tag):
        del self.cetp_transactions[session_tag]


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


CES_CODE_TO_POLICY= {'cesid':'cesid',                       'cesid':'cesid',                        #Contains the CES-ID
                    'ttl':'dp_ttl',                         'dp_ttl':'ttl',                         #Contains the TTL of the connection
                    'certificate':'certificate',            'certificate':'certificate',            #CES-Certificate
                    'keepalive_cycle':'keepalive_cycle',    'keepalive_cycle':'keepalive_cycle',    #Contains the keepalive cycle duration
                    'keepalive':'keepalive',                'keepalive':'keepalive',                #Keepalive
                    'fw_version':'fw_version',              'fw_version':'fw_version',              #Contains terminating codes {error, timeout} 
                    'session_limit':'ces_session_limit',    'ces_session_limit':'session_limit',    #Contains waning codes {backoff}
                    'host_ratelimit':'host_ratelimit',      'host_ratelimit':'host_ratelimit',      #Sets the rate limit {packets/s,bytes/s}
                    'caces':'caces',                        'caces':'caces',                        #Contains the CA address for validating a CES
                    'pow_algo':'pow_algo',                  'pow_algo':'pow_algo',                  #Proof-of-work mechanism to push the burden of communication to the sender
                    'pow':'pow',                            'pow':'pow'
                    }


ALL_C2C_CODES = {'cesid', 'ttl', 'cert', 'keepalive_cycle', 'fw_ver', 'session_limit', 'terminate', 'warning', 'host_ratelimit', 'headersignature', \
                 'caces', 'pow', 'keepalive'}


ALL_GROUPS = {'id', 'payload', 'rloc', 'control', 'mobility','ces'}

TLV_GROUP = {'id':'id',                 'id':'id',
             'payload':'payload',       'payload':'payload',
             'rloc':'rloc',             'rloc':'rloc',
             'control':'control',       'control':'control',
             'mobility':'mobility',     'mobility':'mobility',
             'ces':'ces',               'ces':'ces'
             }

SEND_TLV_ID_CODE            = {}
SEND_TLV_RLOC_CODE          = {}
SEND_TLV_PAYLOAD_CODE       = {}

RESPONSE_TLV_ID_CODE        = {}
RESPONSE_TLV_PAYLOAD_CODE   = {}
RESPONSE_TLV_RLOC_CODE      = {}

VERIFY_TLV_ID_CODE        = {}
VERIFY_TLV_PAYLOAD_CODE   = {}
VERIFY_TLV_RLOC_CODE      = {}



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
                      "warning":cetpOperations.send_ctrl_warning
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
                      "fw_version":cetpOperations.send_fw_version,
                      "session_limit":cetpOperations.send_ces_session_limit,
                      "host_ratelimit":cetpOperations.send_ces_host_ratelimit,
                      "caces":cetpOperations.send_ces_caces,
                      "headersignature":cetpOperations.send_ces_headersignature,
                      "pow":cetpOperations.send_ces_pow,
                      "port_filtering":cetpOperations.send_ces_port_filtering,                      
                      "host_filtering":cetpOperations.send_ces_host_filtering,                      
                      "terminate":cetpOperations.send_ces_terminate,
                      "warning":cetpOperations.send_ctrl_warning
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
                              "host_ratelimit":cetpOperations.response_ces_host_ratelimit,
                              "caces":cetpOperations.response_ces_caces,
                              "headersignature":cetpOperations.response_ces_headersignature,
                              "pow":cetpOperations.response_ces_pow,
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
                              "host_ratelimit":cetpOperations.verify_ces_host_ratelimit,
                              "caces":cetpOperations.verify_ces_caces,
                              "headersignature":cetpOperations.verify_ces_headersignature,
                              "pow":cetpOperations.verify_ces_pow,
                              }


VERIFY_TLV_GROUP = {TLV_GROUP["id"]:VERIFY_TLV_ID_CODE,
                   TLV_GROUP["payload"]:VERIFY_TLV_PAYLOAD_CODE,
                   TLV_GROUP["rloc"]:VERIFY_TLV_RLOC_CODE,
                   TLV_GROUP["control"]:VERIFY_TLV_CONTROl_CODE,
                   TLV_GROUP['ces']:VERIFY_TLV_CES_CODE }


