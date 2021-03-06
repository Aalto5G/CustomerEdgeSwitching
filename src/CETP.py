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
import copy

import cetpManager
import CETPC2C
import CETPH2H
import cetpOperations

from helpers_n_wrappers import container3

LOGLEVELCETP           = logging.DEBUG
LOGLEVELCETPSTATETABLE = logging.INFO
LOGLEVELPAYLOADIDTABLE = logging.INFO

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
    
    def has_value(self):
        return self.value
        
    def get_value(self):
        return self.value

    def set_value(self, value):
        self.value = value
        
    def remove_value(self):
        self.value = None



class CETPStateTable(container3.Container):
    def __init__(self, name="CETPStateTable"):
        """
        Initialize the CETPState object. 
        """
        super().__init__(name)
        self._logger = logging.getLogger("CETP State")
        self._logger.setLevel(LOGLEVELCETPSTATETABLE)
    
    def reregister(self, obj):
        """
        Re-register a transaction from the CETPState.
        @param obj: The transaction object.
        """
        self._logger.debug("Re-registering transaction: {}".format(obj))
        #Use the flag to modify the behavior of the lookupkeys() response
        obj.set_negotiated(status=False)
        self.remove(obj)
        obj.set_negotiated(status=True)
        self.add(obj)
        
    def __str__(self):
        return "Total length of CETPStateTable = {}".format(len(self.getall()))


class PayloadIDTable(container3.Container):
    def __init__(self, name="PayloadIDTable"):
        """
        Initialize the PayloadIDTable object. 
        """
        super().__init__(name)
        self._logger = logging.getLogger("name")
        self._logger.setLevel(LOGLEVELPAYLOADIDTABLE)
            
    def __str__(self):
        return "Total length of PayloadIDTable = {}".format(len(self.getall()))


class PayloadIDs(container3.ContainerNode):
    def __init__(self, r_cesid, payload_type, tunnel_id, preference, name="PayloadIDs"):
        """
        Initialize the Payload IDs object. 
        """
        super().__init__(name)
        self.r_cesid        = r_cesid
        self.payload_type   = payload_type
        self.tunnel_id      = tunnel_id
        self.preference     = preference
        self._logger        = logging.getLogger("name")
        self._logger.setLevel(LOGLEVELPAYLOADIDTABLE)
        self._build_lookupkeys()

    def _build_lookupkeys(self):
        keys = []
        keys += [((self.r_cesid, self.payload_type), True)]
        keys += [((self.r_cesid, self.payload_type, self.tunnel_id), True)]
        self._built_lookupkeys = keys

    def lookupkeys(self):
        return self._built_lookupkeys

    def get_tunnelID(self):
        return self.tunnel_id

    def get_preference(self):
        return self.preference


PPRINT_GROUP = { "id":"id ", "ces":"ces ", "control":"ctrl", "rloc":"rloc", "payload":"payl"}
PPRINT_OPE   = {"query":"qury", "response":"resp", "info":"info"}
PPRINT_CODE  = {"cesid":"cesid", "pow":"pwork", "caces":"caces",     "fw_version":"fwVer",    "ttl":"dpttl", 
                "keepalive_cycle":"kacyc",    "keepalive":"kpalv", "session_limit":"slimt", "evidence_format":"evFmt",
                "evidence":"evdnc", "certificate":"certf", "caep":"caep ", "ack": "ack  ", "ipv4":"ipv4 ", "ipv6":"ipv6 ", "eth": "eth  ", "gre": "gre  "
                }

# 'session_limit':'ces_session_limit',    'ces_session_limit':'session_limit',    #Contains waning codes {backoff}
# 'ttl':'hard_ttl',                         'hard_ttl':'ttl',                         #Contains the TTL of the connection

CONTROL_CODES = ['caep', 'ack']

ALL_C2C_CODES = ['cesid', 'ttl', 'keepalive_cycle', 'fw_ver', 'session_limit', 'terminate', 'warning', 'host_sessions', 'headersignature', \
                 'caces', 'pow', 'keepalive']


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
                              "vxlan":cetpOperations.verify_payload,
                              "gre":cetpOperations.verify_payload,
                              "geneve":cetpOperations.verify_payload}

SEND_TLV_PAYLOAD_CODE   = {#"all"cetpOperations.send_payload,
                          "vxlan":cetpOperations.send_payload,
                          "gre":cetpOperations.send_payload,
                          "geneve":cetpOperations.send_payload}

SEND_TLV_RLOC_CODE      = {#"all"cetpOperations.send_rloc,
                           "ipv4":cetpOperations.send_rloc,
                           "ipv6":cetpOperations.send_rloc,
                           "eth":cetpOperations.send_rloc}

RESPONSE_TLV_PAYLOAD_CODE = {#"all"cetpOperations.response_payload,
                              "vxlan":cetpOperations.response_payload,
                              "gre":cetpOperations.response_payload,
                              "geneve":cetpOperations.response_payload}

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
                         "hard_ttl":cetpOperations.send_ctrl_hard_ttl,
                         "idle_ttl":cetpOperations.send_ctrl_idle_ttl,
                         "dp_keepalive_cycle":cetpOperations.send_ctrl_dp_keepalive_cycle,
                         "qos":cetpOperations.send_ctrl_qos,
                         "ack":cetpOperations.send_ack,
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
                                        
dp_rloc, hard_ttl, dp_keepalive cycle, qos -- can be added to host policy by network admin.. Based on its SLA with the customer.
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
                      "ack":cetpOperations.send_ack,
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
                             "hard_ttl":cetpOperations.response_ctrl_hard_ttl,
                             "idle_ttl":cetpOperations.response_ctrl_idle_ttl,
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
                              "host_filtering":cetpOperations.response_ces_host_filtering,                      
                              "caces":cetpOperations.response_ces_caces,
                              "ack":cetpOperations.response_ack,
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
                          "hard_ttl":cetpOperations.verify_ctrl_hard_ttl,
                          "idle_ttl":cetpOperations.verify_ctrl_idle_ttl,
                          "dp_keepalive_cycle":cetpOperations.verify_ctrl_dp_keepalive_cycle,
                          "qos":cetpOperations.verify_ctrl_qos,
                          "ack":cetpOperations.verify_ack,
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
                          "host_filtering":cetpOperations.verify_ces_host_filtering,                      
                          "caces":cetpOperations.verify_ces_caces,
                          "ack":cetpOperations.verify_ack,
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

