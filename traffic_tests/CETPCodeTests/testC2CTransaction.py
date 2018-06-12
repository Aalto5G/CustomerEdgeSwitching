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
import CETPH2H
import CETPC2C
import cetpOperations
import CETP
import copy
import ConnectionTable
import H2HTransaction
from H2HTransaction import CETPTransaction

LOGLEVELCETP                    = logging.DEBUG
LOGLEVEL_C2CTransaction         = logging.INFO
LOGLEVEL_oC2CTransaction        = logging.INFO
LOGLEVEL_iC2CTransaction        = logging.INFO

NEGOTIATION_RTT_THRESHOLD       = 2

"""
General_CES_policy
        cesid: cesa.lte.
        certificate: config_cesa/cesa.crt
        #private_key: config_cesa/cesa.key
        #ca_certificate: config_cesa/ca.crt
        dp_ttl: 3600
        keepalive_timeout: 2
        keepalive_cycle: 20
        caces: 127.0.0.1
        fw_version: 0.1
        ces_session_limit: 30
        host_ratelimit: 2
        pow_algo: hashcash
        max_ces_session_limit: 100
        max_dp_ttl: 7200
        max_host_ratelimit: 10
        min_keepalive_timeout: 10
"""




class MockCETPManager:
    def remove_c2c_layer(self, r_cesid):        pass
    def remove_cetp_endpoint(self, r_cesid):    pass

class MockCETPC2CLayer:
    def send_cetp(self, msg): pass
    def shutdown(self): pass


@asyncio.coroutine
def test_oC2CCETP_initiate_C2CNegotiation(c2c):
    cetp_resp = yield from c2c.initiate_c2c_negotiation()
    if cetp_resp != None:
        print("cept_resp: ", cetp_resp)

    #c2c.set_terminated()
    
@asyncio.coroutine
def test_iC2CCETP_startCETPProcessing_Success(c2c):
    cetp_msg = {'VER': 2, \
                'TLV': [{'ope': 'info', 'code': 'cesid', 'group': 'ces', 'value': 'cesa.lte.'}, \
                        {'ope': 'info', 'code': 'caces', 'group': 'ces', 'value': '195.148.124.145'}, \
                        {'ope': 'info', 'code': 'fw_version', 'group': 'ces', 'value': '0.1'}, \
                        {'ope': 'info', 'code': 'ttl', 'group': 'ces', 'value': '7200'}, \
                        {'ope': 'info', 'code': 'session_limit', 'group': 'ces', 'value': '200'}, \
                        {'ope': 'info', 'code': 'evidence_format', 'group': 'ces', 'value': 'IETF-IOC1'}, \
                        {'ope': 'info', 'code': 'ipv4', 'group': 'rloc', 'value': (100, 80, '10.0.3.101', 'ISP')}, \
                        {'ope': 'info', 'code': 'ipv4', 'group': 'rloc', 'value': (100, 60, '10.1.3.101', 'IXP')}, \
                        {'ope': 'info', 'code': 'ipv6', 'group': 'rloc', 'value': (100, 40, '11:22:33:44:55:66:77:01', 'ICP')}, \
                        {'ope': 'info', 'code': 'eth', 'group': 'payload', 'value': ''}, {'ope': 'query', 'code': 'cesid', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'caces', 'group': 'ces'}, {'ope': 'query', 'code': 'fw_version', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'ttl', 'group': 'ces'}, {'ope': 'query', 'code': 'session_limit', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'evidence_format', 'group': 'ces'}, {'ope': 'query', 'code': 'ipv4', 'group': 'rloc'}, \
                        {'ope': 'query', 'code': 'ipv6', 'group': 'rloc'}, {'ope': 'query', 'code': 'eth', 'group': 'payload'}], 'DST': 0, 'SST': 1780894005}
    
    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    resp = c2c.process_c2c_transaction(cetp_msg)
    if resp != None:
        (status, cetp_resp) = resp
        print("status:", status)
        print("cetp_resp: ", cetp_resp)
    
@asyncio.coroutine
def test_iC2CCETP_startCETPProcessing_MissingTLVs(c2c):
    cetp_msg = {'VER': 2, \
                'TLV': [{'ope': 'info', 'code': 'cesid', 'group': 'ces', 'value': 'cesa.lte.'}, \
                        {'ope': 'info', 'code': 'fw_version', 'group': 'ces', 'value': '0.1'}, \
                        {'ope': 'info', 'code': 'ttl', 'group': 'ces', 'value': '7200'}, \
                        {'ope': 'info', 'code': 'session_limit', 'group': 'ces', 'value': '200'}, \
                        {'ope': 'info', 'code': 'evidence_format', 'group': 'ces', 'value': 'IETF-IOC1'}, \
                        {'ope': 'info', 'code': 'ipv4', 'group': 'rloc', 'value': (100, 80, '10.0.3.101', 'ISP')}, \
                        {'ope': 'info', 'code': 'ipv4', 'group': 'rloc', 'value': (100, 60, '10.1.3.101', 'IXP')}, \
                        {'ope': 'info', 'code': 'ipv6', 'group': 'rloc', 'value': (100, 40, '11:22:33:44:55:66:77:01', 'ICP')}, \
                        {'ope': 'info', 'code': 'eth', 'group': 'payload', 'value': ''}, {'ope': 'query', 'code': 'cesid', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'caces', 'group': 'ces'}, {'ope': 'query', 'code': 'fw_version', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'ttl', 'group': 'ces'}, {'ope': 'query', 'code': 'session_limit', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'evidence_format', 'group': 'ces'}, {'ope': 'query', 'code': 'ipv4', 'group': 'rloc'}, \
                        {'ope': 'query', 'code': 'ipv6', 'group': 'rloc'}, {'ope': 'query', 'code': 'eth', 'group': 'payload'}], 'DST': 1780894005, 'SST': 0}
    
    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    resp = c2c.process_c2c_transaction(cetp_msg)
    if resp != None:
        (status, cetp_resp) = resp
        print("status:", status)
        #print("cetp_resp: ", cetp_resp)

@asyncio.coroutine
def test_iC2CCETP_startCETPProcessing_TestNotAvailableTLV(c2c):
    cetp_msg = {'VER': 2, \
                'TLV': [{'ope': 'info', 'code': 'cesid', 'group': 'ces', 'value': 'cesa.lte.'}, \
                        {'ope': 'info', 'code': 'fw_version', 'cmp':'notAvailable', 'group': 'ces', 'value': '0.1'}, \
                        {'ope': 'info', 'code': 'ttl', 'group': 'ces', 'value': '7200'}, \
                        {'ope': 'info', 'code': 'session_limit', 'group': 'ces', 'value': '200'}, \
                        {'ope': 'info', 'code': 'evidence_format', 'group': 'ces', 'value': 'IETF-IOC1'}, \
                        {'ope': 'info', 'code': 'ipv4', 'group': 'rloc', 'value': (100, 80, '10.0.3.101', 'ISP')}, \
                        {'ope': 'info', 'code': 'ipv4', 'group': 'rloc', 'value': (100, 60, '10.1.3.101', 'IXP')}, \
                        {'ope': 'info', 'code': 'ipv6', 'group': 'rloc', 'value': (100, 40, '11:22:33:44:55:66:77:01', 'ICP')}, \
                        {'ope': 'info', 'code': 'eth', 'group': 'payload', 'value': ''}, {'ope': 'query', 'code': 'cesid', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'caces', 'group': 'ces'}, {'ope': 'query', 'code': 'fw_version', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'ttl', 'group': 'ces'}, {'ope': 'query', 'code': 'session_limit', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'evidence_format', 'group': 'ces'}, {'ope': 'query', 'code': 'ipv4', 'group': 'rloc'}, \
                        {'ope': 'query', 'code': 'ipv6', 'group': 'rloc'}, {'ope': 'query', 'code': 'eth', 'group': 'payload'}], 'DST': 1780894005, 'SST': 0}
    
    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    resp = c2c.process_c2c_transaction(cetp_msg)
    if resp != None:
        (status, cetp_resp) = resp
        print("status:", status)
        #print("cetp_resp: ", cetp_resp)

@asyncio.coroutine
def test_iC2CCETP_startCETPProcessing_OROperation1notAvailableRLOCs(c2c):
    cetp_msg = {'VER': 2, \
                'TLV': [{'ope': 'info', 'code': 'cesid', 'group': 'ces', 'value': 'cesa.lte.'}, \
                        {'ope': 'info', 'code': 'caces', 'group': 'ces', 'value': '195.148.124.145'}, \
                        {'ope': 'info', 'code': 'fw_version', 'group': 'ces', 'value': '0.1'}, \
                        {'ope': 'info', 'code': 'ttl', 'group': 'ces', 'value': '7200'}, \
                        {'ope': 'info', 'code': 'session_limit', 'group': 'ces', 'value': '200'}, \
                        {'ope': 'info', 'code': 'evidence_format', 'group': 'ces', 'value': 'IETF-IOC1'}, \
                        {'ope': 'info', 'code': 'ipv4', 'group': 'rloc', 'value': (100, 80, '10.0.3.101', 'ISP')}, \
                        {'ope': 'info', 'code': 'ipv6', 'group': 'rloc', 'cmp': 'notAvailable'}, \
                        {'ope': 'info', 'code': 'eth', 'group': 'payload', 'value': ''}, {'ope': 'query', 'code': 'cesid', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'caces', 'group': 'ces'}, {'ope': 'query', 'code': 'fw_version', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'ttl', 'group': 'ces'}, {'ope': 'query', 'code': 'session_limit', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'evidence_format', 'group': 'ces'}, {'ope': 'query', 'code': 'ipv4', 'group': 'rloc'}, \
                        {'ope': 'query', 'code': 'ipv6', 'group': 'rloc'}, {'ope': 'query', 'code': 'eth', 'group': 'payload'}], 'DST': 1780894005, 'SST': 0}
    
    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    resp = c2c.process_c2c_transaction(cetp_msg)
    if resp != None:
        (status, cetp_resp) = resp
        print("status:", status)
        #print("cetp_resp: ", cetp_resp)

@asyncio.coroutine
def test_iC2CCETP_startCETPProcessing_OROperationNnotAvailableRLOCs(c2c):
    cetp_msg = {'VER': 2, \
                'TLV': [{'ope': 'info', 'code': 'cesid', 'group': 'ces', 'value': 'cesa.lte.'}, \
                        {'ope': 'info', 'code': 'caces', 'group': 'ces', 'value': '195.148.124.145'}, \
                        {'ope': 'info', 'code': 'fw_version', 'group': 'ces', 'value': '0.1'}, \
                        {'ope': 'info', 'code': 'ttl', 'group': 'ces', 'value': '7200'}, \
                        {'ope': 'info', 'code': 'session_limit', 'group': 'ces', 'value': '200'}, \
                        {'ope': 'info', 'code': 'evidence_format', 'group': 'ces', 'value': 'IETF-IOC1'}, \
                        {'ope': 'info', 'code': 'ipv4', 'group': 'rloc', 'value': 'notAvailable'}, \
                        {'ope': 'info', 'code': 'ipv6', 'group': 'rloc', 'cmp': 'notAvailable'}, \
                        {'ope': 'info', 'code': 'eth', 'group': 'payload', 'value': ''}, {'ope': 'query', 'code': 'cesid', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'caces', 'group': 'ces'}, {'ope': 'query', 'code': 'fw_version', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'ttl', 'group': 'ces'}, {'ope': 'query', 'code': 'session_limit', 'group': 'ces'}, \
                        {'ope': 'query', 'code': 'evidence_format', 'group': 'ces'}, {'ope': 'query', 'code': 'ipv4', 'group': 'rloc'}, \
                        {'ope': 'query', 'code': 'ipv6', 'group': 'rloc'}, {'ope': 'query', 'code': 'eth', 'group': 'payload'}], 'DST': 1780894005, 'SST': 0}
    
    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    resp = c2c.process_c2c_transaction(cetp_msg)
    if resp != None:
        (status, cetp_resp) = resp
        print("status:", status)
        #print("cetp_resp: ", cetp_resp)

@asyncio.coroutine
def test_oC2CCETP_ContinueProcessing_Success(c2c):
    yield from c2c.initiate_c2c_negotiation()
    cetp_msg = {'DST': 1780894005, 'SST': 1698284349, \
                'TLV': [{'group': 'ces', 'ope': 'info', 'code': 'cesid', 'value': 'cesb.lte.'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'caces', 'value': '195.148.124.145'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'fw_version', 'value': '0.1'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'ttl', 'value': 3600}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'session_limit', 'value': '200'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'evidence_format', 'value': 'IETF-IOC1'}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 80, '10.0.3.103', 'ISP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 60, '10.1.3.103', 'IXP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv6', 'value': (100, 40, '11:22:33:44:55:66:77:03', 'ICP')}, \
                        {'group': 'payload', 'ope': 'info', 'code': 'eth'}], 
                'VER': 2}
    
    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    res = c2c.continue_c2c_negotiation(cetp_msg)
    if res is not None:
        (status, cetp_resp) = res
        print("status: ", status)
        print("cetp_resp: ", cetp_resp)
    
@asyncio.coroutine
def test_oC2CCETP_ContinueProcessing_MissingTLVs(c2c):
    yield from c2c.initiate_c2c_negotiation()
    cetp_msg = {'DST': 1780894005, 'SST': 1698284349, \
                'TLV': [{'group': 'ces', 'ope': 'info', 'code': 'cesid', 'value': 'cesb.lte.'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'fw_version', 'value': '0.1'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'ttl', 'value': 3600}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'session_limit', 'value': '200'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'evidence_format', 'value': 'IETF-IOC1'}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 80, '10.0.3.103', 'ISP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 60, '10.1.3.103', 'IXP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv6', 'value': (100, 40, '11:22:33:44:55:66:77:03', 'ICP')}, \
                        {'group': 'payload', 'ope': 'info', 'code': 'eth'}], 
                'VER': 2}

    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    res = c2c.continue_c2c_negotiation(cetp_msg)
    if res is not None:
        (status, cetp_resp) = res
        print("status: ", status)
        print("cetp_resp: ", cetp_resp)

@asyncio.coroutine
def test_oC2CCETP_ContinueProcessing_TerminateTLV(c2c):
    yield from c2c.initiate_c2c_negotiation()
    cetp_msg = {'TLV': [{'code': 'terminate', 'value': '', 'group': 'ces', 'ope': 'info'}], \
                'VER': 2, 'DST': 1780894005, 'SST': 0}

    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    res = c2c.continue_c2c_negotiation(cetp_msg)
    if res is not None:
        (status, cetp_resp) = res
        print("status: ", status)
        print("cetp_resp: ", cetp_resp)
    
@asyncio.coroutine
def test_oC2CCETP_ContinueProcessing_notAvailableTLV(c2c):
    yield from c2c.initiate_c2c_negotiation()
    cetp_msg = {'DST': 1780894005, 'SST': 1698284349, \
                'TLV': [{'group': 'ces', 'ope': 'info', 'code': 'cesid', 'value': 'cesb.lte.'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'caces', 'cmp': 'notAvailable'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'fw_version', 'value': '0.1'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'ttl', 'value': 3600}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'session_limit', 'value': '200'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'evidence_format', 'value': 'IETF-IOC1'}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 80, '10.0.3.103', 'ISP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 60, '10.1.3.103', 'IXP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv6', 'value': (100, 40, '11:22:33:44:55:66:77:03', 'ICP')}, \
                        {'group': 'payload', 'ope': 'info', 'code': 'eth'}], 
                'VER': 2}

    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    res = c2c.continue_c2c_negotiation(cetp_msg)
    if res is not None:
        (status, cetp_resp) = res
        print("status: ", status)
        print("cetp_resp: ", cetp_resp)

@asyncio.coroutine
def test_oC2CCETP_ContinueProcessing_OROperation1notAvailableRLOCs(c2c):
    yield from c2c.initiate_c2c_negotiation()
    cetp_msg = {'DST': 1780894005, 'SST': 1698284349, \
                'TLV': [{'group': 'ces', 'ope': 'info', 'code': 'cesid', 'value': 'cesb.lte.'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'caces', 'cmp': '195.148.124.145'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'fw_version', 'value': '0.1'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'ttl', 'value': 3600}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'session_limit', 'value': '200'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'evidence_format', 'value': 'IETF-IOC1'}, \
                        {'code': 'ipv4', 'cmp':'notAvailable', 'group': 'rloc', 'ope': 'info'}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv6', 'value': (100, 40, '11:22:33:44:55:66:77:03', 'ICP')}, \
                        {'group': 'payload', 'ope': 'info', 'code': 'eth'}], 
                'VER': 2}

    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    res = c2c.continue_c2c_negotiation(cetp_msg)
    if res is not None:
        (status, cetp_resp) = res
        print("status: ", status)
        print("cetp_resp: ", cetp_resp)

@asyncio.coroutine
def test_oC2CCETP_ContinueProcessing_OROperationNnotAvailableRLOCs(c2c):
    yield from c2c.initiate_c2c_negotiation()
    
    cetp_msg = {'DST': 1780894005, 'SST': 1698284349, \
                'TLV': [{'group': 'ces', 'ope': 'info', 'code': 'cesid', 'value': 'cesb.lte.'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'caces', 'cmp': '195.148.124.145'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'fw_version', 'value': '0.1'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'ttl', 'value': 3600}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'session_limit', 'value': '200'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'evidence_format', 'value': 'IETF-IOC1'}, \
                        {'code': 'ipv4', 'cmp': 'notAvailable', 'group': 'rloc', 'ope': 'info'}, \
                        {'code': 'ipv6', 'cmp': 'notAvailable', 'group': 'rloc', 'ope': 'info'}, \
                        {'group': 'payload', 'ope': 'info', 'code': 'eth'}], 
                'VER': 2}

    #for it in range(0,2):
    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    res = c2c.continue_c2c_negotiation(cetp_msg)
    if res is not None:
        (status, cetp_resp) = res
        print("status: ", status)
        print("cetp_resp: ", cetp_resp)

@asyncio.coroutine
def test_oC2CCETP_ContinueProcessing_WrongRemoteCESID(c2c):
    yield from c2c.initiate_c2c_negotiation()
    cetp_msg = {'DST': 1780894005, 'SST': 1698284349, \
                'TLV': [{'group': 'ces', 'ope': 'info', 'code': 'cesid', 'value': 'cesc.lte.'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'fw_version', 'value': '0.1'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'ttl', 'value': 3600}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'session_limit', 'value': '200'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'evidence_format', 'value': 'IETF-IOC1'}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 80, '10.0.3.103', 'ISP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 60, '10.1.3.103', 'IXP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv6', 'value': (100, 40, '11:22:33:44:55:66:77:03', 'ICP')}, \
                        {'group': 'payload', 'ope': 'info', 'code': 'eth'}], 
                'VER': 2}

    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    res = c2c.continue_c2c_negotiation(cetp_msg)
    if res is not None:
        (status, cetp_resp) = res
        print("status: ", status)
        print("cetp_resp: ", cetp_resp)


@asyncio.coroutine
def test_oC2CCETP_ContinueProcessing_QueriesWithAllOffers(c2c):
    yield from c2c.initiate_c2c_negotiation()
    cetp_msg = {'DST': 1780894005, 'SST': 1698284349, \
                'TLV': [{'group': 'ces', 'ope': 'info', 'code': 'cesid', 'value': 'cesc.lte.'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'fw_version', 'value': '0.1'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'ttl', 'value': 3600}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'session_limit', 'value': '200'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'evidence_format', 'value': 'IETF-IOC1'}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 80, '10.0.3.103', 'ISP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 60, '10.1.3.103', 'IXP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv6', 'value': (100, 40, '11:22:33:44:55:66:77:03', 'ICP')}, \
                        {'group': 'ces', 'ope': 'query', 'code': 'fw_version'}, \
                        {'group': 'payload', 'ope': 'info', 'code': 'eth'}], 
                'VER': 2}

    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    res = c2c.continue_c2c_negotiation(cetp_msg)
    if res is not None:
        (status, cetp_resp) = res
        print("status: ", status)
        print("cetp_resp: ", cetp_resp)

@asyncio.coroutine
def test_oC2CCETP_ContinueProcessing_QueriesForNotAvailableTLVs(c2c):
    yield from c2c.initiate_c2c_negotiation()
    cetp_msg = {'DST': 1780894005, 'SST': 1698284349, \
                'TLV': [{'group': 'ces', 'ope': 'info', 'code': 'cesid', 'value': 'cesc.lte.'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'fw_version', 'value': '0.1'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'ttl', 'value': 3600}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'session_limit', 'value': '200'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'evidence_format', 'value': 'IETF-IOC1'}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 80, '10.0.3.103', 'ISP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 60, '10.1.3.103', 'IXP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv6', 'value': (100, 40, '11:22:33:44:55:66:77:03', 'ICP')}, \
                        {'group': 'ces', 'ope': 'query', 'code': 'fw_vesdsrsion'}, \
                        {'group': 'payload', 'ope': 'info', 'code': 'eth'}], 
                'VER': 2}

    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    res = c2c.continue_c2c_negotiation(cetp_msg)
    if res is not None:
        (status, cetp_resp) = res
        print("status: ", status)
        print("cetp_resp: ", cetp_resp)

@asyncio.coroutine
def test_oC2CCETP_PostC2CNegotiation_Terminate(c2c):
    cetp_msg1 = yield from c2c.initiate_c2c_negotiation()
    sst = cetp_msg1["SST"]
    cetp_msg2 = {'DST': 12133, 'SST': sst, \
                'TLV': [{'group': 'ces', 'ope': 'info', 'code': 'cesid', 'value': 'cesb.lte.'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'caces', 'value': '195.148.124.145'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'fw_version', 'value': '0.1'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'ttl', 'value': 3600}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'session_limit', 'value': '200'}, \
                        {'group': 'ces', 'ope': 'info', 'code': 'evidence_format', 'value': 'IETF-IOC1'}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 80, '10.0.3.103', 'ISP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv4', 'value': (100, 60, '10.1.3.103', 'IXP')}, \
                        {'group': 'rloc', 'ope': 'info', 'code': 'ipv6', 'value': (100, 40, '11:22:33:44:55:66:77:03', 'ICP')}, \
                        {'group': 'payload', 'ope': 'info', 'code': 'eth'}], 
                'VER': 2}
    
    import json
    cetp_msg2 = json.loads(json.dumps(cetp_msg2))
    res = c2c.continue_c2c_negotiation(cetp_msg2)
    if res is not None:
        (status, cetp_resp) = res
        print("status: ", status)
        print("cetp_resp: ", cetp_resp)

    # Post-c2c message    
    """
    cetp_msg = {'DST': 12133, 'SST': sst, \
                'TLV': [{'group': 'ces', 'ope': 'info', 'code': 'terminate', 'value': ''}], 'VER': 2}
    """
    
    cetp_msg = {'DST': 12133, 'SST': sst, \
                'TLV': [{'group': 'ces', 'ope': 'info', 'code': 'terminate', 'value': {"sessions":[(12,23), (23,45)]}}], 'VER': 2}

    #for it in range(0,2):
    import json
    cetp_msg = json.loads(json.dumps(cetp_msg))
    res = c2c.post_c2c_negotiation(cetp_msg)


def test_function(h2h, ip_addr, dst_id):
    """ Testing CES/CETP oC2CTransactions """
    # For start processing
    #asyncio.ensure_future(test_oC2CCETP_initiate_C2CNegotiation(c2c))
    #asyncio.ensure_future(test_oC2CCETPFlood(h2h))
    #asyncio.ensure_future(test_oC2CCETP_forbiddenSender(h2h))
    #asyncio.ensure_future(test_oC2CCETP_forbiddenDestination(h2h))
    
    # -------- For continue processing -------------
    #asyncio.ensure_future(test_oC2CCETP_ContinueProcessing_Success(h2h))
    #asyncio.ensure_future(test_oC2CCETP_ContinueProcessing_WrongRemoteCESID(h2h))
    #asyncio.ensure_future(test_oC2CCETP_ContinueProcessing_MissingTLVs(h2h))
    #asyncio.ensure_future(test_oC2CCETP_ContinueProcessing_TerminateTLV(h2h))
    #asyncio.ensure_future(test_oC2CCETP_PreProcessing(h2h))                                      # Not tested yet  
    #asyncio.ensure_future(test_oC2CCETP_ContinueProcessing_notAvailableTLV(h2h))
    #asyncio.ensure_future(test_oC2CCETP_ContinueProcessing_OROperation1notAvailableRLOCs(c2c))       # Shall return True
    #asyncio.ensure_future(test_oC2CCETP_ContinueProcessing_OROperationNnotAvailableRLOCs(c2c))       # Shall return False

    asyncio.ensure_future(test_oC2CCETP_ContinueProcessing_QueriesForNotAvailableTLVs(c2c))       # Shall return False, or terminate with notAvailable
    #asyncio.ensure_future(test_oC2CCETP_ContinueProcessing_QueriesWithAllOffers(c2c))       # Shall return Full query and response
    
    # -------- For post-c2c negotiation -------------
    #asyncio.ensure_future(test_oC2CCETP_PostC2CNegotiation_Terminate(h2h))                        # Not tested yet.
    #asyncio.ensure_future(test_oC2CCETP_ContinueProcessing_WeirdMessage(h2h))


    # ---- Testing CES/CETP iC2CTransactions against inbound CETP Message ---
    #asyncio.ensure_future(test_iC2CCETP_startCETPProcessing_Success(c2c))                        # Shall return True
    #asyncio.ensure_future(test_iC2CCETP_startCETPProcessing_MissingTLVs(c2c))                    # Shall return None
    #asyncio.ensure_future(test_iC2CCETP_startCETPProcessing_TestNotAvailableTLV(c2c))            # Shall return False
    #asyncio.ensure_future(test_iC2CCETP_startCETPProcessing_OROperation1notAvailableRLOCs(c2c))       # Shall return None/True
    #asyncio.ensure_future(test_iC2CCETP_startCETPProcessing_OROperationNnotAvailableRLOCs(c2c))       # Shall return False
    #asyncio.ensure_future(test_iH2HCETP_startCETPProcessing_CommDeniedByPolicy())                # Shall return False        - Not implemented yet.
    
    # -------- Post-c2c negotiation -----------
    #asyncio.ensure_future(test_iH2HCETP_ForbiddenSender())
    
    """ Testing local H2HTransactions """
    #asyncio.ensure_future(test_localH2H(h2h))
    #asyncio.ensure_future(test_forbiddenSender(h2h))
    #asyncio.ensure_future(test_forbiddenDestination(h2h))


def instantiate_c2cOutboundTransaction(loop, ip_addr, dst_id):
    import yaml, CETPSecurity, ConnectionTable, PolicyManager

    cesid                  = "cesa.lte."
    cetp_policies          = "config_cesa/cetp_policies.json"
    filename               = "config_cesa/config_cesa_ct.yaml"
    config_file            = open(filename)
    ces_conf               = yaml.load(config_file)
    ces_params             = ces_conf['CESParameters']
    conn_table             = ConnectionTable.ConnectionTable()
    cetpstate_mgr          = ConnectionTable.CETPStateTable()                                       # Records the established CETP transactions (both H2H & C2C). Required for preventing the re-allocation already in-use SST & DST (in CETP transaction).
    cetp_security          = CETPSecurity.CETPSecurity(loop, conn_table, ces_params)
    interfaces             = PolicyManager.FakeInterfaceDefinition(cesid)
    policy_mgr             = PolicyManager.PolicyManager(cesid, policy_file=cetp_policies)          # Shall ideally fetch the policies from Policy Management System (of Hassaan)    - And will be called, policy_sys_agent
    host_register          = PolicyManager.HostRegister()
    cetp_mgr               = MockCETPManager()
    c2c_layer              = MockCETPC2CLayer()
    remote_addr            = ("10.0.3.101", 54432)
    
    c2c = oC2CTransaction(loop, l_cesid=cesid, r_cesid="cesb.lte.", cetpstate_mgr=cetpstate_mgr, policy_mgr = policy_mgr, proto = "tls", ces_params = ces_params, \
                          cetp_security = cetp_security, interfaces = interfaces, c2c_layer=c2c_layer, conn_table=conn_table, cetp_mgr=cetp_mgr, remote_addr=remote_addr)
    
    return c2c



def instantiate_c2cInboundTransaction(loop, ip_addr, dst_id):
    import yaml, CETPSecurity, ConnectionTable, PolicyManager

    cesid                  = "cesb.lte."
    cetp_policies          = "config_cesb/cetp_policies.json"
    filename               = "config_cesb/config_cesb_ct.yaml"
    config_file            = open(filename)
    ces_conf               = yaml.load(config_file)
    ces_params             = ces_conf['CESParameters']
    conn_table             = ConnectionTable.ConnectionTable()
    cetpstate_mgr          = ConnectionTable.CETPStateTable()                                       # Records the established CETP transactions (both H2H & C2C). Required for preventing the re-allocation already in-use SST & DST (in CETP transaction).
    cetp_security          = CETPSecurity.CETPSecurity(loop, conn_table, ces_params)
    interfaces             = PolicyManager.FakeInterfaceDefinition(cesid)
    policy_mgr             = PolicyManager.PolicyManager(cesid, policy_file=cetp_policies)          # Shall ideally fetch the policies from Policy Management System (of Hassaan)    - And will be called, policy_sys_agent
    host_register          = PolicyManager.HostRegister()
    c2c_layer              = MockCETPC2CLayer()
    remote_addr            = ("10.0.3.101", 54432)
    cetp_mgr               = MockCETPManager()
    
    c2c = iC2CTransaction(loop, r_addr=remote_addr, l_cesid=cesid, policy_mgr=policy_mgr, cetpstate_mgr=cetpstate_mgr, ces_params=ces_params, proto="tls", \
                          cetp_security=cetp_security, interfaces=interfaces, conn_table=conn_table, cetp_mgr=cetp_mgr)
    return c2c

"""Need to test both the server and the client"""

if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.get_event_loop()
    #ip_addr, dst_id = "10.0.3.111", "srv1.hosta2.cesa.lte."
    #h2h = instantiate_h2hLocalTransaction(loop, ip_addr, dst_id)
    
    ip_addr, dst_id = "10.0.3.111", "srv1.hostb1.cesb.lte."
    c2c = instantiate_c2cOutboundTransaction(loop, ip_addr, dst_id)
    #c2c = instantiate_c2cInboundTransaction(loop, ip_addr, dst_id)
    test_function(c2c, ip_addr, dst_id)
    
    
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Ctrl+C Handled")
    finally:
        loop.close()
