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
import CETPSecurity


def test_cb(a,b,r_addr=None, success=False):
    if success: 
        print("H2H Success")
    else: 
        print("H2H failed")


def instantiate_h2hOutboundTransaction(loop, ip_addr, dst_id):
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
    
    h2h = H2HTransactionOutbound(loop=loop, cb=None, host_ip=ip_addr, src_id="", dst_id=dst_id, l_cesid="cesa.lte.", r_cesid="cesblte.", cetp_h2h=None, \
                                                ces_params=ces_params, policy_mgr=policy_mgr, cetpstate_mgr=cetpstate_mgr, host_register=host_register, \
                                                conn_table=conn_table, interfaces=interfaces, cetp_security=cetp_security)
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb      = (test_cb, cb_args)
    h2h.cb  = cb

    return h2h

def instantiate_h2hLocalTransaction(loop, ip_addr, dst_id):
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
    h2h = H2HTransactionLocal(loop=loop, cb=None, host_ip=ip_addr, src_id="", dst_id=dst_id, policy_mgr=policy_mgr, \
                              cetpstate_mgr=cetpstate_mgr, cetp_security= cetp_security, host_register=host_register, conn_table=conn_table)
    return h2h


def instantiate_h2hInboundTransaction(sstag, dstag):
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
    
    ih2h = H2HTransactionInbound(sstag=sstag, dstag=dstag, l_cesid=cesid, r_cesid="cesa.lte.", policy_mgr=policy_mgr, cetpstate_mgr=cetpstate_mgr, \
                                 interfaces=interfaces, conn_table=conn_table, cetp_security=cetp_security, ces_params=ces_params)
    return ih2h

@asyncio.coroutine
def test_oH2HCETP(h2h):
    cetp_message = yield from h2h.start_cetp_processing()
    print("cetp_message: ", cetp_message)

@asyncio.coroutine
def test_oH2HCETPFlood(h2h):
    cetp_message = yield from h2h.start_cetp_processing()
    print("cetp_message: ", cetp_message)

    N=1
    if cetp_message!=None:
        for it in range(0, N):
            print("iteration", it)
            cetp_message = h2h.continue_cetp_processing(cetp_message)
            print("cetp_message: ", cetp_message)


@asyncio.coroutine
def test_oH2HCETP_forbiddenSender(h2h):
    h2h.cetp_security.register_filtered_domains(CETPSecurity.KEY_BlacklistedLHosts, "hosta1.cesa.lte.")
    yield from asyncio.sleep(0.1)
    yield from test_oH2HCETP(h2h)

@asyncio.coroutine
def test_oH2HCETP_forbiddenDestination(h2h):
    h2h.cetp_security.register_filtered_domains(CETPSecurity.KEY_LocalHosts_Inbound_Disabled, "srv1.hosta1.cesa.lte.")
    yield from asyncio.sleep(0.1)
    yield from test_oH2HCETP(h2h)
    
@asyncio.coroutine
def test_oH2HCETP_ContinueProcessing_Success(h2h):
    cetp_message = yield from h2h.start_cetp_processing()

    cetp_msg = {'DST': 2828710051, \
                'TLV': [{'ope': 'info', 'value': 'srv1.hostb1.cesb.lte.', 'code': 'fqdn', 'group': 'id'}, \
                        {'ope': 'info', 'value': '195.148.124.145', 'code': 'caep', 'group': 'control'}], \
                'VER': 2, \
                'SST': 3857529019}
    
    res_msg = h2h.continue_cetp_processing(cetp_msg)
    if res_msg is not None:
        print("Result outcome", res_msg)
    

@asyncio.coroutine
def test_oH2HCETP_ContinueProcessing_WrongRemoteHostID(h2h):
    cetp_message = yield from h2h.start_cetp_processing()

    cetp_msg = {'DST': 2828710051, \
                'TLV': [{'ope': 'info', 'value': 'srv2.hostb1.cesb.lte.', 'code': 'fqdn', 'group': 'id'}, \
                        {'ope': 'info', 'value': '195.148.124.145', 'code': 'caep', 'group': 'control'}], \
                'VER': 2, \
                'SST': 3857529019}
    
    res_msg = h2h.continue_cetp_processing(cetp_msg)
    if res_msg is not None:
        print("Result outcome", res_msg)
    
@asyncio.coroutine
def test_oH2HCETP_ContinueProcessing_MissingTLVs(h2h):
    cetp_message = yield from h2h.start_cetp_processing()

    cetp_msg = {'DST': 2828710051, \
                'TLV': [{'ope': 'info', 'value': 'srv1.hostb1.cesb.lte.', 'code': 'fqdn', 'group': 'id'}], \
                'VER': 2, \
                'SST': 3857529019}
    
    res_msg = h2h.continue_cetp_processing(cetp_msg)
    if res_msg is not None:
        print("Result outcome", res_msg)

@asyncio.coroutine
def test_oH2HCETP_ContinueProcessing_TerminateTLV(h2h):
    cetp_message = yield from h2h.start_cetp_processing()

    cetp_msg = {'DST': 2828710051, \
                'TLV': [ {'ope': 'info', 'value': '', 'code': 'terminate', 'group': 'control'}], \
                'VER': 2, \
                'SST': 3857529019}
    
    res_msg = h2h.continue_cetp_processing(cetp_msg)
    if res_msg is not None:
        print("Result outcome", res_msg)

@asyncio.coroutine
def test_oH2HCETP_PreProcessing(h2h):
    cetp_message = yield from h2h.start_cetp_processing()

    cetp_msg = {'DST': 2828710051, \
                'TLV': [ {'ope': 'info', 'value': '', 'code': 'terminate', 'group': 'control'}], \
                'VER': 3, \
                'SST': 3857529019}
    
    res = _pre_process(cetp_msg)
    print("PreProcessing outcome", res)

def test_oH2HCETP_ContinueProcessing_notAvailableTLV(h2h):
    cetp_message = yield from h2h.start_cetp_processing()

    cetp_msg = {'DST': 2828710051, \
                'TLV': [{'ope': 'info', 'value': 'srv1.hostb1.cesb.lte.', 'code': 'fqdn', 'group': 'id'}, \
                        {'ope': 'info', 'cmp':'notAvailable', 'value': '195.148.124.145', 'code': 'caep', 'group': 'control'}], \
                'VER': 2, \
                'SST': 3857529019}
    
    res_msg = h2h.continue_cetp_processing(cetp_msg)
    if res_msg is not None:
        print("Result outcome", res_msg)

@asyncio.coroutine
def test_oH2HCETP_PostH2HNegotiation_Terminate(h2h):
    yield from test_oH2HCETP_ContinueProcessing_Success(h2h)
    
    cetp_msg = {'DST': 2828710051, \
                'TLV': [{'ope': 'info', 'value': '', 'code': 'terminate', 'group': 'control'}], \
                'VER': 2, \
                'SST': 3857529019}
    
    res_msg = h2h.post_h2h_negotiation(cetp_msg)
    if res_msg is not None:
        print("Result outcome", res_msg)

@asyncio.coroutine
def test_oH2HCETP_ContinueProcessing_WeirdMessage(h2h):
    cetp_message = yield from h2h.start_cetp_processing()

    cetp_msg = {'DST': 2828710051, \
                'TLV': [{'ope': 'info', 'value': 'srv1.hostb1.cesb.lte.', 'code': 'fqdn', 'group': 'id'}, \
                        {'ope': 'sdsinfo', 'value': '195.148.124.145', 'code': 'caep', 'group': 'control'}], \
                'VER': 2, \
                'SST': 3857529019}
    
    res_msg = h2h.continue_cetp_processing(cetp_msg)
    if res_msg is not None:
        print("Result outcome", res_msg)


@asyncio.coroutine
def test_iH2HCETP(h2h):
    cetp_message = yield from h2h.start_cetp_processing()
    print("cetp_message: ", cetp_message)
    
    if cetp_message != None:
        isst, idst = cetp_message["SST"], cetp_message["DST"]
        sst, dst = idst, isst
        ih2h = instantiate_h2hInboundTransaction(sst, dst)
        resp = ih2h.start_cetp_processing(cetp_message)
        print("\n\nIh2h cetp_message: ", resp)

@asyncio.coroutine
def test_iH2HCETP_Success():
    cetp_message =  {'VER': 2, 'DST': 0, 'TLV': [{'ope': 'info', 'value': 'srv1.hostb1.cesb.lte.', 'group': 'control', 'code': 'dstep'}, \
                                                 {'ope': 'info', 'value': 'hosta1.cesa.lte.', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'info', 'value': '195.148.124.145', 'group': 'control', 'code': 'caep'}, \
                                                 {'ope': 'query', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'query', 'group': 'control', 'code': 'caep'}], \
                     'SST': 2828710051}
    
    if cetp_message != None:
        isst, idst = cetp_message["SST"], cetp_message["DST"]
        sst, dst = idst, isst
        ih2h = instantiate_h2hInboundTransaction(sst, dst)
        resp = ih2h.start_cetp_processing(cetp_message)
        print("\n\nIh2h cetp_message: ", resp)
        
@asyncio.coroutine
def test_iH2HCETP_missingDstep():
    cetp_message =  {'VER': 2, 'DST': 0, 'TLV': [{'ope': 'info', 'value': 'hosta1.cesa.lte.', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'info', 'value': '195.148.124.145', 'group': 'control', 'code': 'caep'}, \
                                                 {'ope': 'query', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'query', 'group': 'control', 'code': 'caep'}], \
                     'SST': 2828710051}
    
    if cetp_message != None:
        isst, idst = cetp_message["SST"], cetp_message["DST"]
        sst, dst = idst, isst
        ih2h = instantiate_h2hInboundTransaction(sst, dst)
        resp = ih2h.start_cetp_processing(cetp_message)
        print("\n\nIh2h cetp_message: ", resp)

@asyncio.coroutine
def test_iH2HCETP_NonExistentDestination():
    cetp_message =  {'VER': 2, 'DST': 0, 'TLV': [{'ope': 'info', 'value': 'srv133.hostb1.cesb.lte.', 'group': 'control', 'code': 'dstep'}, \
                                                 {'ope': 'info', 'value': 'hosta1.cesa.lte.', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'info', 'value': '195.148.124.145', 'group': 'control', 'code': 'caep'}, \
                                                 {'ope': 'query', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'query', 'group': 'control', 'code': 'caep'}], \
                     'SST': 2828710051}
    
    if cetp_message != None:
        isst, idst = cetp_message["SST"], cetp_message["DST"]
        sst, dst = idst, isst
        ih2h = instantiate_h2hInboundTransaction(sst, dst)
        resp = ih2h.start_cetp_processing(cetp_message)
        print("\n\nIh2h cetp_message: ", resp)

@asyncio.coroutine
def test_iH2HCETP_CommDeniedByPolicy():
    cetp_message =  {'VER': 2, 'DST': 0, 'TLV': [{'ope': 'info', 'value': 'srv1.hostb1.cesb.lte.', 'group': 'control', 'code': 'dstep'}, \
                                                 {'ope': 'info', 'value': 'hoste1.cesa.lte.', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'info', 'value': '195.148.124.145', 'group': 'control', 'code': 'caep'}, \
                                                 {'ope': 'query', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'query', 'group': 'control', 'code': 'caep'}], \
                     'SST': 2828710051}
    
    if cetp_message != None:
        isst, idst = cetp_message["SST"], cetp_message["DST"]
        sst, dst = idst, isst
        ih2h = instantiate_h2hInboundTransaction(sst, dst)
        resp = ih2h.start_cetp_processing(cetp_message)
        print("\n\nIh2h cetp_message: ", resp)

@asyncio.coroutine
def test_iH2HCETP_LessOffers():
    cetp_message =  {'VER': 2, 'DST': 0, 'TLV': [{'ope': 'info', 'value': 'srv1.hostb1.cesb.lte.', 'group': 'control', 'code': 'dstep'}, \
                                                 {'ope': 'info', 'value': 'hosta1.cesa.lte.', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'query', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'query', 'group': 'control', 'code': 'caep'}], \
                     'SST': 2828710051}
    
    if cetp_message != None:
        isst, idst = cetp_message["SST"], cetp_message["DST"]
        sst, dst = idst, isst
        ih2h = instantiate_h2hInboundTransaction(sst, dst)
        resp = ih2h.start_cetp_processing(cetp_message)
        print("\n\nIh2h cetp_message: ", resp)


@asyncio.coroutine
def test_iH2HCETP_ForbiddenSender():
    cetp_message =  {'VER': 2, 'DST': 0, 'TLV': [{'ope': 'info', 'value': 'srv1.hostb1.cesb.lte.', 'group': 'control', 'code': 'dstep'}, \
                                                 {'ope': 'info', 'value': 'hosta1.cesa.lte.', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'info', 'value': '195.148.124.145', 'group': 'control', 'code': 'caep'}, \
                                                 {'ope': 'query', 'group': 'id', 'code': 'fqdn'}, \
                                                 {'ope': 'query', 'group': 'control', 'code': 'caep'}], \
                     'SST': 2828710051}
    
    if cetp_message != None:
        isst, idst = cetp_message["SST"], cetp_message["DST"]
        sst, dst = idst, isst
        ih2h = instantiate_h2hInboundTransaction(sst, dst)
        ih2h.cetp_security.add_filtered_domains(CETPSecurity.KEY_BlacklistedRHosts, "hosta1.cesa.lte.")
        
        resp = ih2h.start_cetp_processing(cetp_message)
        print("\n\nIh2h cetp_message: ", resp)

@asyncio.coroutine
def test_localH2H(h2h):
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb      = (test_cb, cb_args)
    h2h.cb  = cb
    result  = yield from h2h.start_cetp_processing()     # Returns True or False
    print(result)

@asyncio.coroutine
def test_forbiddenSender(h2h):
    h2h.cetp_security.register_filtered_domains(CETPSecurity.KEY_BlacklistedLHosts, "hosta1.cesa.lte.")
    yield from asyncio.sleep(0.1)
    yield from test_localH2H(h2h)

@asyncio.coroutine
def test_forbiddenDestination(h2h):
    h2h.cetp_security.register_filtered_domains(CETPSecurity.KEY_LocalHosts_Inbound_Disabled, "srv1.hosta1.cesa.lte.")
    yield from asyncio.sleep(0.1)
    yield from test_localH2H(h2h)
    
   
def test_function(h2h, ip_addr, dst_id):
    """ Testing CES/CETP oH2HTransactions """
    # For start processing
    #asyncio.ensure_future(test_oH2HCETP(h2h))
    #asyncio.ensure_future(test_oH2HCETPFlood(h2h))
    #asyncio.ensure_future(test_oH2HCETP_forbiddenSender(h2h))
    #asyncio.ensure_future(test_oH2HCETP_forbiddenDestination(h2h))
    
    # For continue processing
    #asyncio.ensure_future(test_oH2HCETP_ContinueProcessing_Success(h2h))
    asyncio.ensure_future(test_oH2HCETP_ContinueProcessing_WrongRemoteHostID(h2h))
    #asyncio.ensure_future(test_oH2HCETP_ContinueProcessing_MissingTLVs(h2h))
    #asyncio.ensure_future(test_oH2HCETP_ContinueProcessing_TerminateTLV(h2h))
    #asyncio.ensure_future(test_oH2HCETP_PreProcessing(h2h))
    #asyncio.ensure_future(test_oH2HCETP_ContinueProcessing_notAvailableTLV(h2h))
    #asyncio.ensure_future(test_oH2HCETP_PostH2HNegotiation_Terminate(h2h))
    #asyncio.ensure_future(test_oH2HCETP_ContinueProcessing_WeirdMessage(h2h))


    # ---- Testing H2HTransactionInbound against inbound CETP Message ---
    #asyncio.ensure_future(test_iH2HCETP(h2h))
    #asyncio.ensure_future(test_iH2HCETP_Success())
    #asyncio.ensure_future(test_iH2HCETP_missingDstep())
    #asyncio.ensure_future(test_iH2HCETP_NonExistentDestination())
    #asyncio.ensure_future(test_iH2HCETP_CommDeniedByPolicy())
    #asyncio.ensure_future(test_iH2HCETP_LessOffers())
    #asyncio.ensure_future(test_iH2HCETP_ForbiddenSender())
    
    """ Testing local H2HTransactions """
    #asyncio.ensure_future(test_localH2H(h2h))
    #asyncio.ensure_future(test_forbiddenSender(h2h))
    #asyncio.ensure_future(test_forbiddenDestination(h2h))


"""Need to test both the server and the client"""

if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.get_event_loop()
    #ip_addr, dst_id = "10.0.3.111", "srv1.hosta2.cesa.lte."
    #h2h = instantiate_h2hLocalTransaction(loop, ip_addr, dst_id)
    
    ip_addr, dst_id = "10.0.3.111", "srv1.hostb1.cesb.lte."
    h2h = instantiate_h2hOutboundTransaction(loop, ip_addr, dst_id)
    test_function(h2h, ip_addr, dst_id)
    
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Ctrl+C Handled")
    finally:
        loop.close()
