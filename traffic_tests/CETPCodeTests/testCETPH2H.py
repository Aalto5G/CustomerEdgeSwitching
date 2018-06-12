import asyncio
import logging
import signal
import socket
import sys
import random
import time
import traceback
import json
import yaml
import ssl
import functools
import copy

import cetpManager
from cetpManager import CETPManager
import CETP
import C2CTransaction
import H2HTransaction
import CETPH2H
import CETPC2C
import CETPTransports
import PolicyManager
import CETPSecurity
import ConnectionTable


class MockCETPManager:
    def remove_c2c_layer(self, r_cesid):        pass
    def remove_cetp_endpoint(self, r_cesid):    pass

def getLocalCETP(loop):
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
    #cetp_mgr               = cetpManager.CETPManager(cetp_policies, cesid, ces_params, loop=loop)
    cetp_mgr               = MockCETPManager()
    local_h2h              = CETPH2HLocal(l_cesid=cesid, cetpstate_mgr=cetpstate_mgr, policy_mgr=policy_mgr, cetp_mgr=cetp_mgr, \
                                         cetp_security=cetp_security, host_register=host_register, conn_table=conn_table)
    return local_h2h

@asyncio.coroutine
def testing_Localoutput(h):
    h.set_closure_signal()

@asyncio.coroutine
def test_singleAQuery(h):    
    dst_id = 'srv1.hosta1.cesa.lte.'
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb = (test_cb, cb_args)
    
    h.resolve_cetp(dst_id, cb)
    yield from asyncio.sleep(2)

    asyncio.ensure_future(testing_Localoutput(h))
    yield from asyncio.sleep(2)

@asyncio.coroutine
def test_FloodAQuery(h):
    # Also find maximum limit of H2H queries handled locally.
    dst_id = 'srv1.hosta1.cesa.lte.'
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb = (test_cb, cb_args)

    for it in range(0, 1000):
        h.resolve_cetp(dst_id, cb) 
        if it % 100 == 0:
            yield from asyncio.sleep(0.5)
    
    yield from asyncio.sleep(4)
    asyncio.ensure_future(testing_Localoutput(h))
    yield from asyncio.sleep(2)

def set_closed(h):
    h.set_closure_signal()

@asyncio.coroutine
def test_ratelimit(h, loop):
    # Also find maximum limit of H2H queries handled locally.
    dst_id = 'srv1.hosta1.cesa.lte.'
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb = (test_cb, cb_args)
    loop.call_later(1.0, set_closed, h)
    num = 7000
    
    for it in range(0, num):
        if h._closure_signal == True:
            break
        h.resolve_cetp(dst_id, cb)
        yield from asyncio.sleep(0.000001)
    
    yield from asyncio.sleep(4)
    asyncio.ensure_future(testing_Localoutput(h))
    yield from asyncio.sleep(2)


def get_h2hLayer(loop):
    import yaml, CETPSecurity, ConnectionTable, PolicyManager
    
    cesid                  = "cesa.lte."
    r_cesid                = "cesb.lte."
    cetp_policies          = "config_cesa/cetp_policies.json"
    filename               = "config_cesa/config_cesa_ct.yaml"
    config_file            = open(filename)
    ces_conf               = yaml.load(config_file)
    ces_params             = ces_conf['CESParameters']
    ces_params["max_c2c_transports"] = 2
    conn_table             = ConnectionTable.ConnectionTable()
    cetpstate_mgr          = ConnectionTable.CETPStateTable()                                       # Records the established CETP transactions (both H2H & C2C). Required for preventing the re-allocation already in-use SST & DST (in CETP transaction).
    cetp_security          = CETPSecurity.CETPSecurity(loop, conn_table, ces_params)
    interfaces             = PolicyManager.FakeInterfaceDefinition(cesid)
    policy_mgr             = PolicyManager.PolicyManager(cesid, policy_file=cetp_policies)          # Shall ideally fetch the policies from Policy Management System (of Hassaan)    - And will be called, policy_sys_agent
    host_register          = PolicyManager.HostRegister()
    #cetp_mgr               = cetpManager.CETPManager(cetp_policies, cesid, ces_params, loop=loop)
    cetp_mgr               = MockCETPManager()
    h                      = CETPH2H(l_cesid = cesid, r_cesid = r_cesid, cetpstate_mgr= cetpstate_mgr, policy_mgr=policy_mgr, policy_client=None, \
                                     loop=loop, cetp_mgr=cetp_mgr, ces_params=ces_params, cetp_security=cetp_security, host_register=host_register, \
                                     interfaces=interfaces, conn_table=conn_table)
    
    c2c = CETPC2C.CETPC2CLayer(loop, l_cesid=cesid, r_cesid=r_cesid, cetpstate_mgr= cetpstate_mgr, policy_mgr=policy_mgr, conn_table=conn_table, \
                               ces_params=ces_params, cetp_security=cetp_security, cetp_mgr=cetp_mgr, cetp_h2h=h, interfaces=interfaces)
    h.c2c = c2c
    return h

def test_cb(a,b,r_addr=None, success=False):
    if success:     print("H2H Success")
    else:           print("H2H failed")

@asyncio.coroutine
def test_naptrResponse(h):
    naptr_rrs = []
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'))
    #naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49004', 'tls'))
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls'))
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49003', 'tls'))
    
    dst_id = 'srv1.hostb1.cesb.lte.'
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb = (test_cb, cb_args)
    
    h.process_naptrs(dst_id, naptr_rrs, cb)
    yield from asyncio.sleep(2)

    for it in range(0, 1000):
        h.process_naptrs(dst_id, naptr_rrs, cb) 
        if it % 100 == 0:
            yield from asyncio.sleep(0.5)
    
    asyncio.ensure_future(testing_output(h))
    yield from asyncio.sleep(2)

@asyncio.coroutine
def test_naptrFlood(h):
    """ A NAPTR flood """
    naptr_rrs = []
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'))
    #naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49004', 'tls'))
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls'))
    naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49003', 'tls'))
    
    dst_id = 'srv1.hostb1.cesb.lte.'
    cb_args = ("SomeQ", ("10.0.3.111", 55443))
    cb = (test_cb, cb_args)

    for it in range(0, 1000):
        h.process_naptrs(dst_id, naptr_rrs, cb) 
        if it % 100 == 0:
            yield from asyncio.sleep(0.5)
        
    yield from asyncio.sleep(8)
    asyncio.ensure_future(testing_output(h))
    yield from asyncio.sleep(2)


@asyncio.coroutine
def testing_output(h):
    print("------- Test completed ----")
    print("C2C connected: ", h._isConnected())
    yield from test_resourceCleanup(h)

@asyncio.coroutine
def test_resourceCleanup(h):
    h.handle_interrupt()
    yield from asyncio.sleep(1)

@asyncio.coroutine
def test_transportFailover(h):
    try:
        import os
        naptr_rrs = []
        naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'))
        #naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49004', 'tls'))
        naptr_rrs.append(('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls'))
        
        dst_id = 'srv1.hostb1.cesb.lte.'
        cb_args = ("SomeQ", ("10.0.3.111", 55443))
        cb = (test_cb, cb_args)
        
        dport = 49002
        ipt_cmd = "sudo iptables -A OUTPUT -p tcp --dport {} -j DROP".format(dport)
        os.popen(ipt_cmd)
        yield from asyncio.sleep(0.2)
    
        for it in range(0, 1000):
            h.process_naptrs(dst_id, naptr_rrs, cb) 
            if it % 100 == 0:
                yield from asyncio.sleep(0.5)
        
        yield from asyncio.sleep(4)
        asyncio.ensure_future(testing_output(h))
        yield from asyncio.sleep(2)
        
    except Exception as ex:
        print("test_transportFailover", ex)
    finally:
        dport = 49002
        ipt_cmd = "sudo iptables -D OUTPUT -p tcp --dport {} -j DROP".format(dport)
        os.popen(ipt_cmd)
        yield from asyncio.sleep(0.2)

@asyncio.coroutine
def test_forbiddenSender(h):
    import CETPSecurity
    h.cetp_security.register_filtered_domains(CETPSecurity.KEY_BlacklistedLHosts, "hosta1.cesa.lte.")
    yield from asyncio.sleep(0.1)
    yield from test_singleAQuery(h)

@asyncio.coroutine
def test_forbiddenDestination(h):
    import CETPSecurity
    h.cetp_security.register_filtered_domains(CETPSecurity.KEY_LocalHosts_Inbound_Disabled, "srv1.hosta1.cesa.lte.")
    yield from asyncio.sleep(0.1)
    yield from test_singleAQuery(h)

           
def test_functions(h, loop):
    #For H2H-CETP
    #asyncio.ensure_future(test_naptrResponse(h))
    #asyncio.ensure_future(test_naptrFlood(h))
    #asyncio.ensure_future(test_transportFailover(h))
    #asyncio.ensure_future(test_resourceCleanup(h))
    
    #For LocalH2H-CETP
    #asyncio.ensure_future(test_singleAQuery(h))
    #asyncio.ensure_future(test_FloodAQuery(h))
    #asyncio.ensure_future(test_forbiddenSender(h))
    #asyncio.ensure_future(test_forbiddenDestination(h))
    asyncio.ensure_future(test_ratelimit(h, loop))
    
if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.get_event_loop()
    h = getLocalCETP(loop)
    #h = get_h2hLayer(loop)
    
    try:
        test_functions(h, loop)
        loop.run_forever()
    except KeyboardInterrupt:
        print("Ctrl+C Handled")
        #loop.run_until_complete(testing_Localoutput2(h, loop))
    except Exception as ex:
        print(ex)
    finally:
        loop.close()

