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
import copy
import cetpManager
import C2CTransaction
import H2HTransaction
import CETPH2H
import CETPTransports

LOGLEVEL_CETPC2CLayer          = logging.INFO


class MockH2H:
    def set_closure_signal(self): pass
    def consume_message_from_c2c(self, m): pass
    def start_h2h_consumption(self): pass
    def c2c_connectivity_report(self, connected=True):
        if connected:   print("C2C connected - H2H sessions can negotiate")
        else:           print("C2C connectivity broken")
    def resource_cleanup(self, connected=True): pass
    
class MockCETPManager:
    def remove_c2c_layer(self, r_cesid): pass
    def remove_cetp_endpoint(self, r_cesid): pass


def get_c2cLayer(loop):
    import yaml, CETPSecurity, ConnectionTable, PolicyManager
    
    cetp_h2h               = MockH2H()
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
    
    c = CETPC2CLayer(loop, cetp_h2h=cetp_h2h, l_cesid=cesid, r_cesid=r_cesid, cetpstate_mgr=cetpstate_mgr, cetp_security=cetp_security,\
                     policy_mgr=policy_mgr, interfaces=interfaces, ces_params=ces_params, cetp_mgr=cetp_mgr, conn_table=conn_table)
    return c

@asyncio.coroutine
def testing_output(c):
    print("Total Initiated transports: ", len(c.initiated_transports) )
    print("Total Established transports: ", len(c.connected_transports) )
    print("C2C Negotiated: ", c._is_c2c_negotiated())
    print("Whether C2C is ready to serve H2H layer: ", c.is_connected())
    
    if c.c2c_transaction is not None:
        print("C2C Transaction tags: ", c.c2c_transaction.sstag, c.c2c_transaction.dstag)
    else: print("C2C Transaction tags: ", c.c2c_transaction)
    c.resource_cleanup()

@asyncio.coroutine
def test_c2c_establishment(c):
    """ Tests the case when link to remote CES exists. Tests successful or failure to establish C2C layer.
    Tests that limit on no. of connections between CES nodes is enforced.
    """
    try:
        c.ces_params["max_c2c_transports"] = 2
        #naptr_rrs = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls')]
        naptr_rrs = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'), ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls')]
        #naptr_rrs = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'), \
        #             ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls'), \
        #             ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49003', 'tls')]

        c.process_naptrs(naptr_rrs) 
        yield from asyncio.sleep(3)
        asyncio.ensure_future(testing_output(c))
        yield from asyncio.sleep(2)
        return True
    except Exception as ex:
        print("Excepption '{}'".format(ex))
        return False

@asyncio.coroutine
def test_unreachable_ces(c):
    """ Tests the case when link to remote CES does not exists, i.e. Unreachable CES node """
    rces_ip_port_addrs = [("10.0.3.103", 49001), ("10.0.3.103", 49002)]
    
    try:
        import os
        for r in rces_ip_port_addrs:
            ip, port = r
            ipt_cmd = "sudo iptables -A OUTPUT -p tcp --dport {} -j DROP".format(port)
            os.popen(ipt_cmd)
        
        yield from asyncio.sleep(0.2)
        yield from test_c2c_establishment(c)
        
    except Exception as ex:
        print("Exception '{}' in test_unreachable_ep() ".format(ex))
    finally:
        for r in rces_ip_port_addrs:
            ip, port = r
            ipt_cmd = "sudo iptables -D OUTPUT -p tcp --dport {} -j DROP".format(port)
            os.popen(ipt_cmd)

@asyncio.coroutine
def test_repeated_conns(c):
    """ Checks that limit on max no. of connection between 2 CES nodes is enforced. """
    try:
        c.ces_params["max_c2c_transports"] = 2
        #naptr_rrs = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls')]
        #naptr_rrs = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'), ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls')]
        naptr_rrs = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'), \
                     ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls'), \
                     ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49003', 'tls')]

        for it in range(0, 15):
            c.process_naptrs(naptr_rrs) 
            yield from asyncio.sleep(0.2)
            
        yield from asyncio.sleep(5)
        asyncio.ensure_future(testing_output(c))
        yield from asyncio.sleep(2)
        return True
    
    except Exception as ex:
        print("Excepption '{}'".format(ex))
        return False


@asyncio.coroutine
def test_mixOfReachableAndUnreachableRLOCs(c):
    """ Checks that limit on max no. of connection between 2 CES nodes is enforced. """
    try:
        c.ces_params["max_c2c_transports"] = 2
        naptr_rrs = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'), \
                     ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49004', 'tls'), \
                     ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49003', 'tls')]

        for it in range(0, 15):
            c.process_naptrs(naptr_rrs) 
            yield from asyncio.sleep(0.2)
            
        yield from asyncio.sleep(5)
        asyncio.ensure_future(testing_output(c))
        yield from asyncio.sleep(2)
        return True
    
    except Exception as ex:
        print("Excepption '{}'".format(ex))
        return False


@asyncio.coroutine
def test_C2CLink_lostCase(c):
    """ Testing successful failover on failure of a connected transport """ 
    import os
    try:
        naptr_rrs = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'), ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls')]
        c.process_naptrs(naptr_rrs) 
        yield from asyncio.sleep(3)
        
        print("now")
        dport = 49001
        ipt_cmd = "sudo iptables -A OUTPUT -p tcp --dport {} -j DROP".format(dport)
        os.popen(ipt_cmd)
        print("sleeping")
        yield from asyncio.sleep(20)
        print("Output: ")
        asyncio.ensure_future(testing_output(c))
        yield from asyncio.sleep(2)
        
    except Exception as ex:
        print(ex)
    finally:
        dport = 49001
        ipt_cmd = "sudo iptables -D OUTPUT -p tcp --dport {} -j DROP".format(dport)
        os.popen(ipt_cmd)
        yield from asyncio.sleep(0.2)

            
@asyncio.coroutine
def test_C2CAllLink_lostCase(c):
    """ Output indicated by message to H2H layer on all link lost cases """ 
    import os
    try:
        naptr_rrs = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'), ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls')]
        c.process_naptrs(naptr_rrs) 
        yield from asyncio.sleep(3)
        
        print("now")
        dports = [49001, 49002]
        for d in dports:
            ipt_cmd = "sudo iptables -A OUTPUT -p tcp --dport {} -j DROP".format(d)
            os.popen(ipt_cmd)
            
        print("sleeping")
        yield from asyncio.sleep(20)
        print("output")
        asyncio.ensure_future(testing_output(c))
        yield from asyncio.sleep(2)
        
    except Exception as ex:
        print(ex)
    finally:
        dports = [49001, 49002]
        for d in dports:
            ipt_cmd = "sudo iptables -D OUTPUT -p tcp --dport {} -j DROP".format(d)
            os.popen(ipt_cmd)

@asyncio.coroutine
def test_interruptHandling(c):
    """ Output indicated by message to H2H layer on all link lost cases """ 
    pass

@asyncio.coroutine
def test_absorbingReconnectsToSameRCES(c):
    yield from test_mixOfReachableAndUnreachableRLOCs(c)
    yield from asyncio.sleep(2)
    yield from test_mixOfReachableAndUnreachableRLOCs(c)


def test_functions(loop):
    c = get_c2cLayer(loop)
    #asyncio.ensure_future(test_c2c_establishment(c))
    #asyncio.ensure_future(test_unreachable_ces(c))
    #asyncio.ensure_future(test_repeated_conns(c))
    #asyncio.ensure_future(test_mixOfReachableAndUnreachableRLOCs(c))
    #asyncio.ensure_future(test_absorbingReconnectsToSameRCES(c))
    asyncio.ensure_future(test_C2CLink_lostCase(c))
    #asyncio.ensure_future(test_C2CAllLink_lostCase(c))
    
if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.get_event_loop()
    
    try:
        test_functions(loop)
        loop.run_forever()
    except KeyboardInterrupt:
        print("Ctrl+C Handled")
    except Exception as ex:
        print(ex)
    finally:
        loop.close()
