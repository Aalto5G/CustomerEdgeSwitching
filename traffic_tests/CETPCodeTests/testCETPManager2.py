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
from asyncio.tasks import async


""" Test functions """

def some_cb(dns_q, addr, r_addr=None, success=True):
    print("H2HTransaction success = '{}'".format(success))

def test_output(cetp_mgr):
    print("\n\n")
    print("CETP endpoints: ", cetp_mgr._cetp_endpoints )
    print("C2C Layers: ", cetp_mgr.c2c_register )

def output_system_states(cetp_mgr, r_cesid):
    print("\n\nTesting results:")
    print("cetp_mgr.has_cetp_endpoint(r_cesid)", cetp_mgr.has_cetp_endpoint(r_cesid))
    print("cetp_mgr.has_c2c_layer", cetp_mgr.has_c2c_layer(r_cesid))
    #print("CETP session states:\n", cetp_mgr.cetpstate_mgr.cetp_transactions[ConnectionTable.KEY_ESTABLISHED_CETP])
    print("Connection Table:\n", cetp_mgr.conn_table.connection_dict)

@asyncio.coroutine
def test_dropReConnectsFromUnverifiedSenders(cetp_mgr):
    unverifiable_ip = "10.0.3.103"
    cetp_mgr.cetp_security.register_unverifiable_cetp_sender(unverifiable_ip)
    yield from asyncio.sleep(15)
    test_output(cetp_mgr)

@asyncio.coroutine
def test_processDNSMessage(cetp_mgr):
    sender_info = ("10.0.3.111", 43333)
    cb_args = ("SomeValue", sender_info)
    dst_id = "srv1.hosta1.cesa.lte."
    cetp_mgr.process_dns_message(some_cb, cb_args, dst_id)
    yield from asyncio.sleep(2)
    
    dst_id = "srv1.hostb1.cesb.lte."
    naptr_list =  [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'), ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls')]
    cetp_mgr.process_dns_message(some_cb, cb_args, dst_id, r_cesid= "cesb.lte.", naptr_list=naptr_list)
    yield from asyncio.sleep(2)

    
@asyncio.coroutine   
def test_local_cetp(cetp_mgr):
    sender_info = ("10.0.3.111", 43333)
    cb_args = (2, sender_info)
    dst_id = "hosta2.cesa.lte."
    asyncio.sleep(0.2)
    cetp_mgr.process_local_cetp(some_cb, cb_args, dst_id)

@asyncio.coroutine
def test_local_cetp_forbidden_destination(cetp_mgr):
    sender_info = ("10.0.3.111", 43333)
    cb_args = ("Some value", sender_info)
    dst_id = "srv1.hosta1.cesa.lte."
    cetp_mgr.block_connections_to_local_domain(l_domain=dst_id)
    asyncio.sleep(0.2)
    cetp_mgr.process_local_cetp(some_cb, cb_args, dst_id)


@asyncio.coroutine
def test_naptr_flood(cetp_mgr):
    """ Tests the establishment of CETP-H2H, CETP-C2C layer and CETPTransport(s) towards r-ces upon getting a list of NAPTR records."""
    sender_info = ("10.0.3.111", 43333)
    l_hostid, l_hostip = "hosta1.cesa.lte.", sender_info[0]
    dst_id, r_cesid, r_ip, r_port, r_proto = "", "", "", "", ""
    naptr_records = {}
    naptr_records['srv1.hostb1.cesb.lte.']         = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'), ('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls')]    
    naptr_list = naptr_records['srv1.hostb1.cesb.lte.']
    cb_args = ("SomeValue", sender_info)
    
    st = time.time()
    for it in range(0, 5000):
        n = naptr_list[:]
        dst_id, r_cesid, r_ip, r_port, r_proto = n[0]
        yield from asyncio.sleep(random.uniform(0, 0.001))
        #cetp_mgr.process_outbound_cetp(some_cb, cb_args, dst_id, r_cesid, n)
        cetp_mgr.process_dns_message(some_cb, cb_args, dst_id, r_cesid=r_cesid, naptr_list=n)

    #et = time.time() - st
    #print("Total time", et)
    
    test_output(cetp_mgr)
    yield from asyncio.sleep(4)
    test_output(cetp_mgr)

@asyncio.coroutine
def test_cetpEpCreationDeletion(cetp_mgr):
    """ Tests the establishment of CETP-H2H, CETP-C2C layer and CETPTransport(s) towards r-ces upon getting a list of NAPTR records."""
    ep = cetp_mgr.create_cetp_endpoint("cesb.lte")
    ep.get_cetp_c2c_layer()
    test_output(cetp_mgr)    
    yield from asyncio.sleep(0.2)
    cetp_mgr.close_all_cetp_endpoints()
    yield from asyncio.sleep(0.2)
    test_output(cetp_mgr)    
    
@asyncio.coroutine
def test_startStopCETPListeningService(cetp_mgr):
    print("Listening servers", cetp_mgr._serverEndpoints)
    for ep in cetp_mgr._serverEndpoints:
        cetp_mgr.close_server_endpoint(ep)
    
    yield from asyncio.sleep(1)
    print("Listening servers", cetp_mgr._serverEndpoints)
    
@asyncio.coroutine
def test_reconnectsToUnreachabale(cetp_mgr):
    rip, rport, rproto = "10.0.3.103", '49001', "tls"
    cetp_mgr.cetp_security.register_unreachable_cetp_addr(rip, rport, rproto)
    rip, rport, rproto = "10.0.3.103", '49002', "tls"
    cetp_mgr.cetp_security.register_unreachable_cetp_addr(rip, rport, rproto)
    yield from asyncio.sleep(0.1)
    print(cetp_mgr.cetp_security.unverifiable_cetp_addrs)
    yield from test_cetp_layering(cetp_mgr)
    

@asyncio.coroutine
def test_terminate_cetp_c2c_signalling(cetp_mgr):
    """ Terminate C2C signalling between two CES nodes """
    sender_info, naptr_records, l_hostid, l_hostip = yield from test_cetp_layering(cetp_mgr)
    dst_id, r_cesid, r_ip, r_port, r_proto = "", "", "", "", ""
    yield from asyncio.sleep(0.5)
    
    print("\nInitiating second H2H query")
    for naptr_rr in naptr_records['srv2.hostb1.cesb.lte.']:
        dst_id, r_cesid, r_ip, r_port, r_proto = naptr_rr
        naptr_list = naptr_records['srv2.hostb1.cesb.lte.']
        
    cetp_mgr.process_outbound_cetp(some_cb, (2, sender_info), dst_id, r_cesid, naptr_list)    
    yield from asyncio.sleep(0.5)
    
    #cetp_mgr.terminate_cetp_c2c_signalling(r_cesid, terminate_h2h=False)
    #cetp_mgr.terminate_cetp_c2c_signalling(r_cesid, terminate_h2h=True)
    cetp_mgr.terminate_rces_h2h_sessions(r_cesid)

    print("Displaying output")
    r_cesid = "cesb.lte."
    output_system_states(cetp_mgr, r_cesid)
    yield from asyncio.sleep(1)


@asyncio.coroutine
def test_h2h_session_termination(cetp_mgr):
    """ Tests termination of H2H-CETP sessions based on different parameters: Local host-ID, Local host-IP, remote host-ID and (sender-ID, dst-ID) pair. """
    sender_info, naptr_records, l_hostid, l_hostip = yield from test_cetp_layering(cetp_mgr)
    cb_args = (2, sender_info)
    dst_id, r_cesid, r_ip, r_port, r_proto = "", "", "", "", ""
    yield from asyncio.sleep(0.5)
    sender_ip = "10.0.3.111"
    sender_id = "hosta1.cesa.lte."
    
    print("\nInitiating second H2H query")
    for naptr_rr in naptr_records['srv2.hostb1.cesb.lte.']:
        dst_id, r_cesid, r_ip, r_port, r_proto = naptr_rr
        naptr_list = naptr_records['srv2.hostb1.cesb.lte.']
        
    cetp_mgr.process_outbound_cetp(some_cb, cb_args, dst_id, r_cesid, naptr_list)    
    yield from asyncio.sleep(2)
    
    # Pick one of the following tests
    # Tests termination of H2H-CETP sessions involving a particular local-host, based on host-ID or host-IP
    #print("Request to terminate H2H-CETP sessions involving the host-id <{}>.".format(l_hostid))         # Does it close all session initiated by a host-id or all sessions involving a hostid?
    #cetp_mgr.terminate_local_host_sessions(l_hostid = sender_id)
    #cetp_mgr.terminate_local_host_sessions(lip = sender_ip)
    
    # Tests termination of session with a remote host
    cetp_mgr.terminate_remote_host_sessions("srv1.hostb1.cesb.lte.")
    #cetp_mgr.terminate_host_session_by_fqdns(l_hostid="hosta1.cesa.lte.", r_hostid="srv1.hostb1.cesb.lte.")
    
    
    print("Displaying output")
    r_cesid = "cesb.lte."
    output_system_states(cetp_mgr, r_cesid)
    yield from asyncio.sleep(1)

@asyncio.coroutine    
def test_local_h2h_session_termination(cetp_mgr):
    """ Tests termination of H2H-CETP sessions based on different parameters: Local host-ID, Local host-IP, remote host-ID and (sender-ID, dst-ID) pair. """
    yield from test_local_cetp(cetp_mgr)
    sender_info = ("10.0.3.111", 54433)
    cb_args = (2, sender_info)
    
    sender_ip = "10.0.3.111"
    sender_id = "hosta1.cesa.lte."
    yield from asyncio.sleep(1)
    
    # Pick one of the following tests
    # Tests termination of H2H-CETP sessions involving a particular local-host, based on host-ID or host-IP
    #print("Request to terminate H2H-CETP sessions involving the host-id <{}>.".format(l_hostid))         # Does it close all session initiated by a host-id or all sessions involving a hostid?
    
    cetp_mgr.terminate_local_host_sessions(l_hostid = sender_id)                                        # Connection table at remote end still has entries.
    #cetp_mgr.terminate_local_host_sessions(lip = sender_ip)                                            # True for all tests here.
    
    # Tests termination of session with a remote host
    #cetp_mgr.terminate_remote_host_sessions("srv1.hostb1.cesb.lte.")
    #cetp_mgr.terminate_host_session_by_fqdns(l_hostid="hosta1.cesa.lte.", r_hostid="srv1.hostb1.cesb.lte.")
    
    
    print("Displaying output")
    r_cesid = "cesb.lte."
    output_system_states(cetp_mgr, r_cesid)
    yield from asyncio.sleep(1)
    
    

@asyncio.coroutine
def test_drop_connection(cetp_mgr):
    """ Checks whether CETPSecurity module can block connection requests to/from undesired parties. """
    sender_info, naptr_records, l_hostid, l_hostip = yield from test_cetp_layering(cetp_mgr)
    dst_id, r_cesid, r_ip, r_port, r_proto = "", "", "", "", ""
    r_cesid = "cesb.lte."
    yield from asyncio.sleep(0.5)
    
    # Pick one of the test, to check whether inbound/outbound connections to/from undesired local domains are blocked
    l_domain = "srv1.hosta1.cesa.lte."
    
    #cetp_mgr.block_connections_from_local_domain(l_domain=l_hostid)
    #cetp_mgr.block_connections_from_local_domain(l_domain=l_hostid, r_cesid=r_cesid)
    cetp_mgr.block_connections_to_local_domain(l_domain=l_domain, r_cesid=r_cesid)                  # -- No message sent to remote CES
    #cetp_mgr.block_connections_to_local_domain(l_domain=l_domain)
    
    # Pick one of the test, to check whether inbound/outbound connections from undesired remote domains are blocked
    r_hostid ="hostb1.cesb.lte."
    r_cesid  = "cesb.lte."
    #cetp_mgr.block_connections_from_remote_ces_host(r_hostid=r_hostid)
    #cetp_mgr.block_connections_from_remote_ces_host(r_hostid=r_hostid, r_cesid=r_cesid)
    #cetp_mgr.block_connections_to_remote_ces_host(r_hostid="srv2.hostb1.cesb.lte.")
    #cetp_mgr.block_connections_to_remote_ces_host(r_hostid="srv2.hostb1.cesb.lte.", r_cesid="cesb.lte.")
    
    #cetp_mgr.disable_local_domain(local_domain="hosta1.cesa.lte.")
    #cetp_mgr.report_misbehavior_evidence(lip="10.0.3.111", lpip="", evidence="")                    # No evidence sending encoding yet. in post-c2c- negotiation processing.
    yield from asyncio.sleep(0.5)
    
    print("\nInitiating second H2H query")
    for naptr_rr in naptr_records['srv2.hostb1.cesb.lte.']:
        dst_id, r_cesid, r_ip, r_port, r_proto = naptr_rr
        naptr_list = naptr_records['srv2.hostb1.cesb.lte.']
        
    cetp_mgr.process_outbound_cetp(some_cb, (2, sender_info), dst_id, r_cesid, naptr_list)    
    
    yield from asyncio.sleep(2)

    print("Displaying output")
    r_cesid = "cesb.lte."
    output_system_states(cetp_mgr, r_cesid)
    yield from asyncio.sleep(1)

def test_cetp_ep_creation(cetp_mgr):
    """ Testing the addition of a new cetp_endpoint """
    r_cesid = "random_ces.lte."
    cetp_ep = cetp_mgr.create_cetp_endpoint(r_cesid)
    assert cetp_mgr.has_cetp_endpoint(r_cesid)==True

@asyncio.coroutine
def test_cetp_layering2(cetp_mgr):
    """ Tests the establishment of CETP-H2H, CETP-C2C layer and CETPTransport(s) towards r-ces upon getting a list of NAPTR records."""
    sender_info = ("10.0.3.111", 43333)
    l_hostid, l_hostip = "hosta1.cesa.lte.", sender_info[0]
    dst_id, r_cesid, r_ip, r_port, r_proto = "", "", "", "", ""
    naptr_records = {}
    naptr_records['srv1.hostb1.cesb.lte.']         = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls'), ('srv2.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls')]
    print("Initiating H2H negotiation towards '{}'".format(dst_id))
    naptr_list = naptr_records['srv1.hostb1.cesb.lte.']    
    cb_args = ("SomeValue", sender_info)

    dst_id, r_cesid, r_ip, r_port, r_proto = naptr_list[0]
    cetp_mgr.process_outbound_cetp(some_cb, cb_args, dst_id, r_cesid, naptr_list)    
    #return (sender_info, naptr_records, l_hostid, l_hostip)
    test_output(cetp_mgr)
    yield from asyncio.sleep(2)
    test_output(cetp_mgr)
    output_system_states(cetp_mgr, r_cesid)
    
@asyncio.coroutine
def test_cetp_layering(cetp_mgr):
    """ Establishes the CETP relation with remote CES, used for testing """
    sender_info = ("10.0.3.111", 43333)
    l_hostid, l_hostip = "hosta1.cesa.lte.", sender_info[0]
    dst_id, r_cesid, r_ip, r_port, r_proto = "", "", "", "", ""
    naptr_records = {}
    naptr_records['srv1.hostb1.cesb.lte.']         = [('srv1.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49001', 'tls')]
    naptr_records['srv2.hostb1.cesb.lte.']         = [('srv2.hostb1.cesb.lte.',     'cesb.lte.', '10.0.3.103', '49002', 'tls')]
    
    naptr_list = naptr_records['srv1.hostb1.cesb.lte.'] 
    
    print("Initiating 1st H2H negotiation")
    dst_id, r_cesid, r_ip, r_port, r_proto = naptr_list[0]
    cb_args = ("some", sender_info)
    cetp_mgr.process_outbound_cetp(some_cb, cb_args, dst_id, r_cesid, naptr_list)    
    yield from asyncio.sleep(2)
    return (sender_info, naptr_records, l_hostid, l_hostip)


def createCETPManager(loop):
    try:
        config_file     = "config_cesa/config_cesa_ct.yaml"
        ces_conf        = yaml.load(open(config_file))
        ces_params      = ces_conf['CESParameters']
        cesid           = ces_params['cesid']
        cetp_policies   = ces_conf["cetp_policy_file"]
        logging.basicConfig(level=logging.DEBUG)
        cetp_mgr = CETPManager(cetp_policies, cesid, ces_params, loop=loop)
        cetp_mgr.initiate_cetp_service("10.0.3.101", 48001, "tls")
        return cetp_mgr
    
    except Exception as ex:
        print("Exception in _load_configuration(): ", ex)
    
    
def test_func(loop):
    #asyncio.ensure_future(test_cetp_layering(cetp_mgr))
    #asyncio.ensure_future(test_cetp_layering2(cetp_mgr))
    #asyncio.ensure_future(test_local_cetp(cetp_mgr))
    #asyncio.ensure_future(test_local_h2h_session_termination(cetp_mgr))
    #asyncio.ensure_future(test_h2h_session_termination(cetp_mgr))
    asyncio.ensure_future(test_drop_connection(cetp_mgr))
    #asyncio.ensure_future(test_terminate_cetp_c2c_signalling(cetp_mgr))
    #asyncio.ensure_future(test_cetpEpCreationDeletion(cetp_mgr))
    #asyncio.ensure_future(test_startStopCETPListeningService(cetp_mgr))
    #asyncio.ensure_future(test_reconnectsToUnreachabale(cetp_mgr))
    #asyncio.ensure_future(test_naptr_flood(cetp_mgr))
    #asyncio.ensure_future(test_processDNSMessage(cetp_mgr))

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    cetp_mgr = createCETPManager(loop)
    
    if cetp_mgr is not None:    
        print("Ready for testing")
        test_func(loop)
    
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            print("Ctrl+C Handled")
        finally:
            loop.close()