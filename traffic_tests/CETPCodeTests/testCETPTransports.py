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
import PolicyManager
import CETPH2H
import CETPC2C
import asyncio

CETP_LEN_FIELD = 2

class MockC2C:
    def report_connectivity(self, t, status=True):
        print("Conn status: ", status)
        
    def consume_transport_message(self, cetp_msg, t):
        print("Received Message size:", len(cetp_msg))

@asyncio.coroutine
def test_connection(loop):
    import os, yaml, json
    ip_addr, port = "10.0.3.103", 49001
    remote_addr=(ip_addr, port)
    c2c_layer = MockC2C()
    print("Initiating CETPTransport towards ".format(remote_addr))
    config_file            = open("config_cesa/config_cesa_ct.yaml")
    ces_conf               = yaml.load(config_file)
    ces_params             = ces_conf['CESParameters']    
    ces_certificate_path   = ces_params['certificate']
    ces_privatekey_path    = ces_params['private_key']
    ca_certificate_path    = ces_params['ca_certificate']

    sc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sc.check_hostname = False
    #sc.verify_mode = ssl.CERT_NONE
    sc.verify_mode = ssl.CERT_REQUIRED
    sc.load_verify_locations(ca_certificate_path)
    sc.load_cert_chain(ces_certificate_path, ces_privatekey_path)
        
    try:
        t = oCESTCPTransport(c2c_layer, "tcp", "cesb.lte.", ces_params, remote_addr=remote_addr, loop=loop)
        #coro = loop.create_connection(lambda: t, ip_addr, port, ssl=sc)
        coro = loop.create_connection(lambda: t, ip_addr, port)
        connect_task = asyncio.ensure_future(coro)
        timeout = 2
        yield from asyncio.wait_for(connect_task, timeout)
        
    except Exception as ex:
        print("Exception '{}' towards r_cesid".format(ex))

@asyncio.coroutine
def test_unreachable_ep(loop):
    try:
        import os
        port_n = 49001
        ip_addr = "10.0.3.103"
        ipt_cmd = "sudo iptables -A OUTPUT -p tcp --dport {} -j DROP".format(port_n)
        os.popen(ipt_cmd)
        yield from asyncio.sleep(0.2)
        yield from test_connection(loop)
        
    except:
        print("Exception in test_unreachable_ep() ")
    finally:
        ipt_cmd = "sudo iptables -D OUTPUT -p tcp --dport {} -j DROP".format(port_n)
        os.popen(ipt_cmd)

def test_msg_framing(loop):
    ip_addr, port = "10.0.3.103", 49001
    remote_addr=(ip_addr, port)
    c2c_layer = MockC2C()
    print("Initiating CETPTransport towards ".format(remote_addr))
    ces_params={}
    ces_params["c2c_establishment_t0"] = 2
    
    msg="Take5 CETPv2"
    t = oCESTCPTransport(c2c_layer, "tcp", "cesb.lte.", ces_params, remote_addr=remote_addr, loop=loop)
    to_send = t.message_framing(msg)
    f=b''
    f+=to_send
    t.data_buffer = f
    t._process_data()
    print("Sent Message size:", len(msg))

@asyncio.coroutine
def test_keepalive_t0(loop):
    """ Run for about 20 sec to see behavior"""
    try:
        import os
        yield from test_connection(loop)
        port = 49001
        ipt_cmd = "sudo iptables -A OUTPUT -p tcp --dport {} -j DROP".format(port)
        os.popen(ipt_cmd)
        yield from asyncio.sleep(20)
        
    except:
        print("Exception in test_unreachable_ep() ")
    finally:
        ipt_cmd = "sudo iptables -D OUTPUT -p tcp --dport {} -j DROP".format(port)
        os.popen(ipt_cmd)

def test_function(loop):
    """ Client testing methods """
    #asyncio.ensure_future(test_connection(loop))
    #asyncio.ensure_future(test_unreachable_ep(loop))
    #asyncio.ensure_future(test_keepalive_t0(loop))
    #test_msg_framing(loop)
    
    """ Server testing methods """
    test_server(loop)


"""Need to test both the server and the client"""

if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.get_event_loop()
    test_function(loop)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print("Ctrl+C Handled")
    finally:
        loop.close()
