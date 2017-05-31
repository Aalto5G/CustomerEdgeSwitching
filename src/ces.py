#!/usr/bin/python3

import asyncio
import configparser
import dns
import logging
import signal
import sys
import traceback
import time
import yaml
import json
import cesdns
import cetpManager
import CETPH2H
import CETPC2C
import functools
import PolicyManager

LOGLEVELMAIN    = logging.INFO
LOGLEVELCES     = logging.DEBUG

def trace():
    print('Exception in user code:')
    print('-' * 60)
    traceback.print_exc(file=sys.stdout)
    print('-' * 60)
    
class CustomerEdgeSwitchv2(object):
    def __init__(self, loop, name='CustomerEdgeSwitch', config_file=None):
        self._logger = logging.getLogger(name)
        self._logger.warning('Enabling logger at INFO-level')
        logging.basicConfig(level=LOGLEVELMAIN)
        self._logger.setLevel(LOGLEVELCES)
        self._loop = loop                       # Gets the event loop
        #self._loop.set_debug(True)
        self._read_configuration(config_file)
        self._capture_signal()                  # Captures signals
        self._init_cetp()                       # Initializes CETP
        self._init_dns_server()                 # Initializes DNS
    
    def _capture_signal(self):
        for signame in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(getattr(signal, signame), lambda: asyncio.ensure_future(self._signal_handler(signame)))
    
    def _read_configuration(self, filename):
        config_file = open(filename)
        self.ces_conf = yaml.load(config_file)
        
    def _init_cetp(self):
        """ Initiate CETP manager... Manages CETPLocalManager() and CETPServers() """
        self.ces_params      = self.ces_conf['CESParameters']
        self.ces_name        = self.ces_params['name']
        self.cesid           = self.ces_params['cesid']
        self.ca_certificate  = self.ces_params['ca_certificate']                     # Could be a list of popular/trusted (certificate issuing) CA's certificates
        self._cetp_policies  = self.ces_conf["cetp_policy_file"]
        
        self.cetp_mgr = cetpManager.CETPManager(self._cetp_policies, self.cesid, self.ces_params, loop=self._loop)
        cetp_server_list = self.ces_conf["CETPServers"]["serverNames"]
        for srv in cetp_server_list:
            srv_info = self.ces_conf["CETPServers"][srv]
            srv_addr, srv_port, srv_proto = srv_info["ip"], srv_info["port"], srv_info["transport"]
            self.cetp_mgr.initiate_cetp_service(srv_addr, srv_port, srv_proto)

        
    def _init_dns_server(self):
        # Stores all DNS related parameters in a dictionary
        self._dns = {}
        self._dns['addr'], self._dns['node'] = {}, {}
        self._dns['soa'] = self.ces_conf['DNS']['soa']
        
        # Get address tuple configuration of DNS servers
        for k, v in self.ces_conf['DNS']['server'].items():
            self._dns['addr'][k] = (v['ip'], v['port'])
        
        addr = self._dns['addr']['loopback']
        self._logger.info('Creating DNS Server {} @{}:{}'.format('loopback', addr[0],addr[1]))
        factory = cesdns.DNSServer(cetp_mgr = self.cetp_mgr)
        self._loop.create_task(self._loop.create_datagram_endpoint(lambda: factory, local_addr=addr))

    
    @asyncio.coroutine
    def _signal_handler(self, signame):
        self._logger.critical('Got signal %s: exit' % signame)
        try:
            self._logger.info(" Closing the DNS listening servers.")
            self._logger.info(" Closing the CETP listening service.")
            self.cetp_mgr.close_server_endpoints()
            
            self._logger.info(" Closing the CETPEndpoints with remote CES nodes.")
            self.cetp_mgr.close_all_local_client_endpoints()
            yield from asyncio.sleep(0.2)                             # For graceful execution of Asyncio task.cancel() operations  # Could be repalced with asyncio.wait_for(*tasks)?
            
        except:
            trace()
        finally:
            self._loop.stop()
    
    def start(self):
        print('Starting CESv2...')
        self._loop.run_forever()
        
if __name__ == '__main__':
    try:
        loop = asyncio.get_event_loop()
        ces = CustomerEdgeSwitchv2(loop, config_file = sys.argv[1])
        ces.start()
    except Exception as e:
        print(format(e))
        trace()
    finally:
        loop.close()
    print('Bye!')
