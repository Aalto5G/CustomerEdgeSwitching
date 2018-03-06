#!/usr/bin/python3.5

import asyncio
import aiohttp
import json
import logging
import time
import sys
import random
import traceback
import ssl
import copy

"""
import cetpManager
import C2CTransaction
import H2HTransaction
import CETPH2H
import CETPC2C
"""

LOGLEVEL_RESTPolicyClient = logging.INFO

# Aiohttp-based PolicyAgent in CES to retrieve CETP policies from Policy Management System
# Leveraging https://stackoverflow.com/questions/37465816/async-with-in-python-3-4


class RESTPolicyClient(object):
    def __init__(self, loop, tcp_conn_limit, verify_ssl=False, name="RESTPolicyClient"):
        self._loop              = loop
        self.tcp_conn_limit     = tcp_conn_limit
        self.verify_ssl         = verify_ssl
        self.policy_cache       = {}
        self._timeout           = 2.0
        self._logger            = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_RESTPolicyClient)
        self._logger.info("Initiating RESTPolicyClient towards Policy Management System ")
        self._connect()
        
    def _connect(self):
        try:
            tcp_conn            = aiohttp.TCPConnector(limit=self.tcp_conn_limit, loop=self._loop, verify_ssl=self.verify_ssl)
            self.client_session = aiohttp.ClientSession(connector=tcp_conn)
        except Exception as ex:
            self._logger.error("Failure initiating the rest policy client")
            self._logger.error(ex)

    def close(self):
        self.client_session.close()

    def cache_policy(self, key, policy):
        self.policy_cache[key] = policy

    @asyncio.coroutine
    def get(self, url, params=None, timeout=None):
        if timeout is None:
            timeout = self._timeout
        
        with aiohttp.Timeout(timeout):
            resp = None                                     # To handles issues related to connectivity with url
            try:
                resp = yield from self.client_session.get(url, params=params) 
                if resp.status == 200:
                    policy_response = yield from resp.text()
                    #print(policy_response)
                    return policy_response
                else:
                    return None
            
            except Exception as ex:
                # .close() on exception.
                if resp!=None:
                    resp.close()
                self._logger.error("Exception {} in getting REST response: ".format(ex))
            finally:
                if resp!=None:
                    yield from resp.release()               # .release() - returns connection into free connection pool.


    @asyncio.coroutine
    def delete(self, url, timeout=None):
        if timeout is None:
            timeout = self._timeout
            
        with aiohttp.Timeout(timeout):
            resp = yield from self.client_session.delete(url)
            try:
                return (yield from resp.text())
            except Exception as ex:
                resp.close()
                raise ex
            finally:
                yield from resp.release()


def main(policy_client):
    for i in range(0,1):
        #asyncio.ensure_future(policy_client.get('http://www.sarolahti.fi'))
        url = 'http://100.64.254.24/API/host_cetp_user?'
        params = {'lfqdn':"hosta1.cesa.lte.", 'direction': 'EGRESS'}
        asyncio.ensure_future(policy_client.get(url, params=params, timeout=2))
        #asyncio.ensure_future(policy_client.get('http://www.thomas-bayer.com/sqlrest/'))
        #yield from asyncio.sleep(1)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    tcp_conn_limit = 5
    verify_ssl=False
    policy_client = RESTPolicyClient(loop, tcp_conn_limit, verify_ssl=verify_ssl)
    
    try:
        main(policy_client)
        loop.run_forever()
    except KeyboardInterrupt:
        print('Keyboard Interrupt\n')
    finally:
        # Aiohttp resource cleanup
        loop.stop()
        policy_client.close()
        loop.close()
