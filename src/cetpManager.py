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
import cetpManager
import cetpTransaction

LOGLEVELCETP = logging.DEBUG


class CETPLocalTCPEndpoint(asyncio.Protocol):
    def __init__(self, loop, cetpstate_mgr= None, policy_mgr= None, dns_callback=None, cb_args=None, remote_cesid=None, dest_hostid=None):
        self.loop           = loop
        self.transport      = None
        self.cb_func        = dns_callback
        self.initial_args   = cb_args
        self.cetpstate_mgr  = cetpstate_mgr
        self.policy_mgr     = policy_mgr
        self.remote_cesid   = remote_cesid
        self.dest_hostid    = dest_hostid 
        
        self.dns_for_sstag = {}                 # {(SSTag, DSTag):__, } 
        self.process_first_dnsreq()

    def process_first_dnsreq(self):
        """ Needed to create first CETP packet based on DNS NAPTR response, on established TCP connection """
        self.initial_dnsQ = self.initial_args[0]

    def connection_made(self, transport):
        self.transport = transport
        self.sockname = transport.get_extra_info('sockname')
        self.peername = transport.get_extra_info('peername')
        print("Connection established from", self.sockname, " to ", self.peername)
        dnsmsg, addr = self.initial_args
        
        src_id  = "hosta1.demo.lte"             # Policy associated to Host-ip... Host-ip is associated to host-id
        r_cesid = self.remote_cesid
        dst_id  = self.dest_hostid              # src_id, r_cesid, dst_id, Shall come from dnsReq, and dnsMsg
        
        oces_transaction = cetpTransaction.CETPStateful(dnsmsg=dnsmsg, local_addr=self.sockname, remote_addr=self.peername, cetpstate_mgr=self.cetpstate_mgr, policy_mgr=self.policy_mgr, src_id=src_id, r_cesid=r_cesid, dst_id=dst_id)
        cetp_packet = oces_transaction.start_transaction()
        sstag, dstag = oces_transaction.sstag, oces_transaction.dstag
        self.dns_for_sstag[(sstag,0)] = self.initial_args
        self.transport.write(cetp_packet.encode())
        
        
    def data_received(self, data):
        """ Uses inbound CETP's (SST & DST) in connectionTable for Existing/Ongoing CETP resolutions """
        inbound_cetp = data.decode()                        # Assuming that other hand replays the message
        cetp_packet = json.loads(inbound_cetp)
        #print('Data received: {!r}'.format(inbound_cetp))
        sstag, dstag = cetp_packet["SST"], cetp_packet["DST"]
        sstag = int(sstag)
        
        if self.cetpstate_mgr.has((dstag, 0)):                                      # i_dstag = o_sstag
            print("The CETP packet belongs to an ongoing CETP transaction")
            cetp_transaction = self.cetpstate_mgr.get((dstag, 0))
            cetp_resp = cetp_transaction.continue_establishing(cetp_packet)
            
            if cetp_resp==True:                             # The resolution succeeds, run the following code as callback
                cb_args = self.dns_for_sstag[(dstag, 0)]
                dnsQ, addr = cb_args
                self.cb_func(dnsQ, addr, success=cetp_resp)
            elif cetp_resp==False:
                #print("CETP resolution failed callback")
                cb_args = self.dns_for_sstag[(dstag, 0)]
                dnsQ, addr = cb_args
                self.cb_func(dnsQ, addr, success=cetp_resp)
                return False
            elif cetp_resp==None:
                print("Malformed packet.. Ignore and silently drop")
                return False
            else:
                print("Return the generated packet")
                self.transport.write(cetp_resp.encode())

        elif self.cetpstate_mgr.has((sstag, dstag)):
            print("The packet belongs to an established CETP Transaction")
            cetp_transaction = self.cetpstate_mgr.get((sstag, dstag))
            cetp_transaction.post_establishment(cetp_packet)
        else:
            print("Silently drop the packet")
            
        
    def process_message(self, r_cesid="", src_hostid="", dst_hostid="", cb_args=None):
        """ Triggers CETPStateful Resolution for resolved NAPTR responses """
        src_id  = "hosta1.demo.lte"             # Policy associated to Host-ip... Host-ip is associated to host-id
        r_cesid = r_cesid
        dst_id  = dst_hostid                    # src_id, r_cesid, dst_id, Shall come from dnsReq, and dnsMsg
        dnsquery = cb_args[0]
        
        oces_transaction = cetpTransaction.CETPStateful(dnsmsg=dnsquery, local_addr=self.sockname, remote_addr=self.peername, cetpstate_mgr=self.cetpstate_mgr, policy_mgr=self.policy_mgr, src_id=src_id, r_cesid=r_cesid, dst_id=dst_id)
        cetp_packet = oces_transaction.start_transaction()
        sstag, dstag = oces_transaction.sstag, oces_transaction.dstag
        self.dns_for_sstag[(sstag,0)] = cb_args
        self.transport.write(cetp_packet.encode())
        
    def connection_lost(self, exc):
        print('The server closed the connection')           # Remove it from the list of local_ep, when connection is closed.


class CETPServerTCP(asyncio.Protocol):
    #"""
    def __init__(self, policy_mgr=None, cetpstate_mgr=None):
        self.policy_mgr     = policy_mgr
        self.cetpstate_mgr  = cetpstate_mgr
    #"""
    
    def connection_made(self, transport):
        self.transport  = transport
        self.sockname   = self.transport.get_extra_info('sockname')
        self.peername   = self.transport.get_extra_info('peername')
        print('Connection from {}'.format(self.peername))

    def data_received(self, data):
        """CETPStateless module processes inbound CETP packets """
        inbound_cetp = data.decode()
        cetp_packet = json.loads(inbound_cetp)
        #print('Data received: {!r}'.format(cetp_packet))
        sstag, dstag = cetp_packet["SST"], cetp_packet["DST"]
        sstag = int(sstag)

        if self.cetpstate_mgr.has((sstag, dstag)):
            print("The packet belongs to an ongoing transaction")
            cetp_transaction = self.cetpstate_mgr.get((sstag, dstag))
            cetp_transaction.post_establishment()
        else:
            print("New iCES transaction")
            ices_transaction = cetpTransaction.CETPStateless(cetp_packet, local_addr=self.sockname, remote_addr=self.peername, policy_mgr= self.policy_mgr, cetpstate_mgr= self.cetpstate_mgr)
            cetp_packet = ices_transaction.start_transaction()
            if cetp_packet == None:
                return
        
        #print('Send: {!r}'.format(message))
        self.transport.write(cetp_packet.encode())


class CETPManager:
    """ Initiate/Register server endpoint(s), local client instance(s) """ 
    def __init__(self, host_policies, loop=None):
        #self.logger = logging.getLogger(LOGLEVELCETP)
        self._localEndpoints = {}                           # List of Local Endpoint instances
        self._serverEndpoints = {}
        self.cetp_state = cetpTransaction.CETPConnectionObject()
        self.policy_mgr = cetpTransaction.PolicyManager(policy_file= host_policies)
        self._loop = loop
        self._load_cetp_policies()
        #self._initialize()

    def _load_cetp_policies(self):
        pass
    
    def register_server_endpoint(self, server_ip, server_port, transport_proto, server_ep):
        """ Register the server_ep by thier transport protocol """
        if not transport_proto in self._serverEndpoints:
            self._serverEndpoints[transport_proto] = {}

        key = self.extract_key(ep_ip=server_ip, ep_port=server_port, ep_transport = transport_proto)
        self._serverEndpoints[transport_proto][key] = server_ep


    def create_server_endpoint(self, server_ip, server_port, transport_proto):
        try:
            coro = self._loop.create_server(lambda: CETPServerTCP(policy_mgr=self.policy_mgr, cetpstate_mgr=self.cetp_state), host=server_ip, port=server_port)     # init() parameters can cause issue to new servers??
            #coro = self._loop.create_server(CETPServerTCP, host=server_ip, port=server_port)     # init() parameters can cause issue to new servers??
            srv = self._loop.create_task(coro)
            self.register_server_endpoint(server_ip, server_port, transport_proto, srv)                             # I store the server-task, not the object?
            print('CETP Server is listening on {%s:%d}' % (server_ip, server_port))
        except Exception as ex:
            print("Failed to create CETP server on (%s:%d)" %(server_ip, server_port))
            print(ex)
            
    def get_server_endpoints(self):
        """ Provide list of all local client endpoints """
        end_points = []
        for key, trans in self._serverEndpoints.items():
            for trans, ep in self._serverEndpoints[trans].items():
                endpoints.append(ep)
        return end_points

    def extract_key(self, ep_ip=None, ep_port=None, ep_transport = None):
        return ep_ip

    def create_local_endpoint(self, remote_cesid=None, remote_ip=None, remote_port=None, remote_transport=None, dest_hostid=None, cb_func= None, cb_args=None):
        "Make protocol factory and use it"
        message = 'Ideally this message will be forwarded by start_transaction() of CETP module'
        #r_ep_info = (remote_cesid, remote_ip, remote_port, transport_proto)
        try:
            print("Creating new CETP LocalEndpoint towards '%s'" %(remote_cesid))
            local_ep = CETPLocalTCPEndpoint(self._loop, cetpstate_mgr=self.cetp_state, policy_mgr=self.policy_mgr, dns_callback=cb_func, cb_args=cb_args, remote_cesid=remote_cesid, dest_hostid=dest_hostid)
            coro = self._loop.create_connection(lambda: local_ep, remote_ip, remote_port, local_addr = ('127.0.0.1', random.randint(50000, 54000)))
            client_task = self._loop.create_task(coro)
            self.register_local_endpoint(remote_cesid, remote_ip, remote_port, remote_transport, local_ep)          # I store the client-task, not the object
            print("CETP LocalEndpoint towards '%s' created" %remote_cesid)
            return local_ep
        except:
            client_task.exception()
            print("Failed to create protocol factory for %s at (%s, %d)" %(remote_cesid, remote_ip, remote_port))

    def register_local_endpoint(self, remote_cesid, remote_ip, remote_port, transport_proto, local_ep):
        key = self.extract_key(ep_ip=remote_ip, ep_port=remote_port, ep_transport = transport_proto)
        self._localEndpoints[key] = local_ep
        print(self._localEndpoints)

    def has_local_endpoint(self, remote_cesid=None, remote_ip=None, remote_port=None, remote_transport=None):
        """remote_ep_info must be a tuple of (remote_cesid, remote_ip, remote_port, transport_proto)"""
        key = self.extract_key(ep_ip=remote_ip, ep_port=remote_port, ep_transport=remote_transport)
        return key in self._localEndpoints

    def get_local_endpoint(self, remote_cesid=None, remote_ip=None, remote_port=None, remote_transport=None):
        """remote_ep_info must be a tuple of (remote_cesid, remote_ip, remote_port, transport_proto)"""
        key = self.extract_key(ep_ip=remote_ip, ep_port=remote_port, ep_transport=remote_transport)
        if self.has_local_endpoint(remote_cesid=remote_cesid, remote_ip=remote_ip, remote_port=remote_port, remote_transport=remote_transport):
            return self._localEndpoints[key]
        return None

    def get_local_endpoints(self):
        """ Provide list of all local client endpoints """
        end_points = []
        for key, ep in self._localEndpoints.items():
            endpoints.append(ep)
        return end_points
