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
import CETPC2C
import CETPH2H
import cetpOperations
import copy
import H2HTransaction

LOGLEVELCETP                        = logging.DEBUG
LOGLEVEL_C2CConnectionTemplate      = logging.INFO

# Keys for indexing connections
KEY_MAP_LOCAL_FQDN          = 0     # Indexes host connections against FQDN of local host
KEY_MAP_REMOTE_FQDN         = 1     # Indexes host connections against FQDN of remote host in another CES node

KEY_MAP_LOCAL_HOST          = 2     # Indexes host connections against local host's IP
KEY_MAP_CETP_PRIVATE_NW     = 3     # Indexes host connections against (lip, lpip) pair
KEY_MAP_REMOTE_CESID        = 4     # Indexes host connections against remote CESID 

KEY_MAP_CES_FQDN            = 5     # Indexes host connection against pair of FQDN (of local and remote host) across two CES nodes
KEY_MAP_LOCAL_FQDNs         = 6     # Indexes host connection against pair of FQDN (of local and remote host) in same CES node
KEY_MAP_CES_TO_CES          = 7     # Indexes host connection against an (SST, DST) pair
KEY_MAP_RCESID_C2C          = 8     # Indexes C2C connection against a remote CESID

    
def is_IPv4(ip4_addr):
    try:
        socket.inet_pton(socket.AF_INET, ip4_addr)
        return True
    except socket.error:
        return False

def is_IPv6(ip6_addr):
    try:
        socket.inet_pton(socket.AF_INET6, ip6_addr)
        return True
    except socket.error:
        return False


class ConnectionTable:
    def __init__(self):
        """       
        ConnectionTable to stores all the connections created in CES. 
        """
        self.connection_list = []
        self.connection_dict = {}
        self._logger = logging.getLogger("Connection Table")
        self._logger.setLevel(logging.INFO)
        
    def add(self, connection):
        """
        Add a connection to the ConnectionTable.
        @param connection: The connection object.
        """
        self.connection_list.append(connection)
        for keytype, key in connection.lookupkeys():
            if keytype not in self.connection_dict:
                self.connection_dict[keytype] = {}
            
            if keytype in [KEY_MAP_LOCAL_HOST, KEY_MAP_LOCAL_FQDN, KEY_MAP_REMOTE_FQDN, KEY_MAP_REMOTE_CESID]:
                if key in self.connection_dict[keytype]:
                    conn_lst = self.connection_dict[keytype][key]
                    conn_lst.append(connection)
                else:
                    self.connection_dict[keytype][key] = [connection]
            else:
                self.connection_dict[keytype][key] = connection
            
        self._logger.debug("New connection: %s" % (connection))
        #print("ConnTable: ", self.connection_dict)


    def delete(self, connection):
        """
        Remove a connection from the ConnectionTable.
        @param connection: The connection object.
        """
        self._logger.debug("Delete connection: %s" % (connection))
        if connection in self.connection_list:
            self.connection_list.remove(connection)
        
        #print("Dict: ", self.connection_dict, "\n\n")
        for keytype, key in connection.lookupkeys():
            if keytype in [KEY_MAP_LOCAL_HOST, KEY_MAP_LOCAL_FQDN, KEY_MAP_REMOTE_FQDN, KEY_MAP_REMOTE_CESID]:
                if key in self.connection_dict[keytype]:
                    conn_lst = self.connection_dict[keytype][key]
                    conn_lst.remove(connection)
                    if len(conn_lst)==0:
                        del self.connection_dict[keytype][key]
                        #print("self.connection_dict[keytype]={}, keytype={}, key={}: ".format(self.connection_dict[keytype], keytype, key))
            else:
                del self.connection_dict[keytype][key]
        
        connection.delete()
        #print(self.connection_dict)


    def has(self, keytype, key):
        """
        Check if there is a connection with the given key and keytype.
        @param keytype: The type of the connection.
        @param key: The values of the connection.
        """
        try:
            connection = self.connection_dict[keytype][key]
            return True
        except KeyError:
            return False

    def get(self, keytype, key):
        """
        Check if there is a connection with the given key and keytype.
        @param keytype: The type of the connection.
        @param key: The values of the connection.
        """
        try:
            return self.connection_dict[keytype][key]
        except KeyError:
            return None



LOGLEVEL_H2HConnection   = logging.INFO
LOGLEVEL_LocalConnection = logging.INFO


class C2CConnectionTemplate:
    def __init__(self, l_cesid, r_cesid, lrlocs, rrlocs, lpayloads, rpayloads, name="C2CConnectionTemplate"):
        """
        Initialize a C2CConnectionTemplate object.
        
        @param l_cesid:     Local CES-ID
        @param r_cesid:     Remote CES-ID
        @param lrlocs:      List of dataplane connection RLOCs of local CES   --  Each RLOC represented as  [(int:order, int:preference, int:addrtype, str:addrvalue)]
        @param rrlocs:      List of dataplane connection RLOCs of remote CES  --  Each RLOC represented as  [(int:order, int:preference, int:addrtype, str:addrvalue)]
        @param lpayloads:   List of negotiated dataplane payloads of local CES -- Each payload represented as [(str:type, int:preference, int:tunnel_id_out)]
        @param rpayloads:   List of negotiated dataplane payloads of remote CES-- Each payload represented as [(str:type, int:preference, int:tunnel_id_in)]
        """
        self.l_cesid, self.r_cesid      = l_cesid, r_cesid
        self.lrlocs, self.rrlocs        = lrlocs, rrlocs
        self.lpayloads, self.rpayloads  = lpayloads, rpayloads
        self._select_conn_params()
        self.connectiontype = "CONNECTION_C2C"
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_C2CConnectionTemplate)

    def _select_conn_params(self):
        # Picking the most preferred entry out of a list of negotiated RLOC and payloads
        lrloc      = self.lrlocs[0]
        rrloc      = self.rrlocs[0]
        lpayload   = self.lpayloads[0]
        rpayload   = self.rpayloads[0]
        
        # Extracts the RLOC and payload values
        self.lrloc      = lrloc[3]
        self.rrloc      = rrloc[3]
        self.lpayload   = (lpayload[0], rpayload[2])
        self.rpayload   = (rpayload[0], rpayload[2])

    def get_rlocs(self):
        return (self.lrloc, self.rrloc)

    def get_payloads(self):
        return (self.lpayload, self.rpayload)
    
    def lookupkeys(self):
        keys = []
        keys +=[(KEY_MAP_RCESID_C2C, self.r_cesid)]
        return keys

    def delete(self):
        self._logger.debug("Deleting a '{}' connection!".format(self.connectiontype))
        # Release the cached DNS responses, allocated proxy addresses and whatnot.
        """
        if self.local_af == AF_INET:
            CES_CONF.address_pool.get(AP_PROXY4_HOST_ALLOCATION).release(self.lip, self.lpip)
        elif self.local_af == AF_INET6:
            CES_CONF.address_pool.get(AP_PROXY6_HOST_ALLOCATION).release(self.lip, self.lpip)
        #Delete the DNS cached information
        if CES_CONF.cache_table.has(KEY_CACHEDNS_HOST_LPIP, (self.lip, self.lpip)):
            cached_entry = CES_CONF.cache_table.get(KEY_CACHEDNS_HOST_LPIP, (self.lip, self.lpip))
            CES_CONF.cache_table.delete(cached_entry)
        """



class H2HConnection:
    def __init__(self, cetpstate_mgr, timeout, lid, lip, lpip, rid, lfqdn, rfqdn, sstag, dstag, r_cesid, conn_table, name="H2HConnection"):
        """
        Initialize a H2HConnection object.
        
        @param timeout: The expiration time of the connection
        @param direction: The direction of the connection  -> 'E'stablished / 'I'ncoming / 'O'utgoing  
        @param lid: The ID of the local host -> (int:idtype, str:value)
        @param lip: The IP address of the local host
        @param lpip: The IP proxy address of the local host
        @param rid: The ID of the remote host -> (int:idtype, str:value)
        @param lrloc: The local RLOC of the connection -> [(int:order, int:preference, int:addrtype, str:addrvalue)]
        @param rrloc: The remote RLOC of the connection -> [(int:order, int:preference, int:addrtype, str:addrvalue)]
        """
        self.localFQDN           = lfqdn
        self.remoteFQDN          = rfqdn
        self.lid, self.rid       = lid, rid
        self.lip, self.lpip      = lip, lpip
        self.sstag, self.dstag   = sstag, dstag
        self.r_cesid             = r_cesid
        self.conn_table          = conn_table        
        self.cetpstate_mgr       = cetpstate_mgr
        self.timeout             = timeout
        self.connectiontype      = "CONNECTION_H2H"
        self._logger             = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_H2HConnection)
        self._logger.debug("Connection tags: {} -> {}".format(sstag, dstag))


    def _get_c2c_connection_params(self):
        keytype     = KEY_MAP_RCESID_C2C
        key         = self.r_cesid
        c2c_conn    = self.conn_table.get(keytype, key)
        self.lrloc, self.rrloc          = c2c_conn.get_rlocs()
        self.lpayload, self.rpayload    = c2c_conn.get_payloads()
        self.tunnel_type                = self.lpayload[0]
        self.tunnel_id_in               = self.lpayload[2]
        self.tunnel_id_out              = self.rpayload[2]
    
    def add(self):
        pass
        #add_tunnel_connection(src, psrc, tun_src, tun_dst, tun_id_in, tun_id_out, tun_type, diffserv=False)
        #add_tunnel_connection(self.lip, self.lpip, self.lrloc, self.rrloc, self.tunnel_id_in, self.tunnel_id_out, self.tunnel_type)
        
    def lookupkeys(self):
        keys = []
        keys +=[(KEY_MAP_LOCAL_HOST, self.lip),         (KEY_MAP_CETP_PRIVATE_NW, (self.lip, self.lpip)),     (KEY_MAP_LOCAL_FQDN, self.localFQDN),
                (KEY_MAP_REMOTE_FQDN, self.remoteFQDN), (KEY_MAP_REMOTE_CESID, self.r_cesid)
                ]
        
        if (self.localFQDN is not None) and (self.remoteFQDN is not None):
            keys.append((KEY_MAP_CES_FQDN, (self.localFQDN, self.remoteFQDN)))
        if (self.sstag is not None) and (self.dstag is not None):
            keys.append((KEY_MAP_CES_TO_CES, (self.sstag, self.dstag)))
        return keys
        

    def delete(self):
        self._logger.debug("Deleting a {} connection!".format(self.connectiontype))
        # Release the cached DNS responses, allocated proxy addresses and whatnot.

        #delete_tunnel_connection(self.lip, self.lpip, self.lrloc, self.rrloc, self.tunnel_id_in, self.tunnel_id_out, self.tunnel_type)

        keytype = H2HTransaction.KEY_ESTABLISHED_TAGS
        key     = (self.sstag, self.dstag)
        
        if self.cetpstate_mgr.has(keytype, key):
            cetp_transaction = self.cetpstate_mgr.get(keytype, key)
            cetp_transaction.terminate()


        """
        if self.local_af == AF_INET:
            CES_CONF.address_pool.get(AP_PROXY4_HOST_ALLOCATION).release(self.lip, self.lpip)
        elif self.local_af == AF_INET6:
            CES_CONF.address_pool.get(AP_PROXY6_HOST_ALLOCATION).release(self.lip, self.lpip)
        """


class LocalConnection:
    def __init__(self, timeout, lid=None, lip=None, lpip=None, rid=None, rip=None, rpip=None, lfqdn=None, rfqdn=None, name="LocalConnection"):
        """
        Initialize a LocalConnection object.
        
        @param timeout: The expiration time of the connection
        @param lid: The ID of the local host -> (int:idtype, str:value)
        @param lip: The IP address of the local host
        @param lpip: The IP proxy address of the local host
        @param rid: The ID of the remote host -> (int:idtype, str:value)
        @param rip: The IP address of the remote host
        @param rpip: The IP proxy address of the remote host
        """
        self.timeout          = timeout
        self.lip, self.lpip   = lip, lpip
        self.rip, self.rpip   = rip, rpip
        self.localFQDN        = lfqdn
        self.remoteFQDN       = rfqdn
        self.connectiontype   = "CONNECTION_LOCAL"
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_LocalConnection)

    def lookupkeys(self):
        keys = []
        keys += [(KEY_MAP_LOCAL_HOST, self.lip),     (KEY_MAP_CETP_PRIVATE_NW, (self.lip, self.lpip)),          (KEY_MAP_LOCAL_FQDN, self.localFQDN),
                 (KEY_MAP_LOCAL_FQDNs, (self.localFQDN, self.remoteFQDN))
                 ]
        
        keys += [(KEY_MAP_LOCAL_HOST, self.rip),     (KEY_MAP_CETP_PRIVATE_NW, (self.rip, self.rpip)),          (KEY_MAP_LOCAL_FQDN, self.remoteFQDN),
                 ]
        
        return keys

    def add(self):
        pass
        #add_local_connection(self.lip, self.lpip, self.rip, self.rpip)

    def delete(self):
        self._logger.debug("Deleting a {} connection!".format(self.connectiontype))
        # Release the cached DNS responses, allocated proxy addresses and whatnot.
        #delete_local_connection(self.lip, self.lpip, self.rip, self.rpip)

        """
        if self.local_af == AF_INET:
            CES_CONF.address_pool.get(AP_PROXY4_HOST_ALLOCATION).release(self.lip, self.lpip)
        elif self.local_af == AF_INET6:
            CES_CONF.address_pool.get(AP_PROXY6_HOST_ALLOCATION).release(self.lip, self.lpip)
        #Delete the DNS cached information
        if CES_CONF.cache_table.has(KEY_CACHEDNS_HOST_LPIP, (self.lip, self.lpip)):
            cached_entry = CES_CONF.cache_table.get(KEY_CACHEDNS_HOST_LPIP, (self.lip, self.lpip))
            CES_CONF.cache_table.delete(cached_entry)
        """

