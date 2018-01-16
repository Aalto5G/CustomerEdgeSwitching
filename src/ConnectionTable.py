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

KEY_INITIATED_CETP                  = 0
KEY_ESTABLISHED_CETP                = 1
LOGLEVELCETP                        = logging.DEBUG
LOGLEVEL_C2CConnection              = logging.INFO

# Keys for indexing connections
KEY_MAP_LOCAL_FQDN          = 0     # Indexes host connections against FQDN of local host
KEY_MAP_REMOTE_FQDN         = 1     # Indexes host connections against FQDN of remote host

KEY_MAP_LOCAL_HOST          = 2     # Indexes host connections against local host's IP
KEY_MAP_CETP_PRIVATE_NW     = 3     # Indexes host connections against (lip, lpip) pair
KEY_MAP_REMOTE_CESID        = 4     # Indexes host connections against remote CESID 

KEY_MAP_CES_FQDN            = 5     # Indexes host connection against pair of FQDN (of local and remote host)
KEY_MAP_CES_TO_CES          = 6     # Indexes host connection against an (SST, DST) pair

KEY_MAP_RCESID_C2C          = 7     # Indexes C2C connection against a remote CESID

    
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


class C2CConnection:
    def __init__(self, l_cesid, r_cesid, lrloc, rrloc, lpayload, rpayload):
        """
        Initialize a C2CConnection object.
        
        @param timeout: The expiration time of the connection
        @param direction: The direction of the connection  -> 'E'stablished / 'I'ncoming / 'O'utgoing  
        @param lid: The ID of the local host -> (int:idtype, str:value)
        @param lip: The IP address of the local host
        @param lpip: The IP proxy address of the local host
        @param rid: The ID of the remote host -> (int:idtype, str:value)
        @param lrloc: The local RLOC of the connection -> [(int:order, int:preference, int:addrtype, str:addrvalue)]
        @param rrloc: The remote RLOC of the connection -> [(int:order, int:preference, int:addrtype, str:addrvalue)]
        """
        self.l_cesid, self.r_cesid      = l_cesid, r_cesid
        self.lrloc, self.rrloc          = lrloc, rrloc
        self.lpayload, self.rpayload    = lpayload, rpayload
        self.connectiontype = "CONNECTION_C2C"
        #self._set_address_family(lip=lip)
        #self.remote_af = AF_INET
        #self._set_encapsulation()
        self.active_af = 0
        #Set b port based on local rloc
        self._logger = logging.getLogger("C2CConnection")
        self._logger.setLevel(LOGLEVEL_C2CConnection)

    def get_rlocs(self):
        return (self.lrloc, self.rrloc)

    def get_payloads(self):
        return (self.lpayload, self.rpayload)
    
    def lookupkeys(self):
        keys = []
        keys +=[(KEY_MAP_RCESID_C2C, self.r_cesid)]
        return keys
        

    def delete(self):
        self._logger.debug("Deleting a {} connection!".format(self.connectiontype))
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
    def __init__(self, timeout, lid, lip, lpip, rid, lfqdn, rfqdn, sstag, dstag, r_cesid, conn_table):
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
        self.timeout             = timeout
        self.lid, self.lip, self.lpip, self.rid  = lid, lip, lpip, rid
        self.localFQDN, self.remoteFQDN = lfqdn, rfqdn
        self.sstag, self.dstag = sstag, dstag
        self.r_cesid=r_cesid
        self.conn_table = conn_table        
        self.connectiontype = "CONNECTION_H2H"
        
        #self._set_address_family(lip=lip)
        #self.remote_af = AF_INET
        #self._set_encapsulation()
        self.active_af = 0
        #Set b port based on local rloc
        self._logger = logging.getLogger("H2HConnection")
        self._logger.setLevel(LOGLEVEL_H2HConnection)
        self._logger.debug("Connection tags: {} -> {}".format(sstag, dstag))

    def _get_connection_params(self):
        keytype     = KEY_MAP_RCESID_C2C
        key         = self.r_cesid
        c2c_conn    = self.conn_table.get(keytype, key)
        
        self.lrloc, self.rrloc          = c2c_conn.get_rlocs()
        self.lpayload, self.rpayload    = c2c_conn.get_payloads()


    
    def lookupkeys(self):
        keys = []
        keys +=[(KEY_MAP_LOCAL_HOST, self.lip), (KEY_MAP_CETP_PRIVATE_NW, (self.lip, self.lpip)),
                (KEY_MAP_LOCAL_FQDN, self.localFQDN), (KEY_MAP_REMOTE_FQDN, self.remoteFQDN), (KEY_MAP_REMOTE_CESID, self.r_cesid)]
        
        if (self.localFQDN is not None) and (self.remoteFQDN is not None):
            keys.append((KEY_MAP_CES_FQDN, (self.localFQDN, self.remoteFQDN)))
        if (self.sstag is not None) and (self.dstag is not None):
            keys.append((KEY_MAP_CES_TO_CES, (self.sstag, self.dstag)))
        return keys
        

    def delete(self):
        self._logger.debug("Deleting a {} connection!".format(self.connectiontype))
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


class LocalConnection:
    def __init__(self, timeout, direction, lid=None, lip=None, lpip=None, rid=None, rip=None, rpip=None,lfqdn=None, rfqdn=None):
        """
        Initialize a LocalConnection object.
        
        @param timeout: The expiration time of the connection
        @param direction: The direction of the connection -> 'E'stablished / 'I'ncoming / 'O'utgoing  
        @param lid: The ID of the local host -> (int:idtype, str:value)
        @param lip: The IP address of the local host
        @param lpip: The IP proxy address of the local host
        @param rid: The ID of the remote host -> (int:idtype, str:value)
        @param rip: The IP address of the remote host
        @param rpip: The IP proxy address of the remote host
        """
        self.timeout, self.direction    = timeout, direction
        self.lid, self.lip, self.lpip   = lid, lip, lpip
        self.rid, self.rip, self.rpip   = rid, rip, rpip
        self.localFQDN, self.remoteFQDN = lfqdn, rfqdn
        self.connectiontype = "CONNECTION_LOCAL"
        #self._set_address_family(lip=lip, rip=rip)
        self._logger = logging.getLogger("LocalConnection")
        self._logger.setLevel(LOGLEVEL_LocalConnection)

    def lookupkeys(self):
        keys = []
        keys += [(KEY_MAP_CETP_PRIVATE_NW, (self.lip, self.lpip)), (KEY_MAP_CES_FQDN, (self.localFQDN, self.remoteFQDN)),
                 (KEY_MAP_LOCAL_HOST, self.lip), (KEY_MAP_LOCAL_FQDN, self.localFQDN), (KEY_MAP_REMOTE_FQDN, self.remoteFQDN)]
        return keys

    def delete(self):
        self._logger.debug("Deleting a {} connection!".format(self.connectiontype))
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



class CETPStateTable(object):
    def __init__(self):
        self.cetp_transactions                          = {}                     #{(SST,0): A, (SST,DST): B}            #{KEY_ONgoing: [(SST,0): A, (SST,0): B], KEY_Established: [(SST,DST): C, (SST,DST): D]}
        self.cetp_transactions[KEY_INITIATED_CETP]      = {}
        self.cetp_transactions[KEY_ESTABLISHED_CETP]    = {}
    
    def has_initiated_transaction(self, session_tag):
        keytype = KEY_INITIATED_CETP
        return self._has(keytype, session_tag)
        
    def has_established_transaction(self, session_tag):
        keytype = KEY_ESTABLISHED_CETP
        return self._has(keytype, session_tag)
    
    def add_initiated_transaction(self, session_tag, transaction):
        keytype = KEY_INITIATED_CETP
        self._add(keytype, session_tag, transaction)
        
    def add_established_transaction(self, session_tag, transaction):
        keytype = KEY_ESTABLISHED_CETP
        self._add(keytype, session_tag, transaction)
        #print("Upon adding an established transaction", self.cetp_transactions[KEY_ESTABLISHED_CETP])
        
    def remove_initiated_transaction(self, session_tag):
        keytype = KEY_INITIATED_CETP
        if self._has(keytype, session_tag):
            self._remove(keytype, session_tag)

    def remove_established_transaction(self, session_tag):
        keytype = KEY_ESTABLISHED_CETP
        if self._has(keytype, session_tag):
            self._remove(keytype, session_tag)
        #print("\n After removal", self.cetp_transactions[KEY_ESTABLISHED_CETP])
            
    def get_initiated_transaction(self, session_tag):
        keytype = KEY_INITIATED_CETP
        if self.has_initiated_transaction(session_tag):
            return self._get(keytype, session_tag)

    def get_established_transaction(self, session_tag):
        keytype = KEY_ESTABLISHED_CETP
        if self.has_established_transaction(session_tag):
            return self._get(keytype, session_tag)

    def _has(self, keytype, session_tag):
        if keytype in self.cetp_transactions:
            return session_tag in self.cetp_transactions[keytype]
        return False

    def _add(self, keytype, session_tag, transaction):
        self.cetp_transactions[keytype][session_tag] = transaction
        
    def _get(self, keytype, session_tag):
        return self.cetp_transactions[keytype][session_tag]
    
    def _remove(self, keytype, session_tag):
        del self.cetp_transactions[keytype][session_tag]

    def allocate_proxy_address(self, lip):
        """ Emulates proxy-IP assigning function """
        ms_ip = "10.0.3."
        ls_ip_num = random.randint(0, 255)
        ls_ip = str(ls_ip_num)
        proxy_ip = ms_ip + ls_ip        
        return proxy_ip
    
