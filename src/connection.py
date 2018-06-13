import logging
import time
import pprint

import H2HTransaction
import host

from helpers_n_wrappers import container3
from helpers_n_wrappers import utils3
import asyncio

KEY_RGW = 0
DP_CONN_cookie = 0

class ConnectionTable(container3.Container):
    def __init__(self, name='ConnectionTable'):
        """ Initialize as a Container """
        super().__init__(name)

    def _update_set(self, s):
        myset = set(s)
        for node in myset:
            if node.hasexpired():
                self.remove(node)

    def update_all_rgw(self):
        conn_set = self.lookup(KEY_RGW, update=False, check_expire=False)
        if conn_set is None:
            return
        self._update_set(conn_set)

    def get_all_rgw(self, update=True):
        conn_set = self.lookup(KEY_RGW, update=False, check_expire=False)
        if conn_set is None:
            return []
        if update:
            self._update_set(conn_set)
        return conn_set

    def stats(self, key):
        data = self.lookup(key, update=False, check_expire=False)
        if data is None:
            return 0
        return len(data)



class ConnectionLegacy(container3.ContainerNode):
    TIMEOUT = 2.0
    def __init__(self, name='ConnectionLegacy', **kwargs):
        """ Initialize as a ContainerNode.

        @param name: A description of the object.
        @type name: String
        @param private_ip: Private IPv4 address.
        @type private_ip: String
        @param private_port: Private port number.
        @type private_port: Integer
        @param outbound_ip: Outbound IPv4 address.
        @type outbound_ip: String
        @param outbound_port: Outbound port number.
        @type outbound_port: Integer
        @param remote_ip: Remote IPv4 address.
        @type remote_ip: String
        @param remote_port: Remote port number.
        @type remote_port: Integer
        @param protocol: Protocol number.
        @type protocol: Integer
        @param fqdn: Allocating FQDN.
        @type fqdn: String
        @param dns_resolver: IPv4 address of the DNS server.
        @type dns_resolver: String
        @param dns_host: IPv4 address of the DNS client.
        @type dns_host: String
        @param timeout: Time to live (sec).
        @type timeout: Integer or float
        """
        super().__init__(name)
        # Set default values
        self.autobind = True
        self._autobind_flag = False
        self.dns_bind = False
        # Set attributes
        utils3.set_attributes(self, override=True, **kwargs)
        # Set default values of unset attributes
        attrlist_zero = ['private_ip', 'private_port', 'outbound_ip', 'outbound_port',
                         'remote_ip', 'remote_port', 'protocol', 'loose_packet']
        attrlist_none = ['fqdn', 'dns_resolver', 'dns_host', 'host_fqdn', 'timeout']
        utils3.set_default_attributes(self, attrlist_zero, 0)
        utils3.set_default_attributes(self, attrlist_none, None)
        # Set default timeout if not overriden
        if not self.timeout:
            self.timeout = ConnectionLegacy.TIMEOUT
        # Take creation timestamp
        self.timestamp_zero = time.time()
        ## Override timeout ##
        #self.timeout = 600.0
        ######################
        self.timestamp_eol = self.timestamp_zero + self.timeout
        self._build_lookupkeys()

    def _build_lookupkeys(self):
        # Build set of lookupkeys
        self._built_lookupkeys = []
        # Basic indexing
        self._built_lookupkeys.append((KEY_RGW, False))
        # Host FQDN based indexing
        self._built_lookupkeys.append(((KEY_RGW, self.host_fqdn), False))
        # Private IP-based indexing
        #self._built_lookupkeys.append(((KEY_RGW, self.private_ip), False))
        # Outbound IP-based indexing
        self._built_lookupkeys.append(((KEY_RGW, self.outbound_ip), False))
        ## The type of unique key come determined by the parameters available
        if not self.remote_ip and not self.remote_port:
            # 3-tuple semi-fledged based indexing
            self._built_lookupkeys.append(((KEY_RGW, self.outbound_ip, self.outbound_port, self.protocol), True))
        else:
            # 5-tuple full-fledged based indexing
            self._built_lookupkeys.append(((KEY_RGW, self.outbound_ip, self.outbound_port, self.remote_ip, self.remote_port, self.protocol), True))


    def lookupkeys(self):
        """ Return the lookup keys """
        # Return an iterable (key, isunique)
        return self._built_lookupkeys

    def hasexpired(self):
        """ Return True if the timeout has expired """
        return time.time() > self.timestamp_eol

    def post_processing(self, connection_table, remote_ip, remote_port):
        """ Return True if no further actions are required """
        # TODO: I think the case of loose_packet < 0 does not work as standard DNAT (permanent hole) because of the autobind flag?

        # This is the normal case for incoming connections via RealmGateway
        if self.loose_packet == 0:
            return True

        # This is a special case for opening a hole in the NAT temporarily
        elif self.loose_packet > 0:
            # Consume loose packet token
            self.loose_packet -= 1

        # This is a special case for opening a hole in the NAT permanently
        elif self.loose_packet < 0:
            pass

        if self.autobind and not self._autobind_flag:
            self._logger.info('Binding connection / {}'.format(self))
            # Bind connection to 5-tuple match
            self.remote_ip, self.remote_port = remote_ip, remote_port
            self._built_lookupkeys = [(KEY_RGW, False),
                                      ((KEY_RGW, self.outbound_ip), False),
                                      ((KEY_RGW, self.outbound_ip, self.outbound_port, self.remote_ip, self.remote_port, self.protocol), True)]
            # Update keys in connection table
            connection_table.updatekeys(self)
            # Set autobind flag to True
            self._autobind_flag = True

        return False

    @property
    def age(self):
        return time.time() - self.timestamp_zero

    def __repr__(self):
        ret = ''
        ret += '({})'.format(self.host_fqdn)
        ret += ' [{}]'.format(self.protocol)

        if self.private_port:
            ret += ' {}:{} <- {}:{}'.format(self.private_ip, self.private_port, self.outbound_ip, self.outbound_port)
        else:
            ret += ' {} <- {}'.format(self.private_ip, self.outbound_ip)

        if self.remote_ip:
            ret += ' <=> {}:{}'.format(self.remote_ip, self.remote_port)

        ret += ' ({} sec)'.format(self.timeout)

        if self.fqdn:
            ret += ' | FQDN {}'.format(self.fqdn)

        if self.dns_resolver:
            ret += ' | DNS {} <- {}'.format(self.dns_resolver, self.dns_host)

        if self.loose_packet:
            ret += ' / bucket={}'.format(self.loose_packet)

        if not self.autobind:
            ret += ' / autobind={}'.format(self.autobind)

        return ret



LOGLEVEL_C2CConnectionTemplate  = logging.DEBUG
LOGLEVEL_H2HConnection          = logging.INFO
LOGLEVEL_LocalConnection        = logging.DEBUG

# Keys for indexing connections
KEY_MAP_CETP_CONN           = 1
KEY_MAP_LOCAL_FQDN          = 2     # Indexes host connections against FQDN of local host
KEY_MAP_REMOTE_FQDN         = 3     # Indexes host connections against FQDN of remote host in another CES node

KEY_MAP_LOCAL_HOST          = 4     # Indexes host connections against local host's IP
KEY_MAP_CETP_PRIVATE_NW     = 5     # Indexes host connections against (lip, lpip) pair
KEY_MAP_REMOTE_CESID        = 6     # Indexes host connections against remote CESID 

KEY_MAP_CES_FQDN            = 7     # Indexes all host connections across two CES nodes, as pair of the (local and remote host) FQDN 
KEY_MAP_LOCAL_FQDNs         = 8     # Indexes all host connections within same CES node, as pair of the (local and remote host) FQDN  
KEY_MAP_HOST_FQDNs          = 9     # Indexes all host connections using local and remote FQDNs
KEY_MAP_CES_TO_CES          = 10     # Indexes host connection against an (SST, DST) pair
KEY_MAP_RCESID_C2C          = 11    # Indexes C2C connection against a remote CESID



class C2CConnectionTemplate(container3.ContainerNode):
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
        super().__init__(name)
        self.l_cesid, self.r_cesid      = l_cesid, r_cesid
        self.lrlocs, self.rrlocs        = lrlocs, rrlocs
        self.lpayloads, self.rpayloads  = lpayloads, rpayloads
        self._select_conn_params()
        self.connectiontype = "CONNECTION_C2C"
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_C2CConnectionTemplate)
        self._build_lookupkeys()

    def _select_conn_params(self):
        # Picking the most preferred entry out of a list of negotiated RLOC and payloads
        lrloc      = self.lrlocs[0]
        rrloc      = self.rrlocs[0]
        lpayload   = self.lpayloads[0]
        rpayload   = self.rpayloads[0]
        
        # Extracts the RLOC and payload values
        self.lrloc      = lrloc[3]
        self.rrloc      = rrloc[3]
        self.lpayload   = (lpayload[0], lpayload[2])
        self.rpayload   = (rpayload[0], rpayload[2])

    def get_rlocs(self):
        return (self.lrloc, self.rrloc)

    def get_payloads(self):
        return (self.lpayload, self.rpayload)
    
    def _build_lookupkeys(self):
        self._built_lookupkeys = []
        self._built_lookupkeys +=[((KEY_MAP_RCESID_C2C, self.r_cesid), True)]
    
    def lookupkeys(self):
        return self._built_lookupkeys

    def delete(self):
        self._logger.debug("Deleting a '{}' connection!".format(self.connectiontype))
        # Release the cached DNS responses, allocated proxy addresses and whatnot.
        """
        if self.local_af == AF_INET:
            .address_pool.get(AP_PROXY4_HOST_ALLOCATION).release(self.lip, self.lpip)
        elif self.local_af == AF_INET6:
            .address_pool.get(AP_PROXY6_HOST_ALLOCATION).release(self.lip, self.lpip)
        #Delete the DNS cached information
        if .cache_table.has(KEY_CACHEDNS_HOST_LPIP, (self.lip, self.lpip)):
            cached_entry = .cache_table.get(KEY_CACHEDNS_HOST_LPIP, (self.lip, self.lpip))
            .cache_table.delete(cached_entry)
        """



class H2HConnection(container3.ContainerNode):
    def __init__(self, network, cetpstate_table, address_pool, host_table, conn_table, lid, lip, lpip, rid, lfqdn, rfqdn, sstag, dstag, r_cesid, hard_ttl=None, idle_ttl=None, name="H2HConnection"):
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
        super().__init__(name)
        self.localFQDN           = lfqdn
        self.remoteFQDN          = rfqdn
        self.lid, self.rid       = lid, rid
        self.lip, self.lpip      = lip, lpip
        self.sstag, self.dstag   = sstag, dstag
        self.r_cesid             = r_cesid
        self.conn_table          = conn_table
        self.host_table          = host_table
        self.cetpstate_table     = cetpstate_table
        self.address_pool        = address_pool
        self.network             = network 
        self.connectiontype      = "CONNECTION_H2H"
        self.hard_ttl            = hard_ttl
        self.idle_ttl            = idle_ttl
        self._logger             = logging.getLogger(name+str(lfqdn)+"->"+str(rfqdn))
        self._logger.setLevel(LOGLEVEL_H2HConnection)
        self._logger.debug("Connection tags: {} -> {}".format(sstag, dstag))
        self._build_lookupkeys()
        self._get_c2c_connection_params()
        self._set_cookie()

    def _get_c2c_connection_params(self):
        key         = (KEY_MAP_RCESID_C2C, self.r_cesid)
        c2c_conn    = self.conn_table.get(key)
        self.lrloc, self.rrloc          = c2c_conn.get_rlocs()
        self.lpayload, self.rpayload    = c2c_conn.get_payloads()
        self.tunnel_type                = self.lpayload[0]
        self.tunnel_id_in               = self.lpayload[1]
        self.tunnel_id_out              = self.rpayload[1]
        
    def _build_lookupkeys(self):
        self._built_lookupkeys = []
        self._built_lookupkeys +=[ (KEY_MAP_CETP_CONN, False)]
        self._built_lookupkeys +=[ ((KEY_MAP_LOCAL_HOST, self.lip), False),         ((KEY_MAP_CETP_PRIVATE_NW, self.lip, self.lpip), True) ]
        self._built_lookupkeys +=[ ((KEY_MAP_LOCAL_FQDN, self.localFQDN), False),   ((KEY_MAP_REMOTE_FQDN, self.remoteFQDN), False) ]
        self._built_lookupkeys +=[ ((KEY_MAP_REMOTE_CESID, self.r_cesid), False) ]
        
        if (self.localFQDN is not None) and (self.remoteFQDN is not None):
            self._built_lookupkeys += [ ((KEY_MAP_CES_FQDN, self.localFQDN, self.remoteFQDN), True) ]
            self._built_lookupkeys += [ ((KEY_MAP_HOST_FQDNs, self.localFQDN, self.remoteFQDN), True)]
            
        if (self.sstag is not None) and (self.dstag is not None):
            self._built_lookupkeys += [ ((KEY_MAP_CES_TO_CES, self.sstag, self.dstag), True) ]

        
    def _set_cookie(self):
        global DP_CONN_cookie
        DP_CONN_cookie += 1
        
        if DP_CONN_cookie == 0xFFFFFFFFFFFFFFF0:
            DP_CONN_cookie = 1
            
        self.conn_cookie = DP_CONN_cookie
    
    @asyncio.coroutine
    def insert_dataplane_connection(self):
        #self._logger.info("lrloc: {}, rrloc:{}, tunnel_id_in:{}, tunnel_id_out:{}, tunnel_type:{}".format(self.lrloc, self.rrloc, self.tunnel_id_in, self.tunnel_id_out, self.tunnel_type))
        yield from self.network.add_tunnel_connection(self.lip, self.lpip, self.lrloc, self.rrloc, self.tunnel_id_in, self.tunnel_id_out, self.tunnel_type, \
                                                      self.conn_cookie, self.sstag, self.dstag, hard_timeout=self.hard_ttl, idle_timeout=self.idle_ttl)
        
    def lookupkeys(self):
        return self._built_lookupkeys
        
    def delete(self):
        self._logger.debug("Deleting a {} connection!".format(self.connectiontype))
        asyncio.ensure_future( self.network.delete_tunnel_connection(self.lip, self.lpip, self.lrloc, self.rrloc, self.tunnel_id_in, self.tunnel_id_out, self.tunnel_type, self.sstag, self.dstag) )
        
        # Terminating the H2HTransaction
        key = (H2HTransaction.KEY_ESTABLISHED_TAGS, self.sstag, self.dstag)
        
        if self.cetpstate_table.has(key):
            cetp_transaction = self.cetpstate_table.get(key)
            cetp_transaction.terminate()
        
        # Releasing the CES proxy address
        key      = (host.KEY_HOST_SERVICE, self.localFQDN)
        host_obj = self.host_table.get(key)
        host_id  = host_obj.fqdn
        
        if self.address_pool.in_allocated(host_id, self.lpip):
            self.address_pool.release(host_id, self.lpip)

        # Add the logic for deleting the cached DNS response, if any.


class LocalConnection(container3.ContainerNode):
    def __init__(self, network, address_pool, host_table, lid=None, lip=None, lpip=None, rid=None, rip=None, rpip=None, lfqdn=None, rfqdn=None, hard_ttl=None, idle_ttl=None, name="LocalConnection"):
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
        super().__init__(name)
        self.network          = network
        self.address_pool     = address_pool
        self.host_table       = host_table
        self.lip, self.lpip   = lip, lpip
        self.rip, self.rpip   = rip, rpip
        self.localFQDN        = lfqdn
        self.remoteFQDN       = rfqdn
        self.hard_ttl         = hard_ttl
        self.idle_ttl         = idle_ttl
        self.connectiontype   = "CONNECTION_LOCAL"
        self._logger = logging.getLogger(name+str(lfqdn)+"->"+str(rfqdn))
        self._logger.setLevel(LOGLEVEL_LocalConnection)
        self._build_lookupkeys()
        self._set_cookie()

    def _build_lookupkeys(self):
        self._built_lookupkeys = []
        self._built_lookupkeys += [ (KEY_MAP_CETP_CONN, False) ]
        self._built_lookupkeys += [ ((KEY_MAP_LOCAL_HOST, self.lip), False),        ((KEY_MAP_CETP_PRIVATE_NW, self.lip, self.lpip), True) ]
        self._built_lookupkeys += [ ((KEY_MAP_LOCAL_FQDN, self.localFQDN), False),  ((KEY_MAP_LOCAL_FQDN, self.remoteFQDN), False) ]
        self._built_lookupkeys += [ ((KEY_MAP_LOCAL_FQDNs, self.localFQDN, self.remoteFQDN), True)]
        self._built_lookupkeys += [ ((KEY_MAP_HOST_FQDNs, self.localFQDN, self.remoteFQDN), True)]
        if self.lip != self.rip:
            self._built_lookupkeys += [ ((KEY_MAP_LOCAL_HOST, self.rip), False),    ((KEY_MAP_CETP_PRIVATE_NW, self.rip, self.rpip), True)]

        
    def lookupkeys(self):
        """ Keys for indexing Local Connection object """
        return self._built_lookupkeys    

    def _set_cookie(self):
        global DP_CONN_cookie
        DP_CONN_cookie += 1
        
        if DP_CONN_cookie == 0xFFFFFFFFFFFFFFF0:
            DP_CONN_cookie = 1
            
        self.conn_cookie = DP_CONN_cookie
    
    @asyncio.coroutine
    def insert_dataplane_connection(self):
        yield from self.network.add_local_connection(self.lip, self.lpip, self.rip, self.rpip, cookie = self.conn_cookie, \
                                                     hard_timeout=self.hard_ttl, idle_timeout=self.idle_ttl)

    def delete(self):
        self._logger.debug("Deleting a {} connection!".format(self.connectiontype))
        asyncio.ensure_future( self.network.delete_local_connection(self.lip, self.lpip, self.rip, self.rpip) )

        # Releasing the CES proxy address        
        key     = (host.KEY_HOST_SERVICE, self.localFQDN)
        host_obj = self.host_table.get(key)
        host_id  = host_obj.fqdn
        
        if self.address_pool.in_allocated(host_id, self.lpip):
            self.address_pool.release(host_id, self.lpip)

        key     = (host.KEY_HOST_SERVICE, self.remoteFQDN)
        host_obj = self.host_table.get(key)
        host_id  = host_obj.fqdn
        
        if self.address_pool.in_allocated(host_id, self.rpip):
            self.address_pool.release(host_id, self.rpip)

        # Release the cached DNS responses, if any.
        """
        if .cache_table.has(KEY_CACHEDNS_HOST_LPIP, (self.lip, self.lpip)):
            cached_entry = .cache_table.get(KEY_CACHEDNS_HOST_LPIP, (self.lip, self.lpip))
            .cache_table.delete(cached_entry)
        """



if __name__ == "__main__":
    table = ConnectionTable()
    d1 = {'outbound_ip':'1.2.3.4','dns_resolver':'8.8.8.8','private_ip':'192.168.0.100','fqdn':'host100.rgw','timeout':2.0}
    c1 = ConnectionLegacy(**d1)
    d2 = {'outbound_ip':'1.2.3.5','dns_resolver':'8.8.8.8','private_ip':'192.168.0.100','fqdn':'host100.rgw','timeout':2.0,
          'outbound_port':12345,'protocol':6}
    c2 = ConnectionLegacy(**d2)
    table.add(c1)
    table.add(c2)
    
    l1 = LocalConnection(12, lid="None", lip="None", lpip="None", rid="None", rip="None", rpip="None", lfqdn="None", rfqdn="None")
    table.add(l1)
    
    print('Connection c1 has expired?')
    print(c1.hasexpired())
    print(table)
    print(c1.lookupkeys())
    print(c2.lookupkeys())
    time.sleep(3)
    print('Connection c1 has expired?')
    print(c1.hasexpired())

    table.update_all_rgw()
