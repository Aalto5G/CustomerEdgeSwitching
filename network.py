import asyncio
import aiohttp
import json
import logging
import socket
import subprocess
import struct

import utils
import container3

from async_nfqueue import AsyncNFQueue


LOGLEVELNETWORK = logging.WARNING
LOGLEVELCONNECTION = logging.WARNING

KEY_CESLOCAL = 1
KEY_CESPUBLIC = 2

class Network(object):
    def __init__(self, name='Network', **kwargs):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVELNETWORK)
        utils.set_attributes(self, **kwargs)
        # Map packetmark to DNAT ipaddr for CircularPool
        self._pktmark_cpool = {}
        # Initialize nfqueue object to None
        self._nfqueue = None
        # Flush critical chains
        self.ipt_flush_chain('nat', self.iptables['circularpool']['chain'])
        self.ipt_flush_chain('filter', self.iptables['hostpolicy']['chain'])
        '''
        self._loop = loop
        self._ports = {}
        
        self._ports['lan']  = kwargs['lan']
        self._ports['wan']  = kwargs['wan']
        self._ports['vtep'] = kwargs['vtep']
        
        self._sdn = kwargs['sdn']
        
        # Create Session with keepalive to reduce request time
        self._session = aiohttp.ClientSession(loop=loop)
        '''
    
    def ipt_flush_chain(self, table, chain):
        self._do_subprocess_call('iptables -t {} -F {}'.format(table, chain))
        
    def ipt_add_user(self, ipaddr):
        # Add user to Circular Pool ipt_chain
        self._add_circularpool(ipaddr)
        # Add user's firewall rules and register in global host policy chain
        self._add_basic_hostpolicy(ipaddr)
    
    def ipt_remove_user(self, ipaddr):
        # Remove user from Circular Pool ipt_chain
        self._remove_circularpool(ipaddr)
        # Remove user's firewall rules and deregister in global host policy chain
        self._remove_basic_hostpolicy(ipaddr)
    
    def ipt_add_user_fwrules(self, ipaddr, chain, fwrules):
        host_chain = 'HOST_{}_{}'.format(ipaddr, chain.upper())
        # Sort list by priority of the rules
        sorted_fwrules = sorted(fwrules, key=lambda fwrule: fwrule['priority'])
        for rule in sorted_fwrules:
            xlat_rule = self._ipt_xlat_rule(host_chain, rule)
            self._do_subprocess_call(xlat_rule)
            
    def ipt_register_nfqueue(self, queue, cb):
        assert (self._nfqueue is None)
        self._nfqueue = AsyncNFQueue(queue, cb)
    
    def ipt_deregister_nfqueue(self):
        assert (self._nfqueue is not None)
        self._nfqueue.terminate()
    
    def ipt_nfpacket_dnat(self, packet, ipaddr):
        mark = self._pktmark_cpool[ipaddr]
        packet.set_mark(mark)
        packet.accept()
    
    def ipt_nfpacket_payload(self, packet):
        return packet.get_payload()

    def _add_circularpool(self, ipaddr):
        # Generate packet mark
        mark = self._gen_pktmark_cpool(ipaddr)
        # Add mark to dictionary
        self._pktmark_cpool[ipaddr] = mark
        self._pktmark_cpool[mark] = ipaddr
        # Add rule to iptables
        chain = self.iptables['circularpool']['chain']
        self._do_subprocess_call('iptables -t nat -I {} -m mark --mark 0x{:x} -j DNAT --to-destination {}'.format(chain, mark, ipaddr))
        
    def _remove_circularpool(self, ipaddr):
        # Remove mark from dictionary
        mark = self._pktmark_cpool.pop(ipaddr)
        # Remove rule from iptables
        chain = self.iptables['circularpool']['chain']
        self._do_subprocess_call('iptables -t nat -D {} -m mark --mark 0x{:x} -j DNAT --to-destination {}'.format(chain, mark, ipaddr))
    
    def _add_basic_hostpolicy(self, ipaddr):
        # Define host tables
        host_chain        = 'HOST_{}'.format(ipaddr)
        host_chain_admin  = 'HOST_{}_ADMIN'.format(ipaddr)
        host_chain_legacy = 'HOST_{}_LEGACY'.format(ipaddr)
        host_chain_ces    = 'HOST_{}_CES'.format(ipaddr)
        
        # Create basic chains for host policy
        for chain in [host_chain, host_chain_admin, host_chain_legacy, host_chain_ces]:
            # Create & flush chain
            self._do_subprocess_call('iptables -t filter -N {}'.format(chain))
            self._do_subprocess_call('iptables -t filter -F {}'.format(chain))
        
        # 1. Register triggers in global host policy chain
        ## Get packet marks based on traffic direction
        mark_in = self.iptables['pktmark']['MASK_HOST_INGRESS']
        mark_eg = self.iptables['pktmark']['MASK_HOST_EGRESS']
        ## Add rules to iptables
        chain = self.iptables['hostpolicy']['chain']
        self._do_subprocess_call('iptables -t filter -I {} -m mark --mark {} -d {} -g {}'.format(chain, mark_in, ipaddr, host_chain))
        self._do_subprocess_call('iptables -t filter -I {} -m mark --mark {} -s {} -g {}'.format(chain, mark_eg, ipaddr, host_chain))
        
        # 2. Register triggers in host chain
        ## Get packet marks based on traffic direction
        mark_legacy = self.iptables['pktmark']['MASK_HOST_LEGACY']
        mark_ces = self.iptables['pktmark']['MASK_HOST_CES']
        ## Add rules to iptables
        self._do_subprocess_call('iptables -t filter -A {}                   -j {}'.format(host_chain, host_chain_admin))
        self._do_subprocess_call('iptables -t filter -A {} -m mark --mark {} -j {}'.format(host_chain, mark_legacy, host_chain_legacy))
        self._do_subprocess_call('iptables -t filter -A {} -m mark --mark {} -j {}'.format(host_chain, mark_ces, host_chain_ces))
        self._do_subprocess_call('iptables -t filter -A {}                   -j DROP'.format(host_chain))
        
        # HACK / DEBUG
        #host_chain_accept = self.iptables['hostpolicy']['accept']
        #self._do_subprocess_call('iptables -t filter -I {}                   -j {}'.format(host_chain, host_chain_accept))
    
    def _remove_basic_hostpolicy(self, ipaddr):
        # Define host chains
        host_chain        = 'HOST_{}'.format(ipaddr)
        host_chain_admin  = 'HOST_{}_ADMIN'.format(ipaddr)
        host_chain_legacy = 'HOST_{}_LEGACY'.format(ipaddr)
        host_chain_ces    = 'HOST_{}_CES'.format(ipaddr)
        
        # 1. Remove triggers in global host policy chain
        ## Get packet marks based on traffic direction
        mark_in = self.iptables['pktmark']['MASK_HOST_INGRESS']
        mark_eg = self.iptables['pktmark']['MASK_HOST_EGRESS']
        ## Add rules to iptables
        chain = self.iptables['hostpolicy']['chain']
        self._do_subprocess_call('iptables -t filter -D {} -m mark --mark {} -d {} -g {}'.format(chain, mark_in, ipaddr, host_chain))
        self._do_subprocess_call('iptables -t filter -D {} -m mark --mark {} -s {} -g {}'.format(chain, mark_eg, ipaddr, host_chain))
        
        # 2. Remove host chains
        for chain in [host_chain, host_chain_admin, host_chain_legacy, host_chain_ces]:
            # Flush and remove chain
            self._do_subprocess_call('iptables -t filter -F {}'.format(chain))
            self._do_subprocess_call('iptables -t filter -X {}'.format(chain))
    
    
            
    def _ipt_xlat_rule(self, chain, rule):
        ret = ''
        # Append to chain
        ret += 'iptables -t filter -A {}'.format(chain)
        # Rule direction
        if rule['direction'] == 'EGRESS':
            ret += ' -m mark --mark {}'.format(self.iptables['pktmark']['MASK_HOST_EGRESS'])
        elif rule['direction'] == 'INGRESS':
            ret += ' -m mark --mark {}'.format(self.iptables['pktmark']['MASK_HOST_INGRESS'])
        elif rule['direction'] == 'ANY':
            pass
        else:
            self.logger.error('Unknown direction: {}'.format(rule['direction']))
            return
        
        # IP addresses
        if 'destination-ip' in rule:
            ret += ' -d {}'.format(rule['destination-ip'])
        if 'source-ip' in rule:
            ret += ' -s {}'.format(rule['source-ip'])
        # IP protocol
        if 'protocol' in rule:
            ret += ' -p {}'.format(rule['protocol'])
        # Transport protocol
        if 'destination-port' in rule:
            ret += ' --dport {}'.format(rule['destination-port'])
        if 'source-port' in rule:
            ret += ' --sport {}'.format(rule['source-port'])
        if 'icmp-type' in rule and 'icmp-code' in rule:
            ret += ' --icmp-type {}/{}'.format(rule['icmp-type'], rule['icmp-code'])
        elif 'icmp-type' in rule:
            ret += ' --icmp-type {}'.format(rule['icmp-type'])
        # Action
        if rule['action'] == 'ACCEPT':
            chain_accept = self.iptables['hostpolicy']['accept']
            ret += ' -g {}'.format(chain_accept)
        elif rule['action'] == 'DROP':
            # If we only DROP, there is TCP retransmission and will mess up with CircularPool
            #ret += ' -j DROP'
            # We REJECT the packet to avoid TCP retransmissions for the Circular Pool
            ret += ' -j REJECT'
        else:
            self.logger.error('Unknown action: {}'.format(rule['action']))
            return
        # Metadata
        if 'comment' in rule:
            ret += ' -m comment --comment "{}" '.format(rule['comment'])
        # Additional features
        if 'extra' in rule:
            self._logger.info('Additional iptables rule features not supported yet: {}'.format(rule))
        return ret
    
    def _gen_pktmark_cpool(self, ipaddr):
        """ Return the integer representation of an IPv4 address """
        return struct.unpack("!I", socket.inet_aton(ipaddr))[0]
    
    def _do_subprocess_call(self, command, raise_exc = False, supress_stdout = True):
        try:
            self.logger.debug('System call: ', command)
            if supress_stdout:
                with open(os.devnull, 'w') as f:
                    subprocess.check_call(command, shell=True, stdout=f)
            else:
                subprocess.check_call(command, shell=True)
        except Exception as e:
            if raise_exc:
                raise e
        
    def create_tunnel(self):
        pass
    
    def delete_tunnel(self):
        pass
    
    def create_connection(self, connection):
        
        if isinstance(connection, ConnectionCESLocal):
            msgs = self._flow_add_local(connection)
            
            for m in msgs:
                print('Sending...\n',m)
                self._loop.create_task(self._sdn_api_post(self._session, self._sdn['add'], m))
                        
    
    def delete_connection(self, connection):
        pass
    
    def _flow_add_local(self, conn):
        #TODO: Add timeouts
        
        mac_src = '00:00:00:00:00:00'
        mac_dst = self._ports['vtep']['mac']
        
        msg1 = {}
        msg1['dpid'] = 1
        msg1['table_id'] = 1
        msg1['priority'] = 1
        msg1['flags'] = 1
        msg1['match'] = {'eth_type':2048, 'ipv4_src':conn.src, 'ipv4_dst':conn.psrc}
        msg1['actions'] = [
                           {'type':'SET_FIELD', 'field':'ipv4_src', 'value':conn.pdst},
                           {'type':'SET_FIELD', 'field':'ipv4_dst', 'value':conn.dst},
                           {'type':'SET_FIELD', 'field':'eth_src', 'value':mac_src},
                           {'type':'SET_FIELD', 'field':'eth_src', 'value':mac_dst},
                           {'type':'OUTPUT', 'port':4294967288}
                           ]
        
        msg2 = {}
        msg2['dpid'] = 1
        msg2['table_id'] = 1
        msg2['priority'] = 1
        msg2['flags'] = 1
        msg2['match'] = {'eth_type':2048, 'ipv4_src':conn.dst, 'ipv4_dst':conn.pdst}
        msg2['actions'] = [{'type':'SET_FIELD', 'field':'ipv4_src', 'value':conn.psrc},
                           {'type':'SET_FIELD', 'field':'ipv4_dst', 'value':conn.src},
                           {'type':'SET_FIELD', 'field':'eth_src', 'value':mac_src},
                           {'type':'SET_FIELD', 'field':'eth_src', 'value':mac_dst},
                           {'type':'OUTPUT', 'port':4294967288}
                           ]
        
        return [json.dumps(msg1), json.dumps(msg2)]
        
    @asyncio.coroutine
    def _sdn_api_get(self, session, url, data): 
        response = yield from session.get(url, data=data)
        yield from response.release()
        return response
    
    @asyncio.coroutine
    def _sdn_api_post(self, session, url, data): 
        response = yield from session.post(url, data=data)
        yield from response.release()
        return response
    
    @asyncio.coroutine
    def _sdn_api_delete(self, session, url, data): 
        response = yield from session.delete(url, data=data)
        yield from response.release()
        return response
    

class ConnectionContainer(container3.Container):
    
    def __init__(self, name='ConnectionContainer'):
        """ Initialize the ConnectionContainer as a Container """
        super().__init__(name, LOGLEVELCONNECTION)

class ConnectionCESLocal(container3.ContainerNode):
    def __init__(self, name='ConnectionCESLocal', **kwargs):
        """ Initialize the ConnectionCESLocal as a ContainerNode """
        super().__init__(name, LOGLEVELCONNECTION)
        # Set parameters
        for k,v in kwargs.items():
            print('setattr({},{})'.format(k, v))
            setattr(self, k, v)
        
        '''
        # IP addresses
        src, psrc, dst, pdst
        # FW Rules are a combination of (direction, rules) for both hosts
        TBD
        '''
    
    def lookupkeys(self):
        """ Return the lookup keys of the node """
        return (((self.src, self.psrc), False),
                ((self.dst, self.pdst), False))
        

class ConnectionCESPublic(container3.ContainerNode):
    def __init__(self, name='ConnectionCESPublic', **kwargs):
        """ Initialize the ConnectionCESPublic as a ContainerNode """
        super().__init__(name, LOGLEVELCONNECTION)
    
    def lookupkeys(self):
        """ Return the lookup keys of the node """
        return ((self._key, False),)