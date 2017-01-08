import asyncio
import aiohttp
import json
import logging
import socket, struct
import os, subprocess
import random, string

from aalto_helpers import container3
from aalto_helpers import utils3
from aalto_helpers import iptc_helper3
from aalto_helpers import iproute2_helper3
from nfqueue3 import NFQueue3
from loglevel import LOGLEVEL_NETWORK


# Definition of PACKET MARKS
## Definition of specific packet MARK for traffic
MARK_LOCAL_FROM_LAN      = '0xFF121212/0xFFFFFFFF'
MARK_LOCAL_TO_LAN        = '0xFF211221/0xFFFFFFFF'
MARK_LOCAL_FROM_WAN      = '0xFF021113/0xFFFFFFFF'
MARK_LOCAL_TO_WAN        = '0xFF011131/0xFFFFFFFF'
MARK_LOCAL_FROM_TUN      = '0xFF021114/0xFFFFFFFF'
MARK_LOCAL_TO_TUN        = '0xFF011141/0xFFFFFFFF'
MARK_LAN_TO_WAN          = '0xFF222232/0xFFFFFFFF'
MARK_LAN_FROM_WAN        = '0xFF112223/0xFFFFFFFF'
MARK_LAN_TO_TUN          = '0xFF222342/0xFFFFFFFF'
MARK_LAN_FROM_TUN        = '0xFF112324/0xFFFFFFFF'
## Definition of packet MASKS for traffic
### Classified by traffic scope and direction
MASK_LOCAL               = '0xFF001010/0xFF00F0F0'
MASK_LOCAL_INGRESS       = '0xFF021010/0xFF0FF0F0'
MASK_LOCAL_EGRESS        = '0xFF011001/0xFF0FF00F'
MASK_HOST_INGRESS        = '0xFF000020/0xFF0000F0'
MASK_HOST_EGRESS         = '0xFF000002/0xFF00000F'
MASK_HOST_LEGACY         = '0xFF000200/0xFF000F00'
MASK_HOST_LEGACY_INGRESS = '0xFF000220/0xFF000FF0'
MASK_HOST_LEGACY_EGRESS  = '0xFF000202/0xFF000F0F'
MASK_HOST_CES            = '0xFF000300/0xFF000F00'
MASK_HOST_CES_INGRESS    = '0xFF000320/0xFF000FF0'
MASK_HOST_CES_EGRESS     = '0xFF000302/0xFF000F0F'
### Classified by ingress or egress interface
MASK_LAN_INGRESS         = '0xFF000002/0xFF00000F'
MASK_WAN_INGRESS         = '0xFF000003/0xFF00000F'
MASK_TUN_INGRESS         = '0xFF000004/0xFF00000F'
MASK_LAN_EGRESS          = '0xFF000020/0xFF0000F0'
MASK_WAN_EGRESS          = '0xFF000030/0xFF0000F0'
MASK_TUN_EGRESS          = '0xFF000040/0xFF0000F0'


class Network(object):
    def __init__(self, name='Network', **kwargs):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_NETWORK)
        utils3.set_attributes(self, **kwargs)
        # Initialize nfqueues list
        self._nfqueues = []
        # Test if MARKDNAT is available in the system
        self._enabled_MARKDNAT = self._test_MARKDNAT()
        # Flush conntrack
        self.ipt_flush_conntrack()
        # Initialize ipsets
        self.ips_init()
        # Initialize iptables
        self.ipt_init()

    def ips_init(self):
        data_d = self.datarepository.get_policy('IPSET', {})
        self._logger.info('Installing local ipset policy: {} requirements and {} rules'.format(len(data_d['requires']), len(data_d['rules'])))
        # Install requirements
        for i, entry in enumerate(data_d.setdefault('requires', [])):
            self._logger.debug('#{} requires {} {}'.format(i+1, entry['name'], entry['type']))
            if entry.setdefault('create',False) and not iproute2_helper3.ipset_exists(entry['name']):
                iproute2_helper3.ipset_create(entry['name'], entry['type'])
            if entry.setdefault('flush',False):
                iproute2_helper3.ipset_flush(entry['name'])
        # Populate ipsets
        for entry in data_d.setdefault('rules', []):
            self._logger.debug('Adding {} items to {} type {}'.format(len(entry['items']), entry['name'], entry['type']))
            for i, e in enumerate(entry['items']):
                self._logger.debug('#{} Adding {}'.format(i+1, e))
                iproute2_helper3.ipset_add(entry['name'], e, etype=entry['type'])

    def ipt_init(self):
        data_d = self.datarepository.get_policy('IPTABLES', {})
        for p in self.ipt_policy_order:
            if p not in data_d:
                self._logger.critical('Not found local iptables policy <{}>'.format(p))
                continue
            policy_d = data_d[p]
            self._logger.info('Installing local iptables policy <{}>: {} requirements and {} rules'.format(p, len(policy_d['requires']), len(policy_d['rules'])))
            # Install requirements
            for i, entry in enumerate(policy_d.setdefault('requires', [])):
                self._logger.debug('#{} requires {}.{}'.format(i+1, entry['table'], entry['chain']))
                if entry.setdefault('create',False) and not iptc_helper3.has_chain(entry['table'], entry['chain']):
                    iptc_helper3.add_chain(entry['table'], entry['chain'], silent=False)
                if entry.setdefault('flush',False):
                    iptc_helper3.flush_chain(entry['table'], entry['chain'])
            # Install rules
            for i, entry in enumerate(policy_d.setdefault('rules', [])):
                self._logger.debug('#{} Adding to {}.{} {}'.format(i+1, entry['table'], entry['chain'], entry['rule']))
                iptc_helper3.add_rule(entry['table'], entry['chain'], entry['rule'])

    def ipt_flush_conntrack(self):
        if self._do_subprocess_call('conntrack -F', False, False):
            self._logger.info('Successfully flushed connection tracking information')
            return
        self._logger.warning('Failed to flush connection tracking information')

    def ipt_flush_chain(self, table, chain):
        iptc_helper3.flush_chain(table, chain)

    def ipt_zero_chain(self, table, chain):
        iptc_helper3.zero_chain(table, chain)

    def ipt_add_user(self, hostname, ipaddr):
        self._logger.debug('Add user {}/{}'.format(hostname, ipaddr))
        # Remove previous user data
        self.ipt_remove_user(hostname, ipaddr)
        # Add user to Circular Pool ipt_chain
        self._add_circularpool(hostname, ipaddr)
        # Add user's firewall rules and register in global host policy chain
        self._add_basic_hostpolicy(hostname, ipaddr)

    def ipt_remove_user(self, hostname, ipaddr):
        self._logger.debug('Remove user {}/{}'.format(hostname, ipaddr))
        # Remove user from Circular Pool ipt_chain
        self._remove_circularpool(hostname, ipaddr)
        # Remove user's firewall rules and deregister in global host policy chain
        self._remove_basic_hostpolicy(hostname, ipaddr)

    def ipt_add_user_carriergrade(self, hostname, cgaddrs):
        self._logger.debug('Add carrier grade user {}/{}'.format(hostname, cgaddrs))
        for item in cgaddrs:
            ipaddr = item['ipv4']
            self._logger.debug('Add carrier grade user address {}/{}'.format(hostname, ipaddr))
            # Add carriergrade user to Circular Pool ipt_chain
            self._add_circularpool(hostname, ipaddr)
            # Add user's firewall rules and register in global host policy chain
            self._add_basic_hostpolicy_carriergrade(hostname, ipaddr)

    def ipt_remove_user_carriergrade(self, hostname, cgaddrs):
        self._logger.debug('Remove carrier grade user {}/{}'.format(hostname, cgaddrs))
        for item in cgaddrs:
            ipaddr = item['ipv4']
            self._logger.debug('Remove carrier grade user address {}/{}'.format(hostname, ipaddr))
            # Remove carriergrade user to Circular Pool ipt_chain
            self._remove_circularpool(hostname, ipaddr)
            # Remove user's firewall rules and register in global host policy chain
            self._remove_basic_hostpolicy_carriergrade(hostname, ipaddr)

    def ipt_add_user_fwrules(self, hostname, ipaddr, chain, fwrules):
        host_chain = 'HOST_{}_{}'.format(hostname, chain.upper())
        self._logger.debug('Add fwrules for user {}/{} to chain <{}> ({})'.format(hostname, ipaddr, host_chain, len(fwrules)))
        # Sort list by priority of the rules
        sorted_fwrules = sorted(fwrules, key=lambda rule: rule['priority'])
        # Flush chain before inserting the lot
        iptc_helper3.flush_chain('filter', host_chain)
        for rule in sorted_fwrules:
            xlat_rule = self._ipt_xlat_rule(host_chain, rule)
            iptc_helper3.add_rule('filter', host_chain, xlat_rule)

    def ipt_add_user_groups(self, hostname, ipaddr, groups):
        self._logger.debug('Registering groups for user {}/{} to <{}>'.format(hostname, ipaddr, groups))
        for group in groups:
            if not iproute2_helper3.ipset_exists(group):
                self._logger.error('Subscriber group {} does not exist!'.format(group))
                continue
            iproute2_helper3.ipset_add(group, ipaddr)

    def ipt_remove_user_groups(self, hostname, ipaddr, groups):
        self._logger.debug('Removing groups for user {}/{} to <{}> ({})'.format(hostname, ipaddr, groups))
        for group in groups:
            if not iproute2_helper3.ipset_exists(group):
                self._logger.error('Subscriber group {} does not exist!'.format(group))
                continue
            iproute2_helper3.ipset_delete(group, ipaddr)

    def ipt_register_nfqueues(self, cb, *cb_args, **cb_kwargs):
        for queue in self.ipt_cpool_queue:
            self._nfqueues.append(NFQueue3(queue, cb, *cb_args, **cb_kwargs))

    def ipt_deregister_nfqueues(self):
        for nfqueueObj in self._nfqueues:
            nfqueueObj.terminate()

    def ipt_nfpacket_dnat(self, packet, ipaddr):
        mark = self._gen_pktmark_cpool(ipaddr)
        packet.set_mark(mark)
        packet.accept()

    def ipt_nfpacket_accept(self, packet):
        packet.accept()

    def ipt_nfpacket_drop(self, packet):
        packet.drop()

    def ipt_nfpacket_payload(self, packet):
        return packet.get_payload()

    def _test_MARKDNAT(self):
        ''' Create a temporary chain to insert a MARKDNAT test rule.
        Check if the rule is successfully inserted '''
        try:
            ret = False
            table = 'nat'
            chain = ''.join(random.choice(string.ascii_lowercase) for _ in range(25))
            rule_l = [['target',{'MARKDNAT':{'or-mark':'0'}}]]
            while iptc_helper3.has_chain(table, chain):
                chain = ''.join(random.choice(string.ascii_lowercase) for _ in range(25))
            iptc_helper3.add_chain(table, chain)
            iptc_helper3.add_rule(table, chain, rule_l)
            if iptc_helper3.dump_chain(table, chain):
                self._logger.info('Supported iptables MARKDNAT target')
                ret = True
            else:
                self._logger.warning('Unsupported iptables MARKDNAT target')
                ret = False
        except:
            ret = False
        finally:
            # Delete temporary chain
            iptc_helper3.flush_chain(table, chain)
            iptc_helper3.delete_chain(table, chain)
            return ret

    def _add_circularpool(self, hostname, ipaddr):
        # Do not add specific rule if MARKDNAT is enabled
        if self._enabled_MARKDNAT:
            return
        # Add rule to iptables
        table = 'nat'
        chain = self.ipt_cpool_chain
        mark = self._gen_pktmark_cpool(ipaddr)
        rule = {'mark':{'mark':hex(mark)}, 'target':{'DNAT':{'to-destination':ipaddr}}}
        iptc_helper3.add_rule(table, chain, rule)

    def _remove_circularpool(self, hostname, ipaddr):
        # Do not delete specific rule if MARKDNAT is enabled
        if self._enabled_MARKDNAT:
            return
        # Remove rule from iptables
        table = 'nat'
        chain = self.ipt_cpool_chain
        mark = self._gen_pktmark_cpool(ipaddr)
        rule = {'mark':{'mark':hex(mark)}, 'target':{'DNAT':{'to-destination':ipaddr}}}
        iptc_helper3.delete_rule(table, chain, rule, True)

    def _add_basic_hostpolicy(self, hostname, ipaddr):
        # Define host tables
        host_chain          = 'HOST_{}'.format(hostname)
        host_chain_admin    = 'HOST_{}_ADMIN'.format(hostname)
        host_chain_user     = 'HOST_{}_USER'.format(hostname)
        host_chain_ces      = 'HOST_{}_CES'.format(hostname)

        # Create basic chains for host policy
        for chain in [host_chain, host_chain_admin, host_chain_user, host_chain_ces]:
            self._ipt_create_chain('filter', chain)

        # 1. Register triggers in global host policy chain
        ## Add rules to iptables
        chain = self.ipt_host_chain
        iptc_helper3.add_rule('filter', chain, {'mark':{'mark':MASK_HOST_INGRESS}, 'dst':ipaddr, 'target':host_chain})
        iptc_helper3.add_rule('filter', chain, {'mark':{'mark':MASK_HOST_EGRESS},  'src':ipaddr, 'target':host_chain})

        # 2. Register triggers in host chain
        ## Add rules to iptables
        iptc_helper3.add_rule('filter', host_chain, {'target':host_chain_admin})
        iptc_helper3.add_rule('filter', host_chain, {'target':host_chain_user})
        iptc_helper3.add_rule('filter', host_chain, {'target':host_chain_ces, 'mark':{'mark':MASK_HOST_CES}})
        # Add a variable for default host policy
        iptc_helper3.add_rule('filter', host_chain, {'target':self.ipt_host_unknown})

    def _remove_basic_hostpolicy(self, hostname, ipaddr):
        # Define host tables
        host_chain          = 'HOST_{}'.format(hostname)
        host_chain_admin    = 'HOST_{}_ADMIN'.format(hostname)
        host_chain_user     = 'HOST_{}_USER'.format(hostname)
        host_chain_ces      = 'HOST_{}_CES'.format(hostname)

        # 1. Remove triggers in global host policy chain
        ## Add rules to iptables
        chain = self.ipt_host_chain
        iptc_helper3.delete_rule('filter', chain, {'mark':{'mark':MASK_HOST_INGRESS}, 'dst':ipaddr, 'target':host_chain}, True)
        iptc_helper3.delete_rule('filter', chain, {'mark':{'mark':MASK_HOST_EGRESS},  'src':ipaddr, 'target':host_chain}, True)

        # 2. Remove host chains
        for chain in [host_chain, host_chain_admin, host_chain_user, host_chain_ces]:
            self._ipt_remove_chain('filter', chain)

    def _add_basic_hostpolicy_carriergrade(self, hostname, ipaddr):
        # Define host tables
        host_chain          = 'HOST_{}'.format(hostname)
        # 1. Register triggers in global host policy chain
        ## Add rules to iptables
        chain = self.ipt_host_chain
        iptc_helper3.add_rule('filter', chain, {'mark':{'mark':MASK_HOST_INGRESS}, 'dst':ipaddr, 'target':host_chain})
        iptc_helper3.add_rule('filter', chain, {'mark':{'mark':MASK_HOST_EGRESS},  'src':ipaddr, 'target':host_chain})

    def _remove_basic_hostpolicy_carriergrade(self, hostname, ipaddr):
        # Define host tables
        host_chain          = 'HOST_{}'.format(hostname)
        # 1. Register triggers in global host policy chain
        ## Add rules to iptables
        chain = self.ipt_host_chain
        iptc_helper3.delete_rule('filter', chain, {'mark':{'mark':MASK_HOST_INGRESS}, 'dst':ipaddr, 'target':host_chain}, True)
        iptc_helper3.delete_rule('filter', chain, {'mark':{'mark':MASK_HOST_EGRESS},  'src':ipaddr, 'target':host_chain}, True)

    def _ipt_create_chain(self, table, chain, flush = False):
        # Create and flush to ensure an empty table
        iptc_helper3.add_chain(table, chain)
        if flush:
            iptc_helper3.flush_chain(table, chain, silent=True)

    def _ipt_remove_chain(self, table, chain):
        # Flush and delete to ensure the table is removed
        iptc_helper3.flush_chain(table, chain, silent=True)
        iptc_helper3.delete_chain(table, chain, silent=True)

    def _ipt_xlat_rule(self, chain, rule):
        ret = dict(rule)
        # Translate direction value into packet mark
        if ret['direction'] == 'EGRESS':
            ret['mark'] = {'mark':MASK_HOST_EGRESS}
        elif ret['direction'] == 'INGRESS':
            ret['mark'] = {'mark':MASK_HOST_INGRESS}
        elif ret['direction'] == 'ANY':
            pass
        else:
            raise AttributeError('Unknown direction: {}'.format(ret['direction']))
        return ret

    def _gen_pktmark_cpool(self, ipaddr):
        """ Return the integer representation of an IPv4 address """
        return struct.unpack("!I", socket.inet_aton(ipaddr))[0]

    def _do_subprocess_call(self, command, raise_exc = False, supress_stdout = True):
        try:
            self._logger.debug('System call: {}'.format(command))
            if supress_stdout:
                with open(os.devnull, 'w') as f:
                    subprocess.check_call(command, shell=True, stdout=f, stderr=f)
            else:
                subprocess.check_call(command, shell=True)
            return True
        except Exception as e:
            self._logger.info(e)
            if raise_exc:
                raise e
            return False

    '''
    # This is for CES

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
    '''
