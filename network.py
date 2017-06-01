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
from aiohttp_client import HTTPRestClient
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

# Define variables for SDN API
OVS_DATAPATH_ID     = 0x0000000000123456
OVS_PORT_IN_        = 0xfffffff8
OVS_PORT_TUN_L3     = 100
OVS_PORT_TUN_GRE    = 101
OVS_PORT_TUN_VXLAN  = 102
OVS_PORT_TUN_GENEVE = 103
OVS_PORT_TUN_L3_MAC = '00:00:00:12:34:56'
OVS_PORT_TUN_L3_NET = '172.16.0.0/24'

API_URL_SWITCHES    = 'http://127.0.0.1:8081/stats/switches'
API_URL_FLOW_ADD    = 'http://127.0.0.1:8081/stats/flowentry/add'
API_URL_FLOW_DELETE = 'http://127.0.0.1:8081/stats/flowentry/delete'


class Network(object):
    def __init__(self, name='Network', **kwargs):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LOGLEVEL_NETWORK)
        utils3.set_attributes(self, **kwargs)
        # Initialize nfqueues list
        self._nfqueues = []
        # Configure MARKDNAT
        self._setup_MARKDNAT()
        # Flushing
        self._do_flushing()
        # Initialize ipsets
        self.ips_init()
        # Initialize iptables
        self.ipt_init()
        # Create HTTP REST Client
        self.rest_api_init()
        # Create OpenvSwitch
        self.init_openvswitch()

        # Use control variable to indicate readiness
        self.ready = False

    def ips_init(self):
        data_d = self.datarepository.get_policy('IPSET', {})
        requires = data_d.setdefault('requires', [])
        rules = data_d.setdefault('rules', [])
        self._logger.info('Installing local ipset policy: {} requirements and {} rules'.format(len(requires), len(rules)))
        # Install requirements
        for i, entry in enumerate(requires):
            self._logger.debug('#{} requires {} {}'.format(i+1, entry['name'], entry['type']))
            if entry.setdefault('create',False) and not iproute2_helper3.ipset_exists(entry['name']):
                iproute2_helper3.ipset_create(entry['name'], entry['type'])
            if entry.setdefault('flush',False):
                iproute2_helper3.ipset_flush(entry['name'])
        # Populate ipsets
        for entry in rules:
            self._logger.debug('Adding {} items to {} type {}'.format(len(entry['items']), entry['name'], entry['type']))
            for i, e in enumerate(entry['items']):
                try:
                    self._logger.debug('#{} Adding {}'.format(i+1, e))
                    iproute2_helper3.ipset_add(entry['name'], e, etype=entry['type'])
                except:
                    self._logger.error('#{} Failed to add {}'.format(i+1, e))

    def ipt_init(self):
        data_d = self.datarepository.get_policy('IPTABLES', {})
        for p in self.ipt_policy_order:
            if p not in data_d:
                self._logger.critical('Not found local iptables policy <{}>'.format(p))
                continue
            policy_d = data_d[p]
            requires = policy_d.setdefault('requires', [])
            rules = policy_d.setdefault('rules', [])
            self._logger.info('Installing local iptables policy <{}>: {} requirements and {} rules'.format(p, len(requires), len(rules)))
            # Install requirements
            for i, entry in enumerate(requires):
                self._logger.debug('#{} requires {}.{}'.format(i+1, entry['table'], entry['chain']))
                if entry.setdefault('create',False) and not iptc_helper3.has_chain(entry['table'], entry['chain']):
                    iptc_helper3.add_chain(entry['table'], entry['chain'], silent=False)
                if entry.setdefault('flush',False):
                    iptc_helper3.flush_chain(entry['table'], entry['chain'])
            # Install rules
            for i, entry in enumerate(rules):
                try:
                    self._logger.debug('#{} Adding to {}.{} {}'.format(i+1, entry['table'], entry['chain'], entry['rule']))
                    iptc_helper3.add_rule(entry['table'], entry['chain'], entry['rule'])
                except:
                    self._logger.error('#{} Failed to add to {}.{} {}'.format(i+1, entry['table'], entry['chain'], entry['rule']))

    def _do_flushing(self):
        # Flush conntrack
        if self._do_subprocess_call('conntrack -F', False, False):
            self._logger.info('Successfully flushed connection tracking information')
        else:
            self._logger.warning('Failed to flush connection tracking information')

        # Flush iptables & ipset
        if self.ipt_flush:
            iptc_helper3.flush_all()
            self._logger.info('Successfully flushed iptables')
            iproute2_helper3.ipset_flush()
            self._logger.info('Successfully flushed ipset')

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
        # Add user's IP address to ipset for registered hosts
        if not iproute2_helper3.ipset_test(self.ips_hosts, ipaddr):
            self._logger.debug('Adding host {} to ipset {}'.format(ipaddr, self.ips_hosts))
            iproute2_helper3.ipset_add(self.ips_hosts, ipaddr)

    def ipt_remove_user(self, hostname, ipaddr):
        self._logger.debug('Remove user {}/{}'.format(hostname, ipaddr))
        # Remove user from Circular Pool ipt_chain
        self._remove_circularpool(hostname, ipaddr)
        # Remove user's firewall rules and deregister in global host policy chain
        self._remove_basic_hostpolicy(hostname, ipaddr)
        # Remove user's IP address from ipset of registered hosts
        if iproute2_helper3.ipset_test(self.ips_hosts, ipaddr):
            self._logger.debug('Removing host {} from ipset {}'.format(ipaddr, self.ips_hosts))
            iproute2_helper3.ipset_delete(self.ips_hosts, ipaddr)
        # Delete conntrack entries
        ## Delete connection matching source IP address
        if self._do_subprocess_call('conntrack -D --src {}'.format(ipaddr), False, True):
            self._logger.debug('Successfully deleted connections: conntrack -D --src {}'.format(ipaddr))
        ## Delete connection matching destination IP address
        if self._do_subprocess_call('conntrack -D --reply-src {}'.format(ipaddr), False, True):
            self._logger.debug('Successfully deleted connections: conntrack -D --reply-src {}'.format(ipaddr))

    def ipt_add_user_carriergrade(self, hostname, cgaddrs):
        self._logger.debug('Add carrier grade user {}/{}'.format(hostname, cgaddrs))
        for item in cgaddrs:
            ipaddr = item['ipv4']
            self._logger.debug('Add carrier grade user address {}/{}'.format(hostname, ipaddr))
            # Add carriergrade user to Circular Pool ipt_chain
            self._add_circularpool(hostname, ipaddr)
            # Add user's firewall rules and register in global host policy chain
            self._add_basic_hostpolicy_carriergrade(hostname, ipaddr)
            # Add user's IP address to ipset for registered hosts
            if not iproute2_helper3.ipset_test(self.ips_hosts, ipaddr):
                self._logger.debug('Adding host {} to ipset {}'.format(ipaddr, self.ips_hosts))
                iproute2_helper3.ipset_add(self.ips_hosts, ipaddr)

    def ipt_remove_user_carriergrade(self, hostname, cgaddrs):
        self._logger.debug('Remove carrier grade user {}/{}'.format(hostname, cgaddrs))
        for item in cgaddrs:
            ipaddr = item['ipv4']
            self._logger.debug('Remove carrier grade user address {}/{}'.format(hostname, ipaddr))
            # Remove carriergrade user to Circular Pool ipt_chain
            self._remove_circularpool(hostname, ipaddr)
            # Remove user's firewall rules and register in global host policy chain
            self._remove_basic_hostpolicy_carriergrade(hostname, ipaddr)
            # Remove user's IP address from ipset of registered hosts
            if iproute2_helper3.ipset_test(self.ips_hosts, ipaddr):
                self._logger.debug('Removing host {} from ipset {}'.format(ipaddr, self.ips_hosts))
                iproute2_helper3.ipset_delete(self.ips_hosts, ipaddr)

    def ipt_add_user_fwrules(self, hostname, ipaddr, chain, fwrules):
        host_chain = 'HOST_{}_{}'.format(hostname, chain.upper())
        self._logger.debug('Add fwrules for user {}/{} to chain <{}> ({})'.format(hostname, ipaddr, host_chain, len(fwrules)))
        rules_batch = []
        # Sort list by priority of the rules
        for rule in sorted(fwrules, key=lambda rule: rule['priority']):
            xlat_rule = self._ipt_xlat_rule(host_chain, rule)
            rules_batch.append((host_chain, xlat_rule, 0))
        # Use new batch function
        iptc_helper3.batch_add_rules('filter', rules_batch)

    def ipt_add_user_groups(self, hostname, ipaddr, groups):
        self._logger.debug('Registering groups for user {}/{} <{}>'.format(hostname, ipaddr, groups))
        for group in groups:
            if not iproute2_helper3.ipset_exists(group):
                self._logger.error('Subscriber group {} does not exist!'.format(group))
                continue
            iproute2_helper3.ipset_add(group, ipaddr)

    def ipt_remove_user_groups(self, hostname, ipaddr, groups):
        self._logger.debug('Removing groups for user {}/{} <{}>'.format(hostname, ipaddr, groups))
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

    def _setup_MARKDNAT(self):
        ''' Attempt to enable MARKDNAT target '''
        self._enabled_MARKDNAT = False
        markdnat_capable = self._test_MARKDNAT()
        (w,c) = (self.ipt_markdnat, markdnat_capable)
        if (w,c) == (True, True):
            self._logger.info('Enabled iptables MARKDNAT target')
            self._enabled_MARKDNAT = True
        elif (w,c) == (False, True):
            self._logger.info('Disabled iptables MARKDNAT target')
        elif (w,c) == (True, False):
            self._logger.warning('Unsupported iptables MARKDNAT target')
        elif (w,c) == (False, False):
            self._logger.info('Unavailable iptables MARKDNAT target')

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
                self._logger.debug('MARKDNAT capable')
                ret = True
            else:
                self._logger.debug('MARKDNAT uncapable')
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

        # Create & flush basic chains for host policy
        # Use new batch function
        iptc_helper3.batch_add_chains('filter', (host_chain, host_chain_admin, host_chain_user, host_chain_ces), True)

        rules_batch = []
        # 1. Register triggers in global host policy chain
        ## Add rules to iptables
        rules_batch.append((self.ipt_host_chain,{'mark':{'mark':MASK_HOST_INGRESS}, 'dst':ipaddr, 'target':host_chain},0))
        rules_batch.append((self.ipt_host_chain,{'mark':{'mark':MASK_HOST_EGRESS},  'src':ipaddr, 'target':host_chain},0))

        # 2. Register triggers in host chain
        ## Add rules to iptables
        rules_batch.append((host_chain, {'target':host_chain_admin}, 0))
        rules_batch.append((host_chain, {'target':host_chain_user}, 0))
        rules_batch.append((host_chain, {'target':host_chain_ces, 'mark':{'mark':MASK_HOST_CES}}, 0))
        # Add a variable for default host policy
        rules_batch.append((host_chain, {'target':self.ipt_host_unknown}, 0))
        # Use new batch function
        iptc_helper3.batch_add_rules('filter', rules_batch)

    def _remove_basic_hostpolicy(self, hostname, ipaddr):
        # Define host tables
        host_chain          = 'HOST_{}'.format(hostname)
        host_chain_admin    = 'HOST_{}_ADMIN'.format(hostname)
        host_chain_user     = 'HOST_{}_USER'.format(hostname)
        host_chain_ces      = 'HOST_{}_CES'.format(hostname)

        rules_batch = []
        # 1. Remove triggers in global host policy chain
        ## Add rules to iptables
        rules_batch.append((self.ipt_host_chain, {'mark':{'mark':MASK_HOST_INGRESS}, 'dst':ipaddr, 'target':host_chain}))
        rules_batch.append((self.ipt_host_chain, {'mark':{'mark':MASK_HOST_EGRESS},  'src':ipaddr, 'target':host_chain}))
        # Use new batch functions
        iptc_helper3.batch_delete_rules('filter', rules_batch)

        # 2. Remove host chains
        # Use new batch function
        iptc_helper3.batch_delete_chains('filter', (host_chain, host_chain_admin, host_chain_user, host_chain_ces))


    def _add_basic_hostpolicy_carriergrade(self, hostname, ipaddr):
        # Define host tables
        host_chain          = 'HOST_{}'.format(hostname)

        rules_batch = []
        # 1. Register triggers in global host policy chain
        ## Add rules to iptables
        rules_batch.append((self.ipt_host_chain, {'mark':{'mark':MASK_HOST_INGRESS}, 'dst':ipaddr, 'target':host_chain}, 0))
        rules_batch.append((self.ipt_host_chain, {'mark':{'mark':MASK_HOST_EGRESS},  'src':ipaddr, 'target':host_chain}, 0))
        # Use new batch function
        iptc_helper3.batch_add_rules('filter', rules_batch)

    def _remove_basic_hostpolicy_carriergrade(self, hostname, ipaddr):
        # Define host tables
        host_chain          = 'HOST_{}'.format(hostname)

        rules_batch = []
        # 1. Register triggers in global host policy chain
        ## Add rules to iptables
        rules_batch.append((self.ipt_host_chain, {'mark':{'mark':MASK_HOST_INGRESS}, 'dst':ipaddr, 'target':host_chain}))
        rules_batch.append((self.ipt_host_chain, {'mark':{'mark':MASK_HOST_EGRESS},  'src':ipaddr, 'target':host_chain}))
        # Use new batch functions
        iptc_helper3.batch_delete_rules('filter', rules_batch)

    '''
        ### Not in use since the addition of batch processing ###

    def _ipt_create_chain(self, table, chain, flush = False):
        # Create and flush to ensure an empty table
        iptc_helper3.add_chain(table, chain)
        if flush:
            iptc_helper3.flush_chain(table, chain, silent=True)

    def _ipt_remove_chain(self, table, chain):
        # Flush and delete to ensure the table is removed
        iptc_helper3.flush_chain(table, chain, silent=True)
        iptc_helper3.delete_chain(table, chain, silent=True)
    '''

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

    def _do_subprocess_call(self, command, raise_exc = True, silent = False):
        try:
            self._logger.debug('System call: {}'.format(command))
            if silent:
                with open(os.devnull, 'w') as f:
                    subprocess.check_call(command, shell=True, stdout=f, stderr=f)
            else:
                subprocess.check_call(command, shell=True)
            return True
        except Exception as e:
            if not silent:
                self._logger.info(e)
            if raise_exc:
                raise e
            return False


    def rest_api_init(self):
        """ Create long lived HTTP session """
        self.rest_api = HTTPRestClient(5)

    def rest_api_close(self):
        self.rest_api.close()

    def init_openvswitch(self):
        # Create OpenvSwitch for CES data tunnelling
        ## Create OVS bridge, set datapath-id (16 hex digits) and configure controller
        to_exec = ['ovs-vsctl --if-exists del-br br-ces0',
                   'ovs-vsctl add-br br-ces0',
                   'ovs-vsctl set bridge br-ces0 other-config:datapath-id={:016x}'.format(OVS_DATAPATH_ID),
                   'ovs-vsctl set-controller br-ces0 tcp:127.0.0.1:6653']
        for _ in to_exec:
            self._do_subprocess_call(_)

        ## Add ports
        to_exec = ['ovs-vsctl add-port br-ces0 tun0 -- set interface tun0 ofport_request={} -- set interface tun0 type=internal'.format(OVS_PORT_TUN_L3),
                   'ovs-vsctl add-port br-ces0 gre0-ces0 -- set interface gre0-ces0 ofport_request={} -- set interface gre0-ces0 type=gre options:key=flow options:remote_ip=flow options:local_ip=flow'.format(OVS_PORT_TUN_GRE),
                   'ovs-vsctl add-port br-ces0 vxlan0-ces0 -- set interface vxlan0-ces0 ofport_request={} -- set interface vxlan0-ces0 type=vxlan options:key=flow options:remote_ip=flow options:local_ip=flow'.format(OVS_PORT_TUN_VXLAN),
                   'ovs-vsctl add-port br-ces0 geneve0-ces0 -- set interface geneve0-ces0 ofport_request={} -- set interface geneve0-ces0 type=geneve options:key=flow options:remote_ip=flow options:local_ip=flow'.format(OVS_PORT_TUN_GENEVE)]
        for _ in to_exec:
            self._do_subprocess_call(_)

        ## Configure tun0 port
        to_exec = ['ip link set dev tun0 arp off',
                   'ip link set dev tun0 address {}'.format(OVS_PORT_TUN_L3_MAC),
                   'ip link set dev tun0 mtu 1400',
                   'ip link set dev tun0 up',
                   'ip route add {} dev tun0'.format(OVS_PORT_TUN_L3_NET)]
        for _ in to_exec:
            self._do_subprocess_call(_)

        # Schedule task to wait for SDN Controller
        asyncio.ensure_future(self.wait_up())

    @asyncio.coroutine
    def wait_up(self):
        """ Check with SDN controller the availability of the OpenvSwitch instance """
        while True:
            self.logger.info('wait_up()')
            url = API_URL_SWITCHES
            response = yield from self.rest_api.go_get(url, None)
            print(response)
            yield from asyncio.sleep(5)

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

    '''

'''
# Create OpenvSwitch for CES data tunnelling

## Create OVS bridges
ovs-vsctl --if-exists del-br br-ces0
ovs-vsctl             add-br br-ces0

## Set datapath-id (16 hex digits)
#ovs-vsctl set bridge br-ces0 other-config:datapath-id=0000000000000001
ovs-vsctl set bridge br-ces0 other-config:datapath-id=0000000000123456

## Configure controller
ovs-vsctl set-controller br-ces0 tcp:127.0.0.1:6653


## Add ports
ovs-vsctl add-port br-ces0 tun0         -- set interface tun0         ofport_request=100 -- set interface tun0         type=internal
ovs-vsctl add-port br-ces0 gre0-ces0    -- set interface gre0-ces0    ofport_request=101 -- set interface gre0-ces0    type=gre       options:key=flow options:remote_ip=flow options:local_ip=flow
ovs-vsctl add-port br-ces0 vxlan0-ces0  -- set interface vxlan0-ces0  ofport_request=102 -- set interface vxlan0-ces0  type=vxlan     options:key=flow options:remote_ip=flow options:local_ip=flow
ovs-vsctl add-port br-ces0 geneve0-ces0 -- set interface geneve0-ces0 ofport_request=103 -- set interface geneve0-ces0 type=geneve    options:key=flow options:remote_ip=flow options:local_ip=flow

## Configure tun0 port
ip link set dev tun0 arp off
ip link set dev tun0 address 00:00:00:12:34:56
ip link set dev tun0 mtu 1400
ip link set dev tun0 up
ip route add 172.16.0.0/16 dev tun0


# Run Ryu
export RYU_PATH="/usr/local/lib/python3.5/dist-packages/ryu"
ryu-manager --ofp-listen-host 127.0.0.1 \
            --ofp-tcp-listen-port 6653  \
            --wsapi-host 127.0.0.1      \
            --wsapi-port 8081           \
            --verbose                   \
            $RYU_PATH/app/ofctl_rest.py


'''