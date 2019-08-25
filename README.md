# Customer Edge Switching

## Introduction

The CES-based cooperative network firewall leads to Policy-based communication between end hosts (in private networks), and is backwards compatible with legacy Internet via Realm Gateway (RGW) solution.The source code of CES/CETP based cooperative network firewalling builds on Realm Gateway (RGW) implementation, made public at: https://github.com/Aalto5G/RealmGateway.

This second version of Customer Edge Switching (CES) has been developed in Ubuntu 16.04, using python3's asyncio framework for asynchronous calls. The CES implementation has been validated with a test network, developed using LXC container and other Linux networking features. The project source code provides an easy orchestration of these test networks, for rapid testing of CES functions.

This repository contains a submodule, and thus it shall be cloned as following: ```git clone $REPOSITORY_URL --recursive```


## Install package dependencies
The following dependencies are required:

```
# apt-get update
# apt-get install build-essential python3-dev libnetfilter-queue-dev python3-pip
# apt-get install ipset libipset3 iptables ipset ebtables bridge-utils
# apt-get install ipsec-tools openvswitch-common openvswitch-ipsec openvswitch-switch python-openvswitch racoon
# apt-get install python3-aiohttp python3-yaml python3-dnspython
```

The following python dependencies are required:

```
$ pip3 install --upgrade pip setuptools
$ pip3 install --upgrade ipython dnspython aiohttp scapy pyyaml NetfilterQueue ryu python-iptables pyroute2 --user
```

## How to run CES firewall

The CES code is executed by passing a set of network-related parameters to the program (as arguments). Whereas, the CETP-related parameters are read from a configuration file, specified against 'cetp-config' parameter in the startup script. In addition, the host-related and network-related communication policies can be loaded from a Security Policy Management (SPM) system. 

In summary, the CES boot-up script appears as below (for a 'gwa' node in our test setup):

```
Run as:
./rgw.py  --name gwa.demo                                                                    \
          --dns-soa                      gwa.demo. cname-gwa.demo.                           \
                                         0.168.192.in-addr.arpa. 1.64.100.in-addr.arpa.      \
          --dns-cname-soa                cname-gwa.demo.                                     \
          --dns-server-local             127.0.0.1 53                                        \
          --dns-server-lan               192.168.0.1 53                                      \
          --dns-server-wan               100.64.1.130 53                                     \
          --dns-resolver                 127.0.0.1 54                                        \
          --ddns-server                  127.0.0.2 53                                        \
          --dns-timeout                  0.010 0.100 0.200                                   \
          --pool-serviceip               100.64.1.130/32                                     \
          --pool-cpoolip                 100.64.1.133/32 100.64.1.134/32 100.64.1.135/32     \
          --ipt-cpool-queue              1                                                   \
          --ipt-cpool-chain              CIRCULAR_POOL                                       \
          --ipt-host-chain               CUSTOMER_POLICY                                     \
          --ipt-host-unknown             CUSTOMER_POLICY_ACCEPT                              \
          --ipt-policy-order             PACKET_MARKING NAT mREJECT ADMIN_PREEMPTIVE         \
                                         GROUP_POLICY CUSTOMER_POLICY                        \
                                         ADMIN_POLICY ADMIN_POLICY_DHCP                      \
                                         ADMIN_POLICY_HTTP ADMIN_POLICY_DNS                  \
                                         GUEST_SERVICES                                      \
          --ips-hosts                    IPS_SUBSCRIBERS                                     \
          --ipt-markdnat                                                                     \
          --ipt-flush                                                                        \
          --repository-subscriber-folder ../config.d/gwa.demo.subscriber.d/                  \
          --repository-policy-folder     ../config.d/gwa.demo.policy.d/                      \
          --repository-api-url           http://127.0.0.1:8082/                              \
          --network-api-url              http://127.0.0.1:8081/                              \
          --synproxy                     172.31.255.14 12345                                 \
          --spm-services-boolean         False                                               \
          --spm-url-cetp-host            http://10.0.3.200/API/cetp_policy_node?             \
          --spm-url-cetp-network         http://10.0.3.200/API/ces_policy_node?              \
          --cetp-config                  ../config.d/gwa.demo.cetp.policy/config_gwa.yaml    \
          --cetp-policies                ../config.d/gwa.demo.cetp.policy/cetp_policies.json 	          
```


## Overview of test network, and access to Internet

There are two ways of running automated enviroment for CES/RealmGateway, either using the LXC container orchestration or via the bash script with Linux network namespaces. In both cases, the CES/RealmGateway uses the "router" node as default gateway, which also provides SYNPROXY protection to its stub network. Similarly, the "router" node is configured to send all default traffic to 100.64.0.254 IP address, which is installed on the host machine running the virtual environment.

If Internet connectivity is desired on the virtual environment, one can enable NATting (on hosting-VM) via MASQUERADE as follows:

```
iptables -t nat -I POSTROUTING -o interfaceWithInternetAccess -j MASQUERADE
```

## What are all these folders?

This is the current view of the root folder

```
.
├── config.d
├── docs
├── iptables_devel
├── logs
├── orchestration
├── scripts
├── src
├── traffic_tests
├── AUTHORS
├── DOCUMENTATION.md
├── LICENSE
├── LICENSE.header
├── README.md
├── run_gwa.sh
└── TODO
```

A brief description of what to find:
- config.d: Policies related to CES/RGW and subcriber, we use now and the ones we used in the past.
- docs: Assorted documentation.
- iptables_devel: Userspace and kernel modules for MARKDNAT iptables module.
- logs: Storage for runtime logging.
- orchestration: Necessary scripts for quick deployment of test environments.
- scripts: Assorted script files that have been of some use at some point.
- src: The holy grail of our code.
- traffic_tests: Test related scripts from functional and performance perspective.
- AUTHORS
- DOCUMENTATION.md
- LICENSE
- LICENSE.header
- README.md
- run_gwa.sh: Quickest way to start the code of a netns enviroment
- TODO


## Test deployments
### LXC deployment
It was originally developed as a separate project under RealmGateway solution, for quick orchestration and replication of environments. Check the documentation inside the ```orchestration\lxc``` folder to quickly spawn the pre-configured test environment ```dev_environment```.

### Network namespaces deployment
This is devised as the quickest way to virtualize hosts with a minimal overhead. It mainly provides isolation to the network stack. Local modifications to the file system are allowed, but discouraged. Check the documentation inside the ```orchestration\netns``` folder to quickly spawn the pre-configured test environment.

## Policy-related details
The current repository ships with a set of policies and subscriber information for basic testing.

### Communication Policy information

### Data-plane policy details -> (primarily related to RGW)

For realm gateway operations:
When plan on making a new deployment, there are a few things to account (in network node running CES/RGW):

* circularpool.policy: Set a sensible maximum level according the size of the Circular Pool.
* ipset.policy: These are currently processed directly by iproute2, iptables, and ipset modules. Remember to populate the sets *IPS_CIRCULAR_POOL*, *IPS_SPOOFED_NET_xyz*, and *IPS_FILTER_xyz*.
Setting incorrect values on these fields may make debugging quite difficult as you might need to trace packets in iptables.
* iptables.policy: This is one of the most critical files that needs editing. Please pay attention to the following:

    NAT.rules: In mangle.CIRCULAR_POOL chain the targets NFQUEUE queue-num need to match the argument ```--ipt-cpool-queue``` passed to the python program.

    NAT.rules: In nat.POSTROUTING chain we use 2 rules for SNAT target that match on a different packet mark.
The most crucial is the one indicated as ```SNAT to available pool``` and it should include the available addresses in the Circular Pool for better efficiency of outgoing connections.

    ADMIN_POLICY_DNS.rules: In filter.POLICY_DNS_WAN_DOMAIN_LIMIT chain we have 2 rules for filtering incoming FQDNs that do not belong to the defined SOA zones.
This helps protect the built-in DNS server of the python program. Replace the zone defined, e.g. '|03|gwa|04|demo|00|' with the one of your choice, adhering to the DNS name encoding.

    GUEST_SERVICES.rules: In nat.GUEST_SERVICES we use redirection rules with DNAT to the private IP address of the node of the LAN interface. This is used for enabling the Captive Portal functinoality.
Modify this if your deployment uses different private networks.

    Don't forget to look for the token ```hashlimit``` that sets the limitations in different rules. You may want to modify these values based on the nature of your deployment.


### Creating a large number of subscribers on the go

We can quickly create a large number of subscriber based on a pre-defined template as follows:
1. Create a template file e.g. ```template.gwa.cesproto.re2ee.org.yaml```:

```
REPLACE_UENAME3.gwa.cesproto.re2ee.org.:
    ID:
        FQDN:   ['REPLACE_UENAME3.gwa.cesproto.re2ee.org.']
        IPV4:   ['192.168.145.REPLACE_SEQ']
        MSISDN: ['358145000REPLACE_SEQ3']
    GROUP:
        - IPS_GROUP_PREPAID3
    CIRCULARPOOL:
        - {max: 3 }
    SFQDN:
        - {fqdn:          'REPLACE_UENAME3.gwa.cesproto.re2ee.org.',  proxy_required: false, carriergrade: false                             }
        - {fqdn:      'www.REPLACE_UENAME3.gwa.cesproto.re2ee.org.',  proxy_required: true , carriergrade: false                             }
        - {fqdn:     'icmp.REPLACE_UENAME3.gwa.cesproto.re2ee.org.',  proxy_required: false, carriergrade: false, protocol: 1,    port: 0    }
        - {fqdn:      'tcp.REPLACE_UENAME3.gwa.cesproto.re2ee.org.',  proxy_required: false, carriergrade: false, protocol: 6,    port: 0    }
        - {fqdn:      'udp.REPLACE_UENAME3.gwa.cesproto.re2ee.org.',  proxy_required: false, carriergrade: false, protocol: 17,   port: 0    }
        - {fqdn:     'sctp.REPLACE_UENAME3.gwa.cesproto.re2ee.org.',  proxy_required: false, carriergrade: false, protocol: 132,  port: 0    }
        - {fqdn:      'ssh.REPLACE_UENAME3.gwa.cesproto.re2ee.org.',  proxy_required: false, carriergrade: false, protocol: 6,    port: 22   }
    FIREWALL:
        FIREWALL_ADMIN:
            - {'priority': 0,   'direction': 'EGRESS',  'protocol': '17', 'udp':{'dport': '53'}, 'target': 'REJECT', 'hashlimit': {'hashlimit-above':'5/sec', 'hashlimit-burst':'50', 'hashlimit-name':'DnsLanHosts', 'hashlimit-mode':'srcip', 'hashlimit-htable-expire':'1001'}, 'comment':{'comment':'Host DNS limit'}}
        FIREWALL_USER:
            - {'priority': 100, 'direction': 'EGRESS',  'target': 'ACCEPT', 'comment':{'comment':'Allow outgoing'}}
            - {'priority': 100, 'direction': 'INGRESS', 'target': 'ACCEPT', 'comment':{'comment':'Allow incoming'}}
```
2. Then, in a bash console we can create 254 users labeled from ue001 to ue254 as follows:

```
for i in $(seq 1 254); do
    i3=$(printf %03d $i)
    cp template.gwa.cesproto.re2ee.org.yaml ue$i3.gwa.cesproto.re2ee.org.yaml
	sed -i "s/REPLACE_UENAME3/ue$i3/g" ue$i3.gwa.cesproto.re2ee.org.yaml
	sed -i "s/192.168.145.REPLACE_SEQ/192.168.145.$i/g" ue$i3.gwa.cesproto.re2ee.org.yaml
	sed -i "s/358145000REPLACE_SEQ3/358145000$i3/g" ue$i3.gwa.cesproto.re2ee.org.yaml
done
```

## Considerations related to development or performance testing
### Rate limiting policies
Disable iptables rules that may rate limit packet per second (hashlimit), specially when testing (in development context).

### Network-related considerations
- Use tc/netem for simulating network delays on the interfaces of a Linux bridge
```
tc qdisc add    dev eth0 root netem delay 1000ms
tc qdisc change dev eth0 root netem delay 1000ms 50ms
tc qdisc del    dev eth0 root
```

- Increase the qlen size of your virtual adaptors. We have witnessed how veth pairs with qlen=1000 have resulted in packet loss when testing >2000 new TCP connections per second. Experimentally we have used the value qlen=25000.
```
ip link set dev eth0 qlen 25000
```

### Miscellaneous
- Configure TCP SYNPROXY in default mode for all the required IP addresses and disable synchronization of Realm Gateway connections (add & delete)
- Reduce console logging (WARNING level) and deactivate other file loggers.

### Performance testing
Use well-defined (S)FQDN to test specifically UDP and TCP connections, as they may be subjected to different network delays due to the presence of an in-network TCP SYNPROXY.

- Use the developed client to specifically control the IP addresses for DNS resolution and Data transfers:
- Using several IP sources also enables more socket binding options, which is necessary for high test loads.


## Other useful information

### Create python virtual environment

If you don't want to populate your system with extra libraries and modules, you can can create a python virtual environment using the following guide:  http://askubuntu.com/questions/244641/how-to-set-up-and-use-a-virtual-python-environment-in-ubuntu

Remember that the virtual environment shortcuts are not available when doing ```sudo``` per se, but you can achieve admin rights for your python interpreter with the following:

```
$ sudo /path/to/.virtualenvs/your_virtual_environment/bin/python
```


## Caveats and work arounds (mainly related to RGW in data-plane).
### Increase the number of file descriptors

This is the workaround for the "too many files open" problem:

- Add to /etc/sysctl.conf
```
# Custom extend number of files
fs.file-max=2097152
fs.inotify.max_queued_events=1048576
fs.inotify.max_user_instances=1048576
fs.inotify.max_user_watches=1048576
```

- Reload sysctl configuration
```
sysctl -p
```

- Add to /etc/security/limits.conf
```
# Added on 17/01/2017
*         hard    nofile      500000
*         soft    nofile      500000
root      hard    nofile      500000
root      soft    nofile      500000
```

- Check that /etc/ssh/sshd_config contains:
```
UsePAM=yes
```

- Check that /etc/pam.d/sshd contains
```
session    required   pam_limits.so
```

- Restart SSH service and reconnect


### Configure the system for high traffic volume

- Add to /etc/sysctl.conf

```
# Reduce TIME_WAIT socket connections
net.ipv4.tcp_fin_timeout=1

# Increase virtual memory areas
vm.max_map_count=262144

# Increase system IP port limits
net.ipv4.ip_local_port_range=1024 65535


# Increase conntrack size 1:16 bucket ratio for 4M connections

Increase bucket size: Verify input parameter with "modinfo nf_conntrack" / (expect_hashsize or hashsize)
net.netfilter.nf_conntrack_buckets=262144
### In recent kernels it might not be possible to modify this value on the fly, alternatively try one of the following:
### Option 1: echo "options nf_conntrack expect_hashsize=262144" > /etc/modprobe.d/nf_conntrack.conf
### Option 2: /sbin/modprobe nf_conntrack expect_hashsize=262144

## Increase max number of connections
net.netfilter.nf_conntrack_max=4194304

### It is a good idea to reboot the system to ensure the kernel module is loaded with the appropriate configuration and reapplying the settings with "sysctl -p"
### Verify the values are loaded correctly!
```

- Reload sysctl configuration
```
sysctl -p
```

