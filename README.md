# Customer Edge Switching

## Introduction

This version of Customer Edge Switching v2.0 has been developed under
Ubuntu 16.04 and python3 'asyncio' framework for asynchronous calls.

This particular branch adds the CES/CETP based cooperative firewall functionality to previously developed RGW functionality.
The project code has been developed and tested on LXC containers, that simulate different network scenarios.

This repository contains a submodule. Clone with ```git clone ssh://git@gitlab.cloud.mobilesdn.org:60022/CES/customer_edge_switching_v2.git --recursive```

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
$ pip3 install --upgrade ipython dnspython aiohttp scapy-python3 pyyaml NetfilterQueue ryu python-iptables pyroute2 --user
```

## Caveats and pitfalls

There are two ways of running automated enviroment for CES/RealmGateway, either using the LXC container orchestration or via the bash script with Linux network namespaces.
In both cases, the CES/RealmGateway uses the "router" node as default gateway, which also provides SYNPROXY protection to its stub network. Similarly, the "router" node
is configured to send all default traffic to 100.64.0.254 IP address, which is installed on the host machine running the virtual environment.

If Internet connectivity is desired on the virtual environment, one can enable NATting (on hosting-VM) via MASQUERADE as follows:

```
iptables -t nat -I POSTROUTING -o interfaceWithInternetAccess -j MASQUERADE
```

## How to run a Realm Gateway

The configuration file has been discontinued. Now all parameters are passed as arguments to the program, i.e.:

```
Run as:
./rgw.py  --name gwa.demo                                                    \
          --dns-soa gwa.demo. 0.168.192.in-addr.arpa. 1.64.100.in-addr.arpa. \
          --dns-server-local 127.0.0.1 53                                    \
          --dns-server-lan   192.168.0.1 53                                  \
          --dns-server-wan   100.64.1.130 53                                 \
          --dns-resolver     127.0.0.1 54                                    \
          --ddns-server      127.0.0.2 53                                    \
          --dns-timeout      0.010 0.100 0.200                               \
          --pool-serviceip   100.64.1.130/32                                 \
          --pool-cpoolip     100.64.1.133/32 100.64.1.134/32 100.64.1.135/32 \
          --ipt-cpool-queue  1                                               \
          --ipt-cpool-chain  CIRCULAR_POOL                                   \
          --ipt-host-chain   CUSTOMER_POLICY                                 \
          --ipt-host-unknown CUSTOMER_POLICY_ACCEPT                          \
          --ipt-policy-order PACKET_MARKING NAT mREJECT ADMIN_PREEMPTIVE     \
                             GROUP_POLICY CUSTOMER_POLICY                    \
                             ADMIN_POLICY ADMIN_POLICY_DHCP                  \
                             ADMIN_POLICY_HTTP ADMIN_POLICY_DNS              \
                             GUEST_SERVICES                                  \
          --ips-hosts        IPS_SUBSCRIBERS                                 \
          --ipt-markdnat                                                     \
          --ipt-flush                                                        \
          --repository-subscriber-folder gwa.subscriber.d/                   \
          --repository-policy-folder     gwa.policy.d/
```


## Configuring a deployment

The current repository ships with a set of policies and subscriber information for basic testing.
However, if we plan on making a new deployment there are a few things we need to take into account:

* circularpool.policy: Set a sensible maximum level according the size of the Circular Pool.

* ipset.policy: These are currently processed directly by iproute2, iptables, and ipset. Remember to populate the sets *IPS_CIRCULAR_POOL*, *IPS_SPOOFED_NET_xyz*, and *IPS_FILTER_xyz*.
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


## Build & install the iptables modules for Realm Gateway (optional)

The Realm Gateway uses a tailor made module for an iptables extension target, MARKDNAT, which requires both a user space and a kernel module.
This extension can only be used in table nat and PREROUTING chain. The target implements the normal actions
of MARK, regarding the skb->mark mangling and DNAT --to-destination A.B.C.D with the resulting mark.

This extension allows performing the DNAT operation based on the packet mark.
The packet mark can be controlled as well from a user space application via NFQUEUE target.

Installing the kernel module

```
$ cd ./iptables_devel
$ make
# make install_MARKDNAT
```

Installing the user space module

```
# cp ./iptables_devel/userspace/libxt_MARKDNAT.so /lib/xtables/
$ iptables -j MARKDNAT --help
```


## Create subscribers in batch

We can quickly create a large number of subscriber based on a pre-defined template as follows:

Create a template file e.g. ```template.gwa.cesproto.re2ee.org.yaml```:

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


Then, in a bash console we will create users ue001 to ue254 as follows:

```
for i in $(seq 1 254); do
    i3=$(printf %03d $i)
    cp template.gwa.cesproto.re2ee.org.yaml ue$i3.gwa.cesproto.re2ee.org.yaml
	sed -i "s/REPLACE_UENAME3/ue$i3/g" ue$i3.gwa.cesproto.re2ee.org.yaml
	sed -i "s/192.168.145.REPLACE_SEQ/192.168.145.$i/g" ue$i3.gwa.cesproto.re2ee.org.yaml
	sed -i "s/358145000REPLACE_SEQ3/358145000$i3/g" ue$i3.gwa.cesproto.re2ee.org.yaml
done
```


## Other useful information

### Create python virtual environment

If you don't want to populute your system with extra libraries and modules, you can can create a python virtual environment using the following guide:

http://askubuntu.com/questions/244641/how-to-set-up-and-use-a-virtual-python-environment-in-ubuntu

Remember that the virtual environment shortcuts are not available when doing ```sudo``` per se, but you can achieve admin rights for your python interpreter with the following:

```
$ sudo /path/to/.virtualenvs/your_virtual_environment/bin/python
```

### Linux bridged & iptables (Not currently in use)

It is very common to deploy Linux bridges to trigger iptables packet processing to that traffic.
However, additional kernel modules need to be loaded.

```
# modprobe br_netfilter
# modprobe xt_physdev
```

In order to send traffic from the linux bridge to iptables modify your ```/etc/sysctl.conf``` to include the following:

```
net.bridge.bridge-nf-call-arptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-filter-pppoe-tagged=0
net.bridge.bridge-nf-filter-vlan-tagged=1
net.bridge.bridge-nf-pass-vlan-input-dev=1
```
>>>>>>> refs/heads/master
