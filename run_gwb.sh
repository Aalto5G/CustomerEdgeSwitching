#!/bin/bash

if [[ $UID != 0 ]]; then
    echo "Please run this script with sudo:"
    echo "sudo $0 $*"
    exit 1
fi

echo "Starting Realm Gateway as gwb.demo"
cd src
./rgw.py  --name gwb.demo                                                    \
          --dns-cname-soa    cname-gwb.demo.                                 \
          --dns-soa gwb.demo. 0.168.192.in-addr.arpa. 1.64.100.in-addr.arpa. \
          --dns-server-local 127.0.0.1 53                                    \
          --dns-server-lan   192.168.0.1 53                                  \
          --dns-server-wan   100.64.2.130 53                                 \
          --dns-resolver     100.64.0.1 53                                   \
          --ddns-server      127.0.0.2 53                                    \
          --dns-timeout      0.010 0.100 0.200                               \
          --dns-timeout-naptr  0.100 0.200 0.300                             \
          --pool-serviceip   100.64.2.130/32                                 \
          --pool-cpoolip     100.64.2.131/32 100.64.2.132/32 100.64.2.133/32 \
          --pool-cespoolip   172.16.2.100/26                                 \
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
          --network-api-url  http://127.0.0.1:8081/                          \
          --repository-subscriber-folder ../config.d/gwb.demo.subscriber.d/  \
          --repository-policy-folder     ../config.d/gwb.demo.policy.d/      \
          --cetp-config  		    ../config.d/gwb.demo.cetp.policy/config_gwb.yaml         \
          --spm-services-boolean    False                                                            \
          --cetp-host-policy-location      http://10.0.3.200/API/cetp_policy_node?                   \
          --cetp-network-policy-location   http://10.0.3.200/API/ces_policy_node?                    \
          --cetp-policies-host-file      ../config.d/gwb.demo.cetp.policy/host_cetp_policies.json    \
          --cetp-policies-network-file   ../config.d/gwb.demo.cetp.policy/network_cetp_policies.json \
          --repository-api-url  	http://10.0.3.200:8001                                       \
          --synproxy         		10.0.3.151 12345
