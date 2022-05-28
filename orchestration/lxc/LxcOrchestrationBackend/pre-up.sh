#!/bin/bash

echo "Enabling necesary kernel modules for CES/RealGateway"
for MODULE in sctp nf_conntrack_proto_sctp xt_sctp xt_MARKDNAT netmap openvswitch
do
	echo "> modprobe $MODULE"
	modprobe $MODULE
done
echo ""

echo "Remove lxc-start profile from Apparmor"
apparmor_parser --remove /etc/apparmor.d/usr.bin.lxc-start
ln -s /etc/apparmor.d/usr.bin.lxc-start /etc/apparmor.d/disabled/

echo ""
for NIC in br-wan0 lxcmgt0
do
	echo "Setting up $NIC"
	ip link del dev $NIC 2> /dev/null
	ip link add dev $NIC type bridge forward_delay 0
	ip link set dev $NIC up
done

ip address add 172.31.255.1/24 dev lxcmgt0
# Configure br-wan0 with IP address for accessing test public network
ip address flush dev br-wan0
ip address add 100.64.0.254/24 dev br-wan0
## Set default gateway via br-wan0 in host to control NATting
ip route add 100.64.0.0/16 via 100.64.0.1