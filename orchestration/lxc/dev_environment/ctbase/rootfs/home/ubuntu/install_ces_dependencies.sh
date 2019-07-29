#!/bin/bash

# Steps required to install CES/RGW in a Linux Container

## Install CES/RGW dependencies
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y git build-essential python3-dev libnetfilter-queue-dev python3-pip
sudo apt-get install ipset libipset3 iptables ipset ebtables bridge-utils
sudo apt-get install ipsec-tools openvswitch-common openvswitch-ipsec openvswitch-switch python-openvswitch racoon

sudo pip3 install --upgrade pip setuptools
sudo pip3 install --upgrade dnspython aiohttp pyyaml NetfilterQueue python-iptables pyroute2 ipython scapy-python3 --user
sudo -H pip3 install --upgrade ryu
### Update all pip packages
#pip-review --auto -v
