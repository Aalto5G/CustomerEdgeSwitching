## Create OVS bridges
ovs-vsctl --if-exists del-br br-ces0
ovs-vsctl             add-br br-ces0
ovs-vsctl set bridge br-ces0 other-config:datapath-id=0x0000000000000001
ovs-vsctl set-controller br-ces0 tcp:127.0.0.1:6653

## Add ports
ovs-vsctl add-port br-ces0 tun0         -- set interface tun0         ofport_request=100 -- set interface tun0         type=internal
ovs-vsctl add-port br-ces0 gre0-ces0    -- set interface gre0-ces0    ofport_request=101 -- set interface gre0-ces0    type=gre       options:key=flow options:remote_ip=flow options:local_ip=flow options:tos=inherit
ovs-vsctl add-port br-ces0 vxlan0-ces0  -- set interface vxlan0-ces0  ofport_request=102 -- set interface vxlan0-ces0  type=vxlan     options:key=flow options:remote_ip=flow options:local_ip=flow options:tos=inherit
ovs-vsctl add-port br-ces0 geneve0-ces0 -- set interface geneve0-ces0 ofport_request=103 -- set interface geneve0-ces0 type=geneve    options:key=flow options:remote_ip=flow options:local_ip=flow options:tos=inherit

## Configure tun0 port
ip link set dev tun0 arp off
ip link set dev tun0 address 00:00:00:12:34:56
ip link set dev tun0 mtu 1400
ip link set dev tun0 up
ip route add 172.16.0.0/16 dev tun0

