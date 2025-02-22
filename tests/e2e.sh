#!/usr/bin/env bash
set -eux

ip -all netns delete

ip netns add server1
ip netns add server2
ip netns add router
ip netns add device1
ip netns add device2

ip link add veth_r_s1 netns router type veth peer veth_s1_r netns server1
ip link add veth_r_s2 netns router type veth peer veth_s2_r netns server2

ip link add br-lan netns router type bridge
ip link add veth_r_d1 netns router type veth peer veth_d1_r netns device1
ip link add veth_r_d2 netns router type veth peer veth_d2_r netns device2

# server: setup network
ip netns exec server1 ip addr add 10.0.1.1/24 dev veth_s1_r
ip netns exec server1 ip addr add 10.0.1.2/24 dev veth_s1_r
ip netns exec server1 ip link set veth_s1_r up
# server2
ip netns exec server2 ip addr add 10.0.2.1/24 dev veth_s2_r
ip netns exec server2 ip addr add 10.0.2.2/24 dev veth_s2_r
ip netns exec server2 ip link set veth_s2_r up

# router: setup external networks
ip netns exec router ip addr add 10.0.1.100/24 dev veth_r_s1
ip netns exec router ip link set veth_r_s1 up
ip netns exec router ip addr add 10.0.2.100/24 dev veth_r_s2
ip netns exec router ip link set veth_r_s2 up

# router: setup LAN
ip netns exec router ip link set veth_r_d1 master br-lan
ip netns exec router ip link set veth_r_d2 master br-lan
ip netns exec router ip addr add 192.168.1.1/24 dev br-lan
ip netns exec router ip link set br-lan up
ip netns exec router ip link set veth_r_d1 up
ip netns exec router ip link set veth_r_d2 up

# router: enable forwarding
ip netns exec router sysctl net.ipv4.ip_forward=1

# device: setup network
ip netns exec device1 ip addr add 192.168.1.100/24 dev veth_d1_r
ip netns exec device1 ip link set veth_d1_r up
ip netns exec device1 ip route add default via 192.168.1.1 dev veth_d1_r
# device2
ip netns exec device2 ip addr add 192.168.1.200/24 dev veth_d2_r
ip netns exec device2 ip link set veth_d2_r up
ip netns exec device2 ip route add default via 192.168.1.1 dev veth_d2_r

# router: show networking info
ip netns exec router ip link show
ip netns exec router ip addr show
ip netns exec router ip route show

# start our program
ip netns exec router ./target/debug/einat -i veth_r_s1 --bpf-log 5 >/dev/null 2>&1 &
ip netns exec router ./target/debug/einat -i veth_r_s2 >/dev/null 2>&1 &
sleep 1

#
# test network connectivity
#
# router to servers
ip netns exec router ping -c1 10.0.1.1
ip netns exec router ping -c1 10.0.2.1

# devices to router
ip netns exec device1 ping -c1 192.168.1.1
ip netns exec device2 ping -c1 192.168.1.1

# devices to servers, would be SNAT by router
ip netns exec device1 ping -c1 10.0.1.1
ip netns exec device1 ping -c1 10.0.2.1
# device2
ip netns exec device2 ping -c1 10.0.1.1
ip netns exec device2 ping -c1 10.0.2.1

# Create unreplied conntracks in router.
# Make sure if we add one of these beforehand, the created conntrack would not block connection from server's 3479 to device's 29999.
ip netns exec server1 nc -uq0 -s 10.0.1.1 -p 3479 10.0.1.100 29999 <<<"test"
ip netns exec server1 nc -uq0 -s 10.0.1.2 -p 3479 10.0.1.100 29999 <<<"test"
ip netns exec router nc -uq0 -s 10.0.1.100 -p 29999 10.0.1.1 3479 <<<"test"
ip netns exec router nc -uq0 -s 10.0.1.100 -p 29999 10.0.1.2 3479 <<<"test"
ip netns exec device2 nc -uq0 -p 29999 10.0.1.1 3479 <<<"test"
ip netns exec device1 nc -uq0 -p 29999 10.0.1.1 3479 <<<"test"
ip netns exec device2 nc -uq0 -p 29999 10.0.1.2 3479 <<<"test"

# start stunserver in servers
ip netns exec server1 stunserver --mode full --primaryinterface 10.0.1.1 --altinterface 10.0.1.2 &
ip netns exec server2 stunserver --mode full --primaryinterface 10.0.2.1 --altinterface 10.0.2.2 &
sleep 1

# STUN NAT behavior test with our program
ip netns exec device1 stunclient --mode full --localport 29999 10.0.1.1

ip netns exec device1 stunclient --mode full --localport 29999 10.0.1.1 | grep -z "Endpoint Independent Mapping.*Endpoint Independent Filtering"
ip netns exec device2 stunclient --mode full --localport 29999 10.0.1.1 | grep -z "Endpoint Independent Mapping.*Endpoint Independent Filtering"
ip netns exec device1 stunclient --mode full --localport 29999 10.0.2.1 | grep -z "Endpoint Independent Mapping.*Endpoint Independent Filtering"
ip netns exec device2 stunclient --mode full --localport 29999 10.0.2.1 | grep -z "Endpoint Independent Mapping.*Endpoint Independent Filtering"

ip netns delete device2
ip netns delete device1
ip netns delete router
ip netns delete server2
ip netns delete server1

kill -KILL $(jobs -p)
