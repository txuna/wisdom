
#!/bin/bash

# 브릿지 생성 및 셋업
ip link add br0 type bridge
ip link set br0 up
ip link set br0 address DE:AD:BE:EF:00:01 # 나중에 세팅되나?
ip addr add 10.201.0.1/24 brd 10.201.0.255 dev br0
iptables --policy FORWARD ACCEPT

# container4 네트워크 네임스페이스 셋업
ip netns add container4
ip link add brid4 type veth peer name veth4
ip link set veth4 netns container4
ip netns exec container4 ip a add 10.201.0.4/24 dev veth4

ip netns exec container4 ip link set veth4 address DE:AD:BE:EF:00:04 

ip netns exec container4 ip link set dev lo up
ip netns exec container4 ip link set dev veth4 up
ip link set brid4 master br0
ip link set dev brid4 up
ip netns exec container4 ip route add default via 10.201.0.1

# container5 네트워크 네임스페이스 셋업
ip netns add container5
ip link add brid5 type veth peer name veth5
ip link set veth5 netns container5
ip netns exec container5 ip a add 10.201.0.5/24 dev veth5

ip netns exec container5 ip link set veth5 address DE:AD:BE:EF:00:05

ip netns exec container5 ip link set dev lo up
ip netns exec container5 ip link set dev veth5 up
ip link set brid5 master br0
ip link set dev brid5 up
ip netns exec container5 ip route add default via 10.201.0.1

# container6 네트워크 네임스페이스 셋업
ip netns add container6
ip link add brid6 type veth peer name veth6
ip link set veth6 netns container6
ip netns exec container6 ip a add 10.201.0.6/24 dev veth6

ip netns exec container6 ip link set veth6 address DE:AD:BE:EF:00:06

ip netns exec container6 ip link set dev lo up
ip netns exec container6 ip link set dev veth6 up
ip link set brid6 master br0
ip link set dev brid6 up
ip netns exec container6 ip route add default via 10.201.0.1

# client1 네트워크 네임스페이스 셋업
ip netns add client1
ip link add brid7 type veth peer name veth7
ip link set veth7 netns client1
ip netns exec client1 ip a add 10.201.0.10/24 dev veth7

ip netns exec client1 ip link set veth7 address DE:AD:BE:EF:00:0A

ip netns exec client1 ip link set dev lo up
ip netns exec client1 ip link set dev veth7 up
ip link set brid7 master br0
ip link set dev brid7 up
ip netns exec client1 ip route add default via 10.201.0.1

# NAT 및 DNS 셋업
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.201.0.0/24 -j MASQUERADE

mkdir -p /etc/netns/container4/
echo 'nameserver 8.8.8.8' > /etc/netns/container4/resolv.conf

mkdir -p /etc/netns/container5/
echo 'nameserver 8.8.8.8' > /etc/netns/container5/resolv.conf

mkdir -p /etc/netns/container6/
echo 'nameserver 8.8.8.8' > /etc/netns/container6/resolv.conf

mkdir -p /etc/netns/client1/
echo 'nameserver 8.8.8.8' > /etc/netns/client1/resolv.conf