#!/bin/sh
set -x

echo "Creating world ..."
ip link add br0 type bridge vlan_filtering 1 mcast_snooping 0
ip link add a1 type veth peer b1
ip link add a2 type veth peer b2
ip link set b1 master br0
ip link set b2 master br0

ip link set a1 up
ip link set b1 up
ip link set a2 up
ip link set b2 up
ip link set br0 up

ip link add link br0 vlan1 type vlan id 1
ip link add link br0 vlan2 type vlan id 2

ip link set vlan1 up
ip link set vlan2 up

# Move b2 to VLAN 2
bridge vlan add vid 2 dev b2 pvid untagged
bridge vlan del vid 1 dev b2

# Set br0 as tagged member of both VLANs
bridge vlan add vid 1 dev br0 self
bridge vlan add vid 2 dev br0 self

# IP World
ip addr add 10.0.0.1/24 dev vlan1
ip addr add 20.0.0.1/24 dev vlan2

ip netns add a1
ip link set a1 netns a1
ip netns exec a2 ip link set lo up
ip netns exec a1 ip link set a1 up
ip netns exec a1 ip addr add 10.0.0.10/24 dev a1

ip netns add a2
ip link set a2 netns a2
ip netns exec a2 ip link set lo up
ip netns exec a2 ip link set a2 up
ip netns exec a2 ip addr add 20.0.0.10/24 dev a2

echo "Creating config ..."
cat <<EOF > bridge.conf
# vlan (*,G) multicast routing
phyint vlan1 enable
phyint vlan2 enable
mroute from vlan1 group 225.1.2.3 to vlan2
EOF
cat bridge.conf

echo "Starting smcrouted ..."
../src/smcrouted -f bridge.conf -n -N -P /tmp/smcrouted.pid &

echo "Starting collector ..."
ip netns exec a2 tcpdump -c 2 -lni a2 -w bridge.pcap icmp and dst 225.1.2.3 &
sleep 1

echo "Starting emitter ..."
ip netns exec a1 ping -c 3 -W 1 -I a1 -t 2 225.1.2.3

echo "Cleaning up ..."
killall smcrouted
ip link del br0
ip netns exec a1 ip link set a1 netns 1
ip link del a1
ip netns exec a2 ip link set a2 netns 1
ip link del a2

echo "Analyzing ..."
lines=$(tcpdump -r bridge.pcap | grep 225.1.2.3 | tee bridge.result | wc -l)
cat bridge.result
echo "=> num routes frames $lines"

# one frame lost due to initial (*,G) -> (S,G) setup
[ "$lines" != "2" ] && exit 1
exit 0
