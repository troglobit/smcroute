#!/bin/sh
# Verify IPv4 (*,G) routing on top of VLAN interfaces
set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

echo "Creating world ..."
topo dummy vlan 100 110
ip addr add 10.100.0.1/24 dev a1.100
ip addr add 10.110.0.1/24 dev a1.110
ip addr add 20.100.0.1/24 dev a2.100
ip addr add 20.110.0.1/24 dev a2.110

echo "Creating config ..."
cat <<EOF > vlan.conf
# vlan (*,G) multicast routing
phyint a1.110 enable
phyint a2.110 enable
mroute from a1.110 group 225.1.2.3 to a2.110
EOF
cat vlan.conf

echo "Starting smcrouted ..."
../src/smcrouted -f vlan.conf -n -N -P /tmp/smcrouted.pid &
sleep 1

echo "Starting collector ..."
tshark -c 2 -lni a2.110 -w vlan.pcap icmp and dst 225.1.2.3 &
sleep 1

echo "Starting emitter ..."
ping -c 3 -W 1 -I a1.110 -t 2 225.1.2.3

# Show active routes (and counters)
cat /proc/net/ip_mr_cache
ip mroute

echo "Cleaning up ..."
killall smcrouted
sleep 1
ip link del a1
ip link del a2

echo "Analyzing ..."
lines=$(tshark -r vlan.pcap | grep 225.1.2.3 | tee vlan.result | wc -l)
cat vlan.result
echo "Routed frames for group 225.1.2.3 => $lines"

# one frame lost due to initial (*,G) -> (S,G) setup
[ "$lines" = "2" ] && exit 0
exit 1
