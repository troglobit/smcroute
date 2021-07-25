#!/bin/sh
# Verifies IPv6 (S,G) rules
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

echo "Creating world ..."
topo bridge

# IP world ...
ip addr add 2001:1::1/64 dev vlan1
ip addr add 2001:2::1/64 dev vlan2

echo "Creating config ..."
cat <<EOF > ipv6.conf
# ipv6 (*,G) multicast routing
phyint vlan1 enable
phyint vlan2 enable
mroute from vlan1 source fc00::1 group ff04:0:0:0:0:0:0:114 to vlan2
mroute from vlan1                group ff2e::42             to vlan2
EOF
cat ipv6.conf

echo "Starting smcrouted ..."
../src/smcrouted -f ipv6.conf -n -N -P /tmp/smcrouted.pid -l debug &
sleep 1

echo "Starting collector ..."
tshark -c 5 -lni a2 -w ipv6.pcap 'dst ff04::114 or dst ff2e::42' &
sleep 1

echo "Starting emitter ..."
nemesis udp -6 -c 3 -d a1 -T 3 -S fc00::1                -D ff04::114 -M 33:33:00:00:01:14
nemesis udp -6 -c 3 -d a1 -T 3 -S fdd1:9ac8:e35b:4e2d::1 -D ff2e::42  -M 33:33:00:00:00:42

# Show active routes (and counters)
cat /proc/net/ip6_mr_cache
ip -6 mroute

echo "Cleaning up ..."
killall smcrouted
sleep 1
ip link del br0
ip link del a1
ip link del a2

echo "Analyzing ..."
lines1=$(tshark -r ipv6.pcap | grep ff04::114 | tee    ipv6.result | wc -l)
lines2=$(tshark -r ipv6.pcap | grep ff2e::42  | tee -a ipv6.result | wc -l)
cat ipv6.result
echo "Routed frames for group ff04::114 => $lines1"
echo "Routed frames for group ff2e::42  => $lines2"

# one frame lost due to initial (*,G) -> (S,G) route setup
# no frames lost in pure (S,G) route
[ "$lines1" = "3" -a "$lines2" = "2" ] && exit 0
exit 1
