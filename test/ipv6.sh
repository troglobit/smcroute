#!/bin/sh
# Verifies IPv6 (S,G) rules, no forwarding test due to limitations
# setting IPv6 addreess in Docker container.
set -x

echo "Creating world ..."
for iface in a1 a2; do
    ip link add $iface type dummy
    ip link set $iface up
    ip link set $iface multicast on
done

# fdd1:9ac8:e35b:4e2d::/64
# fdd1:9ac8:e35b:4e2d:xxxx:xxxx:xxxx:xxxx
ip addr add fdd1:9ac8:e35b:4e2d::1/64 dev a1
ip addr add fdd1:9ac8:e35b:4e2d::2/64 dev a2

echo "Creating config ..."
cat <<EOF > ipv6.conf
# ipv6 (*,G) multicast routing
phyint a1 enable
phyint a2 enable
mroute from a1 source fc00::1 group ff01:0:0:0:0:0:0:114 to a2
mroute from a1 group ff2e::42 to a2
EOF
cat ipv6.conf

echo "Starting smcrouted ..."
../src/smcrouted -f ipv6.conf -n -N -P /tmp/smcrouted.pid &
sleep 2

ip -6 mroute
cat /proc/net/ip6_mr_vif /proc/net/ip6_mr_cache
ip -6 mroute > ipv6.result
killall smcrouted
sleep 1
ip link del a1
ip link del a2

lines=$(grep -c 'fc00::1,ff01::114' ipv6.result)
echo "Installed routes group ff01::114 => $lines"

[ "$lines" = "1" ] && exit 0
exit 1

################################ FUTURE ################################
echo "Starting collector ..."
tshark -c 5 -lni a2 -w ipv6.pcap 'dst ff01::114 or dst ff2e::42' &
sleep 1

echo "Starting emitter ..."
ping6 -c 3 -W 1 -I a1 -t 2 [ff01::114]
ping6 -c 3 -W 1 -I a1 -t 2 [ff2e::42]

# Show active routes (and counters)
cat /proc/net/ip_mr_cache
ip mroute

echo "Cleaning up ..."
killall smcrouted
sleep 1
ip link del a1
ip link del a2

echo "Analyzing ..."
lines1=$(tshark -r ipv6.pcap | grep ff01::114 | tee    ipv6.result | wc -l)
lines2=$(tshark -r ipv6.pcap | grep ff2e::42  | tee -a ipv6.result | wc -l)
cat ipv6.result
echo "Routed frames for group ff01::114 => $lines1"
echo "Routed frames for group ff2e::42  => $lines2"

# one frame lost due to initial (*,G) -> (S,G) route setup
# no frames lost in pure (S,G) route
[ "$lines1" = "2" -a "$lines2" = "3" ] && exit 0
exit 1
