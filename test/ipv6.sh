#!/bin/sh
# Verifies IPv6 (S,G) rules
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Creating world ..."
topo bridge

# IP world ...
ip addr add 2001:1::1/64 dev vlan1
ip addr add 2001:2::1/64 dev vlan2

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
# ipv6 (*,G) multicast routing
phyint vlan1 enable
phyint vlan2 enable
mroute from vlan1 source fc00::1 group ff04:0:0:0:0:0:0:114 to vlan2
mroute from vlan1                group ff2e::42             to vlan2
EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug &
sleep 1

print "Starting collector ..."
tshark -c 5 -lni a2 -w "/tmp/$NM/pcap" 'dst ff04::114 or dst ff2e::42' 2>/dev/null &
sleep 1

print "Starting emitter ..."
nemesis udp -6 -c 3 -d a1 -T 3 -S fc00::1                -D ff04::114 -M 33:33:00:00:01:14
nemesis udp -6 -c 3 -d a1 -T 3 -S fdd1:9ac8:e35b:4e2d::1 -D ff2e::42  -M 33:33:00:00:00:42

# Show active routes (and counters)
cat /proc/net/ip6_mr_cache
ip -6 mroute

print "Analyzing ..."
lines1=$(tshark -r "/tmp/$NM/pcap" 2>/dev/null | grep ff04::114 | tee    "/tmp/$NM/result" | wc -l)
lines2=$(tshark -r "/tmp/$NM/pcap" 2>/dev/null | grep ff2e::42  | tee -a "/tmp/$NM/result" | wc -l)
cat "/tmp/$NM/result"
echo " => $lines1 for group ff04::114, expected => 3"
echo " => $lines2 for group ff2e::42,  expected => 2"

print "Cleaning up ..."
topo teardown

# one frame lost due to initial (*,G) -> (S,G) route setup
# no frames lost in pure (S,G) route
[ "$lines1" = "3" -a "$lines2" = "2" ] && exit 0
exit 1
