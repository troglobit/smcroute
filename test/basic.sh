#!/bin/sh
# Verifies IPv4 (S,G) and (*,G) rules by injecting frames on one
# interface and verifying reception on another.
set -x

echo "Creating world ..."
for iface in a1 a2; do
    ip link add $iface type dummy
    ip link set $iface up
    ip link set $iface multicast on
done
ip addr add 10.0.0.1/24 dev a1
ip addr add 20.0.0.1/24 dev a2

echo "Creating config ..."
cat <<EOF > basic.conf
# basic (*,G) multicast routing
phyint a1 enable
phyint a2 enable
mroute from a1 source 10.0.0.1 group 225.3.2.1 to a2
mroute from a1 group 225.1.2.3 to a2
EOF
cat basic.conf

echo "Starting smcrouted ..."
../src/smcrouted -f basic.conf -n -N -P /tmp/smcrouted.pid &
sleep 1

echo "Starting collector ..."
tcpdump -c 5 -lni a2 -w basic.pcap 'dst 225.3.2.1 or dst 225.1.2.3' &
sleep 1

echo "Starting emitter ..."
ping -c 3 -W 1 -I a1 -t 2 225.3.2.1
ping -c 3 -W 1 -I a1 -t 2 225.1.2.3

# Show active routes (and counters)
cat /proc/net/ip_mr_cache
ip mroute

echo "Cleaning up ..."
killall smcrouted
sleep 1
ip link del a1
ip link del a2

echo "Analyzing ..."
lines1=$(tcpdump -r basic.pcap | grep 225.1.2.3 | tee basic.result    | wc -l)
lines2=$(tcpdump -r basic.pcap | grep 225.3.2.1 | tee -a basic.result | wc -l)
cat basic.result
echo "Routed frames for group 225.1.2.3 => $lines1"
echo "Routed frames for group 225.3.2.1 => $lines2"

# one frame lost due to initial (*,G) -> (S,G) route setup
# no frames lost in pure (S,G) route
[ "$lines1" = "2" -a "$lines2" = "3" ] && exit 0
exit 1
