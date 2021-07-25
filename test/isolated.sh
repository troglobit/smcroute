#!/bin/sh
# Verifies (*,G) routing between two emulated end devices.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Creating world ..."
topo isolated left right

# IP World
ip addr add 10.0.0.1/24 dev left
nsenter --net=left ip addr add 10.0.0.10/24 dev eth0

ip addr add 20.0.0.1/24 dev right
nsenter --net=right ip addr add 20.0.0.10/24 dev eth0

ip -br l
ip -br a

print "Creating config ..."
cat <<EOF > isolated.conf
# vlan (*,G) multicast routing
phyint left  enable
phyint right enable
mroute from left group 225.1.2.3 to right
EOF
cat isolated.conf

print "Starting smcrouted ..."
../src/smcrouted -f isolated.conf -n -N -P /tmp/isolated.pid -l debug &
sleep 1

print "Starting collector ..."
nsenter --net=right tshark -c 2 -lni eth0 -w isolated.pcap dst 225.1.2.3  2>/dev/null &
sleep 1

print "Starting emitter ..."
nsenter --net=left ping -c 3 -W 1 -I eth0 -t 3 225.1.2.3 >/dev/null
show_mroute

print "Cleaning up ..."
topo teardown

print "Analyzing ..."
lines=$(tshark -r isolated.pcap 2>/dev/null | grep 225.1.2.3 | tee isolated.result | wc -l)
cat isolated.result
echo " => $lines expected 2"

# one frame lost due to initial (*,G) -> (S,G) setup
[ "$lines" = "2" ] && exit 0
exit 1
