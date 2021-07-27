#!/bin/sh
# Verify IPv4 (*,G) routing on top of VLAN interfaces
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Creating world ..."
topo basic vlan 100 110
ip addr add 10.100.0.1/24 dev a1.100
ip addr add 10.110.0.1/24 dev a1.110
ip addr add 20.100.0.1/24 dev a2.100
ip addr add 20.110.0.1/24 dev a2.110
ip -br a

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
# vlan (*,G) multicast routing
phyint a1.110 enable
phyint a2.110 enable
mroute from a1.110 group 225.1.2.3 to a2.110
EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug &
sleep 1

print "Starting collector ..."
tshark -c 2 -lni a2.110 -w "/tmp/$NM/pcap" icmp and dst 225.1.2.3 2>/dev/null &
sleep 1

print "Starting emitter ..."
ping -c 3 -W 1 -I a1.110 -t 2 225.1.2.3 2>/dev/null
show_mroute

print "Analyzing ..."
lines=$(tshark -r "/tmp/$NM/pcap" 2>/dev/null | grep 225.1.2.3 | tee "/tmp/$NM/result" | wc -l)
cat "/tmp/$NM/result"
echo " => $lines for 225.1.2.3, expected => 2"

print "Cleaning up ..."
topo teardown

# one frame lost due to initial (*,G) -> (S,G) setup
[ "$lines" = "2" ] && exit 0
exit 1
