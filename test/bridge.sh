#!/bin/sh
# Verifies (*,G) routing between VLANs on top of a VLAN filtering bridge
# with bridge ports as VETH interfaces.  UDP injection with nemesis, see
# test/README.md as for why.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Creating world ..."
topo bridge
ip addr add 10.0.0.1/24 dev vlan1
ip addr add 20.0.0.1/24 dev vlan2
ip -br a

print "Creating config ..."
cat <<EOF > bridge.conf
# vlan (*,G) multicast routing
phyint vlan1 enable
phyint vlan2 enable
mroute from vlan1 group 225.1.2.3 to vlan2
EOF
cat bridge.conf

print "Starting smcrouted ..."
../src/smcrouted -f bridge.conf -n -N -P /tmp/bridge.pid &
sleep 1

print "Starting collector ..."
tshark -c 2 -lni a2 -w bridge.pcap dst 225.1.2.3 2>/dev/null &
sleep 1

print "Starting emitter ..."
nemesis udp -c 3 -S 10.0.0.10 -D 225.1.2.3 -T 3 -M 01:00:5e:01:02:03 -d a1
show_mroute

print "Cleaning up ..."
topo teardown

print "Analyzing ..."
lines=$(tshark -r bridge.pcap 2>/dev/null | grep 225.1.2.3 | tee bridge.result | wc -l)
cat bridge.result
echo " => $lines for 225.1.2.3, expected => 2"

# one frame lost due to initial (*,G) -> (S,G) setup
[ "$lines" = "2" ] && exit 0
exit 1
