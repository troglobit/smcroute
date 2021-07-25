#!/bin/sh
# Verifies IPv4 (S,G) and (*,G) rules by injecting frames on one
# interface and verifying reception on another.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

echo "Creating world ..."
topo dummy
ip addr add 10.0.0.1/24 dev a1
ip addr add 20.0.0.1/24 dev a2
ip -br a

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
../src/smcrouted -f basic.conf -n -N -P /tmp/basic.pid -l debug &
sleep 1

echo "Starting collector ..."
tshark -Qc 5 -lni a2 -w basic.pcap 'dst 225.3.2.1 or dst 225.1.2.3' 2>/dev/null &
sleep 1

echo "Starting emitter ..."
ping -c 3 -W 1 -I a1 -t 2 225.3.2.1 >/dev/null
ping -c 3 -W 1 -I a1 -t 2 225.1.2.3 >/dev/null
show_mroute

echo "Cleaning up ..."
topo teardown

echo "Analyzing ..."
lines1=$(tshark -r basic.pcap 2>/dev/null | grep 225.1.2.3 | tee    basic.result | wc -l)
lines2=$(tshark -r basic.pcap 2>/dev/null | grep 225.3.2.1 | tee -a basic.result | wc -l)
cat basic.result
echo " => $lines1 for 225.1.2.3, expected => 2"
echo " => $lines2 for 225.3.2.1, expected => 3"

# one frame lost due to initial (*,G) -> (S,G) route setup
# no frames lost in pure (S,G) route
[ "$lines1" = "2" -a "$lines2" = "3" ] && exit 0
exit 1
