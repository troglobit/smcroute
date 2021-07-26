#!/bin/sh
# Verifies IPv4 (S,G) and (*,G) rules by injecting frames on one
# interface and verifying reception on another.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Creating world ..."
topo dummy
ip addr add 10.0.0.1/24 dev a1
ip addr add 20.0.0.1/24 dev a2
ip -br a

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
# basic (*,G) multicast routing
phyint a1 enable
phyint a2 enable
mroute from a1 source 10.0.0.1 group 225.3.2.1 to a2
mroute from a1 group 225.1.2.3 to a2
EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug -S "/tmp/$NM/sock" &
sleep 1

print "Starting collector ..."
tshark -Qc 7 -lni a2 -w "/tmp/$NM/pcap" 'dst 225.3.2.1 or dst 225.1.2.3 or dst 225.1.2.4' 2>/dev/null &

../src/smcroutectl -S "/tmp/$NM/sock" add a1 225.1.2.4 a2

print "Starting emitter ..."
ping -c 3 -W 1 -I a1 -t 2 225.3.2.1 >/dev/null
ping -c 3 -W 1 -I a1 -t 2 225.1.2.3 >/dev/null
ping -c 3 -W 1 -I a1 -t 2 225.1.2.4 >/dev/null
show_mroute

print "Analyzing ..."
lines1=$(tshark -r "/tmp/$NM/pcap" 2>/dev/null | grep 225.1.2.3 | tee    "/tmp/$NM/result" | wc -l)
lines2=$(tshark -r "/tmp/$NM/pcap" 2>/dev/null | grep 225.3.2.1 | tee -a "/tmp/$NM/result" | wc -l)
lines3=$(tshark -r "/tmp/$NM/pcap" 2>/dev/null | grep 225.1.2.4 | tee -a "/tmp/$NM/result" | wc -l)
cat "/tmp/$NM/result"
echo " => $lines1 for 225.1.2.3, expected => 2"
echo " => $lines2 for 225.3.2.1, expected => 3"
echo " => $lines3 for 225.1.2.4, expected => 2"

print "Cleaning up ..."
topo teardown

# one frame lost due to initial (*,G) -> (S,G) route setup
# no frames lost in pure (S,G) route
# shellcheck disable=SC2166
[ "$lines1" = "2" -a "$lines2" = "3" -a "$lines3" = "2" ] && exit 0
exit 1
