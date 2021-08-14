#!/bin/sh
# Verify multicast routing between two routers over a GRE tunnel
#
#         netns: R1                         netns: R2
#        .-------------.                   .-------------.
#        |  smcrouted  |                   |  smcrouted  |
#        |    /   \    |       br0         |    /   \    |
#   MC --> eth1   eth0 |      /   \        | eth0   eth1 <-- MC
#        |            `------'     '-------'             |
#        '-------------'  192.168.0.0/24   '-------------'
#          10.0.0.0/24                       10.0.0.0/24
#
# Note: you may have to `modprobe ip_gre` before the test.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Checking dependencies ..."
lsb_release -a
uname -a
check_dep grep -q ip_gre /proc/modules

print "Creating world ..."
topo multi R1 R2

# IP world ...
echo "Links, addresses, and routes for R1 ====================================="
nsenter --net=R1 -- ip addr add 192.168.0.10/24 dev eth0
nsenter --net=R1 -- ip addr add 10.0.0.1/24     dev eth1
nsenter --net=R1 -- ip tunnel add tun0 mode gre remote 192.168.0.20 local 192.168.0.10 ttl 255
nsenter --net=R1 -- ip addr add 172.16.0.10/24  dev tun0
nsenter --net=R1 -- ip link set tun0 multicast on
nsenter --net=R1 -- ip link set tun0 up
nsenter --net=R1 -- ip route add 20.0.0.0/24 via 172.16.0.10
nsenter --net=R1 -- ip -br l
nsenter --net=R1 -- ip -br a
nsenter --net=R1 -- ip -br r

echo "Links, addresses, and routes for R2 ====================================="
nsenter --net=R2 -- ip addr add 192.168.0.20/24 dev eth0
nsenter --net=R2 -- ip addr add 20.0.0.1/24     dev eth1
nsenter --net=R2 -- ip tunnel add tun0 mode gre remote 192.168.0.10 local 192.168.0.20 ttl 255
nsenter --net=R2 -- ip addr add 172.16.0.20/24  dev tun0
nsenter --net=R2 -- ip link set tun0 multicast on
nsenter --net=R2 -- ip link set tun0 up
nsenter --net=R2 -- ip route add 10.0.0.0/24 via 172.16.0.20
nsenter --net=R2 -- ip -br l
nsenter --net=R2 -- ip -br a
nsenter --net=R2 -- ip -br r

print "Verifying connectivity ..."
printf "R1 (172.16.0.10) "
if ! nsenter --net=R1 -- ping -c 3 172.16.0.20; then
    FAIL "R1: cannot reach R2 over GRE tunnel"
fi

print "Creating config ..."
cat <<EOF >"/tmp/$NM/shared.conf"
# shared.conf for both netns
phyint tun0 enable
phyint eth1 enable

mgroup from eth1 group 225.1.2.3
mroute from eth1 group 225.1.2.3 to tun0

mgroup from tun0 group 225.1.2.3
mroute from tun0 group 225.1.2.3 to eth1
EOF
cat "/tmp/$NM/shared.conf"

print "Starting smcrouted instances ..."
nsenter --net=R1 -- ../src/smcrouted -f "/tmp/$NM/shared.conf" -n -N -I R1 -l debug -S "/tmp/$NM/R1.sock" &
echo $! >> "/tmp/$NM/PIDs"
nsenter --net=R2 -- ../src/smcrouted -f "/tmp/$NM/shared.conf" -n -N -I R2 -l debug -S "/tmp/$NM/R2.sock" &
echo $! >> "/tmp/$NM/PIDs"
sleep 1

print "Starting collector on eth1@R2 ..."
nsenter --net=R2 -- tshark -w "/tmp/$NM/pcap" -lni eth1 -c5 'dst 225.1.2.3' 2>/dev/null &

print "Starting emitters ..."
nsenter --net=R1 -- ping -c 5 -W 1 -I eth1 -t 10 225.1.2.3 > /dev/null &
sleep 5

print "Analyzing pcap from eth1@R2 ..."
lines1=$(tshark -r "/tmp/$NM/pcap" 2>/dev/null | grep 225.1.2.3 | tee "/tmp/$NM/result" | wc -l)
cat "/tmp/$NM/result"

echo " => $lines1 for group 225.1.2.3 from R1, expected >= 4"

# Expect one frame loss for each initial (*,G) -> (S,G) route setup
# shellcheck disable=SC2086
[ $lines1 -ge 3 ] && OK
FAIL
