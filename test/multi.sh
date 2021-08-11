#!/bin/sh
# Verify interop between multiple routers and 1:1 NAT.  Same subnet and
# source IP of multicast emitters.
#
# Note: you may have to `chmod a+rw /var/run/xtables.lock` before test.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Checking dependencies ..."
check_dep iptables

print "Creating world ..."
topo multi R1 R2

# IP world ...
nsenter --net=R1 -- ip addr add 192.168.0.10/24 dev eth0
nsenter --net=R1 -- ip addr add 10.0.0.1/24     dev eth1
nsenter --net=R1 -- iptables -t nat -A PREROUTING  -d 192.168.10.0/24 -j NETMAP --to 10.0.0.0/24
nsenter --net=R1 -- iptables -t nat -A POSTROUTING -s 10.0.0.0/24     -j NETMAP --to 192.168.10.0/24
nsenter --net=R1 -- ip -br l
nsenter --net=R1 -- ip -br a

nsenter --net=R2 -- ip addr add 192.168.0.20/24 dev eth0
nsenter --net=R2 -- ip addr add 10.0.0.1/24     dev eth1
nsenter --net=R2 -- iptables -t nat -A PREROUTING  -d 192.168.20.0/24 -j NETMAP --to 10.0.0.0/24
nsenter --net=R2 -- iptables -t nat -A POSTROUTING -s 10.0.0.0/24     -j NETMAP --to 192.168.20.0/24
nsenter --net=R2 -- ip -br l
nsenter --net=R2 -- ip -br a

print "Creating config ..."
cat <<EOF >"/tmp/$NM/shared.conf"
# shared.conf for both netns
phyint eth0 enable
phyint eth1 enable

mgroup from eth1 group 225.1.2.3
mroute from eth1 group 225.1.2.3 to eth0

mgroup from eth0 group 225.1.2.3
mroute from eth0 group 225.1.2.3 to eth1
EOF
cat "/tmp/$NM/shared.conf"

print "Starting smcrouted instances ..."
nsenter --net=R1 -- ../src/smcrouted -f "/tmp/$NM/shared.conf" -n -N -I R1 -l debug -S "/tmp/$NM/R1.sock" &
echo $! >> "/tmp/$NM/PIDs"
nsenter --net=R2 -- ../src/smcrouted -f "/tmp/$NM/shared.conf" -n -N -I R2 -l debug -S "/tmp/$NM/R2.sock" &
echo $! >> "/tmp/$NM/PIDs"
sleep 1

collect br0 -c10 'dst 225.1.2.3'

print "Starting emitters ..."
nsenter --net=R1 -- ping -c 5 -W 1 -I eth1 -t 3 225.1.2.3 > /dev/null &
sleep 1
nsenter --net=R2 -- ping -c 5 -W 1 -I eth1 -t 3 225.1.2.3 > /dev/null &
sleep 5

print "R1 multicast routes and 1:1 NAT ..."
nsenter --net=R1 -- ip mroute
nsenter --net=R1 -- iptables -v -L -t nat

print "R2 multicast routes and 1:1 NAT ..."
nsenter --net=R2 -- ip mroute
nsenter --net=R2 -- iptables -v -L -t nat

print "Analyzing ..."
lines=$(tshark -r "/tmp/$NM/pcap" 2>/dev/null | grep 225.1.2.3 | tee "/tmp/$NM/result" | wc -l)

cat "/tmp/$NM/result"
echo " => $lines for group ff04::114, expected >= 8"

# shellcheck disable=SC2086
[ $lines -ge 8 ] && OK
FAIL
