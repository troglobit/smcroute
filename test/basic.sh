#!/bin/sh
#set -x

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
mroute from a1 group 225.1.2.3 to a2
EOF
cat basic.conf

echo "Starting smcrouted ..."
../src/smcrouted -f basic.conf -n -N &

echo "Starting collector ..."
tcpdump -c 2 -lni a2 -w basic.pcap icmp and dst 225.1.2.3 &
sleep 1

echo "Starting emitter ..."
ping -c 3 -W 1 -I a1 -t 2 225.1.2.3

echo "Cleaning up ..."
killall smcrouted
ip link del a1
ip link del a2

echo "Analyzing ..."
lines=$(tcpdump -r basic.pcap | grep 225.1.2.3 | tee basic.result | wc -l)
cat basic.result
echo "=> num routes frames $lines"

# one frame lost due to initial (*,G) -> (S,G) setup
[ "$lines" != "2" ] && exit 1
exit 0
