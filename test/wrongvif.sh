#!/bin/sh
# Verifies WRONGVIF remediation when two routers share a source IP on
# the same shared bridge -- the colliding-source case from issue #143.
#
#                                br0 (root ns)
#                                |          |
#         netns: R1               |          |              netns: R2
#        .-------------.          |          |          .-------------.
#        |  smcrouted  |          |          |          |  smcrouted  |
#   .--->| eth1   eth0 |---br0 port            br0 port---| eth0   eth1 |<---.
#   |    '-------------'                                  '-------------'    |
#   |                                                                        |
#   netns: fpga1                                                netns: fpga2
#     eth0 == 10.0.0.2                                          eth0 == 10.0.0.2
#     emits multicast                                          emits multicast
#
# fpga1 and fpga2 share 10.0.0.2 as source; this is the colliding
# source from gsmecher's #143 report.  fpga1 emits first -- R1
# forwards onto br0, R2 sees the (10.0.0.2, 225.1.2.3) flow on its
# eth0 and installs a stop filter in its kernel MFC.  Then fpga2
# emits the same (S,G) into R2.eth1; the kernel finds the existing
# entry, sees the packet arrived on the wrong VIF, and raises
# IGMPMSG_WRONGVIF.  smcrouted's WRONGVIF remediation looks up the
# matching (*,G) rule with rule->inbound == real iif and reinstalls
# the MFC with the correct inbound iface.
#
# Without remediation R2's flow stays blocked; with it 1+ packets
# reach br0 from R2 (the WRONGVIF that triggers the repair is lost).
#
# Packets from R1 and R2 share SRCIP+GROUP, so the test distinguishes
# them by TTL: fpga1 ttl=11 (decremented to 10 by R1 at br0), fpga2
# ttl=21 (decremented to 20 by R2 at br0).
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Checking dependencies ..."
check_dep tshark

print "Creating world ..."
# Persistent netns mount files; nsenter --net=<file> opens them.  We
# can't use `topo multi` because we need eth1 as a veth into a
# separate fpga netns rather than the dummy it provides.
PID=$$
for ns in R1 R2 fpga1 fpga2; do
	touch "/tmp/$NM/$ns"
	echo "/tmp/$NM/$ns" >> "/tmp/$NM/mounts"
	unshare --net="/tmp/$NM/$ns" -- ip link set lo up
done

# br0 (root ns) connects R1.eth0 and R2.eth0 via veth pairs.
ip link add br0 type bridge
ip link set br0 up

for r in R1 R2; do
	nsenter --net="/tmp/$NM/$r" -- ip link add eth0 type veth peer "${r}br"
	nsenter --net="/tmp/$NM/$r" -- ip link set "${r}br" netns $PID
	nsenter --net="/tmp/$NM/$r" -- ip link set eth0 up
	ip link set "${r}br" master br0
	ip link set "${r}br" up
done

# fpgaN.eth0 <-> RN.eth1 direct veth pairs (create in fpga, move the
# eth1 end into the router via the netns mount file path).
for n in 1 2; do
	nsenter --net="/tmp/$NM/fpga$n" -- ip link add eth0 type veth peer eth1
	nsenter --net="/tmp/$NM/fpga$n" -- ip link set eth1 netns "/tmp/$NM/R$n"
	nsenter --net="/tmp/$NM/fpga$n" -- ip link set eth0 up
	nsenter --net="/tmp/$NM/R$n"    -- ip link set eth1 up
done

# IP addressing.  Both fpgas share 10.0.0.2 -- the colliding source.
nsenter --net="/tmp/$NM/R1"    -- ip addr add 192.168.0.10/24 dev eth0
nsenter --net="/tmp/$NM/R1"    -- ip addr add 10.0.0.1/24     dev eth1
nsenter --net="/tmp/$NM/R2"    -- ip addr add 192.168.0.20/24 dev eth0
nsenter --net="/tmp/$NM/R2"    -- ip addr add 10.0.0.1/24     dev eth1
nsenter --net="/tmp/$NM/fpga1" -- ip addr add 10.0.0.2/24     dev eth0
nsenter --net="/tmp/$NM/fpga2" -- ip addr add 10.0.0.2/24     dev eth0
nsenter --net="/tmp/$NM/fpga1" -- ip route add 225.1.2.3 dev eth0
nsenter --net="/tmp/$NM/fpga2" -- ip route add 225.1.2.3 dev eth0

# Both routers see multicast from 10.0.0.2 arriving on eth0 (from the
# OTHER router's forward); rp_filter strict-mode would drop it because
# 10.0.0.0/24 is reachable via eth1 in our route table.  accept_local
# additionally lets us accept multicast whose src matches one of our
# own local addresses on a non-local iface.
for ns in R1 R2; do
	for k in all default eth0 eth1; do
		nsenter --net="/tmp/$NM/$ns" -- sysctl -wq net.ipv4.conf.$k.rp_filter=0
		nsenter --net="/tmp/$NM/$ns" -- sysctl -wq net.ipv4.conf.$k.accept_local=1
	done
done

print "Creating config ..."
cat <<EOF >"/tmp/$NM/shared.conf"
phyint eth0 enable
phyint eth1 enable

mroute from eth1 group 225.1.2.3 to eth0
EOF
cat "/tmp/$NM/shared.conf"

print "Starting smcrouted instances ..."
nsenter --net="/tmp/$NM/R1" -- ../src/smcrouted -f "/tmp/$NM/shared.conf" -n -N -i R1 -l debug -u "/tmp/$NM/R1.sock" &
echo $! >> "/tmp/$NM/PIDs"
nsenter --net="/tmp/$NM/R2" -- ../src/smcrouted -f "/tmp/$NM/shared.conf" -n -N -i R2 -l debug -u "/tmp/$NM/R2.sock" &
echo $! >> "/tmp/$NM/PIDs"
sleep 1

collect br0 -c10 'dst 225.1.2.3'

print "Phase 1: fpga1 emits first (ttl=11), R2 should install a stop filter ..."
nsenter --net="/tmp/$NM/fpga1" -- ping -c 3 -W 1 -t 11 225.1.2.3 > /dev/null
sleep 1

print "R2 MFC after Phase 1 (expect iif: eth0, no oifs):"
nsenter --net="/tmp/$NM/R2" -- ip mroute

print "Phase 2: fpga2 emits (ttl=21), WRONGVIF must remap to eth1 ..."
nsenter --net="/tmp/$NM/fpga2" -- ping -c 3 -W 1 -t 21 225.1.2.3 > /dev/null
sleep 2

print "R2 MFC after Phase 2 (expect iif: eth1, oifs: eth0):"
nsenter --net="/tmp/$NM/R2" -- ip mroute

print "Analyzing br0 pcap ..."
lines1=$(tshark -r "/tmp/$NM/pcap" 2>/dev/null | grep 225.1.2.3 | grep 'ttl=10' | tee    "/tmp/$NM/result" | wc -l)
lines2=$(tshark -r "/tmp/$NM/pcap" 2>/dev/null | grep 225.1.2.3 | grep 'ttl=20' | tee -a "/tmp/$NM/result" | wc -l)
cat "/tmp/$NM/result"
echo " => $lines1 packets from R1 (ttl=10), expected >= 2"
echo " => $lines2 packets from R2 (ttl=20), expected >= 1"

# R1 always works (NOCACHE -> rule match).  R2 only works after the
# WRONGVIF remap installs the correct MFC entry; the WRONGVIF packet
# that triggers the remap is itself lost.
[ "$lines1" -ge 2 ] && [ "$lines2" -ge 1 ] && OK
FAIL
