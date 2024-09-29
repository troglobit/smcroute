#!/bin/sh
# Verifies SIGHUP/reload functionality
# XXX: add group verification as well
#set -x

. "$(dirname "$0")/lib.sh"

print "Creating world ..."
topo plus
ip addr add 10.0.0.1/24 dev a1
ip addr add  fc00::1/64 dev a1
ip addr add 20.0.0.2/24 dev a2
ip addr add  fc00::2/64 dev a2
ip addr add 30.0.0.1/24 dev b1
ip -br a

print "Creating config #1 ..."
cat <<EOF > "/tmp/$NM/conf"
phyint a1 enable
phyint a2 enable
phyint b1 enable

mgroup from a1 source 10.0.0.1 group 225.3.2.1
mroute from a1 source 10.0.0.1 group 225.3.2.1 to b1

mgroup from a2 source 10.0.0.1 group 225.3.2.1
mroute from a2 source 10.0.0.1 group 225.3.2.1 to b1

mgroup from a1 source fc00::3 group ff04:0:0:0:0:0:0:114
mroute from a1 source fc00::3 group ff04:0:0:0:0:0:0:114 to b1

mgroup from a2 source fc00::3 group ff04:0:0:0:0:0:0:114
mroute from a2 source fc00::3 group ff04:0:0:0:0:0:0:114 to b1

EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -N -n -P "/tmp/$NM/pid" -l debug -u "/tmp/$NM/sock" &
sleep 1

cat /proc/net/ip_mr_vif
cat /proc/net/ip_mr_cache
../src/smcroutectl -pu "/tmp/$NM/sock" show groups
show_mroute
ip mroute | grep -E "\(10.0.0.1,225.3.2.1\)\s+Iif: a1\s+Oifs: b1" \
|| FAIL "Failed add IPv4 a1(S,G) -> b1 route"
ip mroute | grep -E "\(10.0.0.1,225.3.2.1\)\s+Iif: a2\s+Oifs: b1" \
|| FAIL "Failed add IPv4 a2(S,G) -> b1 route"

ip -6 mroute | grep -E "\(fc00::3,ff04::114\)\s+Iif: a1\s+Oifs: b1" \
|| FAIL "Failed add IPv6 a1(S,G) -> b1 route"
ip -6 mroute | grep -E "\(fc00::3,ff04::114\)\s+Iif: a2\s+Oifs: b1" \
|| FAIL "Failed add IPv6 a2(S,G) -> b1 route"
OK
