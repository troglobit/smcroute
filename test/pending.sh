#!/bin/sh
# Verifies that an mroute/mgroup referencing an interface that does not
# yet exist is queued on the pending list and automatically activated
# when the interface arrives, without SIGHUP or `smcroutectl reload`.
# Covers both a missing inbound (a1) and a missing outbound (a3).
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Creating world ..."
# Only a2 exists at startup; a1 (inbound) and a3 (outbound) come later.
ip link add a2 type dummy
ip link set a2 multicast on
ip link set a2 up
ip addr add 20.0.0.1/24 dev a2
ip -br a

print "Creating config that references a1 and a3 (not yet present) ..."
cat <<EOF > "/tmp/$NM/conf"
mroute from a1 group 225.1.2.3 to a2
mroute from a2 group 225.7.8.9 to a3
mgroup from a1 group 225.4.5.6
EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -P "/tmp/$NM/pid" -l debug -u "/tmp/$NM/sock" &
sleep 1

print "Verifying both mroutes and the mgroup are pending ..."
../src/smcroutectl -pu "/tmp/$NM/sock" show pending | tee "/tmp/$NM/pending-before"
grep -Eq "^mroute.*from a1.*group 225\.1\.2\.3.*to a2" "/tmp/$NM/pending-before" \
	|| FAIL "mroute with missing inbound (a1) not on pending list"
grep -Eq "^mroute.*from a2.*group 225\.7\.8\.9.*to a3" "/tmp/$NM/pending-before" \
	|| FAIL "mroute with missing outbound (a3) not on pending list"
grep -Eq "^mgroup.*from a1.*group 225\.4\.5\.6" "/tmp/$NM/pending-before" \
	|| FAIL "mgroup not on pending list"

print "Creating the missing interfaces a1 and a3 ..."
ip link add a1 type dummy
ip link set a1 multicast on
ip link set a1 up
ip addr add 10.0.0.1/24 dev a1
ip link add a3 type dummy
ip link set a3 multicast on
ip link set a3 up
ip addr add 30.0.0.1/24 dev a3

# Give the netlink listener a moment to deliver the events and drain.
sleep 1

print "Verifying pending list is now empty ..."
../src/smcroutectl -pu "/tmp/$NM/sock" show pending | tee "/tmp/$NM/pending-after"
grep -q "^No pending" "/tmp/$NM/pending-after" \
	|| FAIL "pending list should be empty after both interfaces arrived"

print "Verifying both mroutes are installed in smcrouted ..."
../src/smcroutectl -pu "/tmp/$NM/sock" show | tee "/tmp/$NM/show-after"
grep -Eq "225\.1\.2\.3.*a1.*a2" "/tmp/$NM/show-after" \
	|| FAIL "(*,225.1.2.3) a1 -> a2 missing after auto-activation"
grep -Eq "225\.7\.8\.9.*a2.*a3" "/tmp/$NM/show-after" \
	|| FAIL "(*,225.7.8.9) a2 -> a3 missing after auto-activation"

print "Verifying a1 and a3 have VIFs allocated ..."
../src/smcroutectl -pu "/tmp/$NM/sock" show interfaces | tee "/tmp/$NM/iface-after"
grep -Eq "^[[:space:]]*[0-9]+[[:space:]]+a1[[:space:]]+[0-9]+" "/tmp/$NM/iface-after" \
	|| FAIL "a1 should have a VIF after auto-activation"
grep -Eq "^[[:space:]]*[0-9]+[[:space:]]+a3[[:space:]]+[0-9]+" "/tmp/$NM/iface-after" \
	|| FAIL "a3 should have a VIF after auto-activation"

print "Verifying multicast actually flows through the new route ..."
collect a2 -c2 'dst 225.1.2.3'
ping -c 3 -W 1 -I a1 -t 2 225.1.2.3 >/dev/null
show_mroute

print "Analyzing ..."
lines=$(tshark -r "/tmp/$NM/pcap" 2>/dev/null | grep 225.1.2.3 | tee "/tmp/$NM/result" | wc -l)
cat "/tmp/$NM/result"
echo " => $lines for 225.1.2.3, expected >= 2"

########################################################################### DONE
# One frame lost to (*,G) -> (S,G) install on first packet.
[ "$lines" -ge 2 ] && OK
FAIL
