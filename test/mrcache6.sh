#!/bin/sh
# Verifies IPv6 (S,G) add and remove route via IPC bites in kernel.
# Twist: uses only one interface, inteded to mimic Debian test.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

debug()
{
    cat /proc/net/ip6_mr_cache
    ip -6 mroute
    echo "-----------------------------------------------------------------------------------"
    ../src/smcroutectl -pd -u "/tmp/$NM/sock"
}

print "Creating world ..."
topo basic
ip addr add fc01::1/64 dev a1
ip -br a

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
# empty
EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -P "/tmp/$NM/pid" -l debug -u "/tmp/$NM/sock" &
sleep 1

print "Adding IPC route ..."
../src/smcroutectl -u "/tmp/$NM/sock" add a1 fc01::1 ff01:0:0:0:0:0:0:114 a1
sleep 1

print "Verifying kernel route ..."
debug
if ! grep "ff01:0000:0000:0000:0000:0000:0000:0114 fc01:0000:0000:0000:0000:0000:0000:0001 2          0        0        0  2:1" /proc/net/ip6_mr_cache; then
    FAIL
fi

print "Removing IPC route ..."
../src/smcroutectl -u "/tmp/$NM/sock" del a1 fc01::1 ff01:0:0:0:0:0:0:114
sleep 1

print "Verifying kernel route ..."
debug
if grep "ff01:0000:0000:0000:0000:0000:0000:0114 fc01:0000:0000:0000:0000:0000:0000:0001" /proc/net/ip_mr_cache; then
    FAIL
fi

OK
