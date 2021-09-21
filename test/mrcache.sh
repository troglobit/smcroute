#!/bin/sh
# Verifies IPv4 (S,G) add and remove route via IPC bites in kernel.
# Twist: uses only one interface, inteded to mimic Debian test.
#set -x

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

debug()
{
    cat /proc/net/ip_mr_cache
    ip mroute
    echo "-----------------------------------------------------------------------------------"
    ../src/smcroutectl -pd -u "/tmp/$NM/sock"
}

print "Creating world ..."
topo basic
ip addr add 10.0.0.1/24 dev a1
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
../src/smcroutectl -u "/tmp/$NM/sock" add a1 10.0.0.1 224.0.1.20 a1
sleep 1

print "Verifying kernel route ..."
debug
if ! grep "140100E0 0100000A 2          0        0        0  2:1" /proc/net/ip_mr_cache; then
    FAIL
fi

print "Removing IPC route ..."
../src/smcroutectl -u "/tmp/$NM/sock" del a1 10.0.0.1 224.0.1.20
sleep 1

print "Verifying kernel route ..."
debug
if grep "140100E0 0100000A" /proc/net/ip_mr_cache; then
    FAIL
fi

OK
