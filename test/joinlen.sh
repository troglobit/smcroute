#!/bin/sh

# only checking for a sample in each range
check_output()
{
    print "Verifying ..."
    if [ -n "$1" ]; then
	ip maddr show dev a2
	if ! ip maddr show dev a2 | grep -q "$1"; then
	    FAIL "Cannot find (* $1)"
	fi
    fi

    if [ -n "$2" ]; then
	cat /proc/net/mcfilter
	if ! grep -q "$2" /proc/net/mcfilter; then
	    FAIL "Cannot find ($2)"
	fi
    fi
}

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Creating world ..."
topo basic

# IP world ...
ip addr add 10.0.0.1/24  dev a1
ip addr add 20.0.0.1/24  dev a2
ip addr add 2001:1::1/64 dev a1
ip addr add 2001:2::1/64 dev a2
ip -br a

################################################################## STATIC GROUPS
print "Phase 1: Join groups (.conf)"
cat <<EOF > "/tmp/$NM/conf"
# ASM + SSM join/leave multicast groups
phyint a1 enable
phyint a2 enable

mgroup from a1 source 10.0.0.10 group 225.1.2.40/24
mgroup from a2 group 225.3.2.250/24
EOF
cat "/tmp/$NM/conf"

print "Starting smcrouted ..."
../src/smcrouted -f "/tmp/$NM/conf" -n -N -P "/tmp/$NM/pid" -l debug -S "/tmp/$NM/sock" &
sleep 1

check_output "225.3.2.249" "0xe101022a 0x0a00000a"

################################################################### LEAVE GROUPS
../src/smcroutectl -S "/tmp/$NM/sock" leave a1 10.0.0.10 225.1.2.40/24
../src/smcroutectl -S "/tmp/$NM/sock" leave a2 225.3.2.250/24
cat /proc/net/mcfilter
ip maddr show dev a2

#################################################################### JOIN GROUPS
print "Phase 2: Join groups (IPC)"
../src/smcroutectl -S "/tmp/$NM/sock" join a1 10.0.0.10 225.1.1.1/30
../src/smcroutectl -S "/tmp/$NM/sock" join a2 225.0.0.1/30
check_output "225.0.0.2" "0xe1010102 0x0a00000a"

################################################################### LEAVE GROUPS
print "Debug 1 ..."
../src/smcroutectl -S "/tmp/$NM/sock" show group
../src/smcroutectl -S "/tmp/$NM/sock" leave a1 10.0.0.10 225.1.1.1/30
../src/smcroutectl -S "/tmp/$NM/sock" leave a2 225.0.0.1/30

################################################################### JOIN SOURCES
print "Debug 2 ..."
../src/smcroutectl -S "/tmp/$NM/sock" show group
print "Phase 3: Join group from multiple sources (IPC)"
../src/smcroutectl -S "/tmp/$NM/sock" join a1 10.0.0.1/26 225.1.2.3
check_output "" "0xe1010203 0x0a00003e"

########################################################################### DONE
OK
