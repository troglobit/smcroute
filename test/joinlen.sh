#!/bin/sh

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

cat /proc/net/mcfilter
ip maddr show dev a2

print "Verifying ..."
# only checking for a sample in each range
ip maddr show dev a2 | grep 225.3.2.249
config_asm=$?

grep "0xe101022a 0x0a00000a" /proc/net/mcfilter
config_ssm=$?

################################################################### LEAVE GROUPS
../src/smcroutectl -S "/tmp/$NM/sock" leave a1 10.0.0.10 225.1.2.40/24
../src/smcroutectl -S "/tmp/$NM/sock" leave a2 225.3.2.250/24

#################################################################### JOIN GROUPS
print "Phase 2: Join groups (IPC)"
../src/smcroutectl -S "/tmp/$NM/sock" join a1 10.0.0.10 225.1.1.1/30
../src/smcroutectl -S "/tmp/$NM/sock" join a2 225.0.0.1/30

cat /proc/net/mcfilter
ip maddr show dev a2

print "Verifying ..."
# only checking for a sample in each range
ip maddr show dev a2 | grep 225.0.0.2
join_asm=$?

grep "0xe1010102 0x0a00000a" /proc/net/mcfilter
join_ssm=$?

########################################################################### DONE
# shellcheck disable=SC2166
[ $config_asm -eq 0 -a $config_ssm -eq 0 -a $join_asm -eq 0 -a $join_ssm -eq 0 ] && OK
FAIL
