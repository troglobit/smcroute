#!/bin/sh
# Helper functions for testing SMCRoute


# Print heading for test phases
print()
{
    printf "\e[7m>> %-72s\e[0m\n" "$1"
}


# Set up a basic bridge topology, two VETH pairs with one end in the
# bridge and the other free.  Each pair is also in a separate VLAN.
#
# No IP address assignment is done in topo files, only topology setup.
#
# Topology:          ¦
#             vlan1  ¦  vlan2
#                  \ ¦ /
#       a1 -------- br0 --------- a2
#                    ¦
#       VLAN 1       ¦        VLAN 2
#
# Note: in addition to VLAN filtering, the bridge has both IGMP and MLD
#       snooping disabled, because the main purpose of these tests is to
#       verify the IPv4 and IPv6 routing functionality of SMCRoute.
#       Future tests may include verifying join/leave of groups (TODO)
topo_bridge()
{
    cat << EOF > topo.ip
link add br0 type bridge vlan_filtering 1 mcast_snooping 0
link add a1 type veth peer b1
link add a2 type veth peer b2
link set b1 master br0
link set b2 master br0

link set a1 up
link set b1 up
link set a2 up
link set b2 up
link set br0 up

link add link br0 vlan1 type vlan id 1
link add link br0 vlan2 type vlan id 2

link set vlan1 up
link set vlan2 up
EOF

    # Move b2 to VLAN 2
    # Set br0 as tagged member of both VLANs
    cat <<EOF > bridge.ip
vlan add vid 2 dev b2 pvid untagged
vlan del vid 1 dev b2

vlan add vid 1 dev br0 self
vlan add vid 2 dev br0 self
EOF

    ip     -force -batch topo.ip
    bridge -force -batch bridge.ip
}


# Set up a basic dummy interface topology,
#
# No IP address assignment is done in topo files, only topology setup.
topo_dummy()
{
    cat << EOF > topo.ip
link add a1 type dummy
link set a1 up
link set a1 multicast on

link add a2 type dummy
link set a2 up
link set a2 multicast on
EOF

    ip -force -batch topo.ip

    return 2
}

# Set up VLAN interfaces on top of dummy interfaces
# shellcheck disable=SC2048
topo_dummy_vlan()
{
    num=$1
    shift 1

    i=1
    while [ $i -le "$num" ]; do
	iface=a$i
	i=$((i + 1))

	for vid in $*; do
	    ip link add "$iface.$vid" link $iface type vlan id "$vid"
	    ip link set "$iface.$vid" up
	    ip link set "$iface.$vid" multicast on
	done
    done
}

topo()
{
    case "$1" in
	bridge)
	    topo_bridge
	    ;;
	dummy)
	    topo_dummy
	    num=$?
	    shift
	    case "$1" in
		vlan)
		    shift
		    topo_dummy_vlan "$num" "$*"
		    ;;
	    esac
	    ;;
	*)
	    print "No such topology: $1"
	    exit 1
	    ;;
    esac
}
