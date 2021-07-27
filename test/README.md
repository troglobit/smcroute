Module Tests
============

The following tests verify fundamental functionality of SMCRoute when
`configure --enable-test`.  Required tools to be installed and available
in `$PATH`:

  - `ip` and `bridge` (iproute2 package, not the BusyBox variants)
  - `ping`
  - `tshark` (because `tcpdump -w foo.pcap` doesn't work in an unshare)

These tools come preinstalled in the Docker container used by SMCRoute
in the [GitHub CI/CD action][2].  Here's how you can get it yourself:

    ~$ docker pull ghcr.io/troglobit/misc:latest
    ~$ docker run --privileged -v`pwd`:`pwd` -w `pwd` -it ghcr.io/troglobit/misc:latest

To run the tests:

	~$ cd src/smcroute
	~/src/smcroute$ ./autogen.sh
	~/src/smcroute$ ./configure --enable-test
	~/src/smcroute$ make -j9
	~/src/smcroute$ make check

Each unit test is standalone.  To manually run select tests:

    ~/src/smcroute$ cd test/
	~/src/smcroute/test$ unshare -mrun ./testname.sh

The tools `ping` and `tshark` are used to create and listen to multicast
streams "routed by" SMCRoute.

> **Note:** these tests must be run in sequence, not in parallel,
>   because they use the same interface names *and*, most importantly,
>   we may run on a kernel w/o multicast policy routing support!

[1]: https://github.com/libnet/nemesis
[2]: https://github.com/troglobit/smcroute/actions/workflows/build.yml


Topologies
----------

The following test topologies are employed to verify different aspects
and use-cases supported by SMCRoute.

### Basic

Interfaces `a1` and `a2` are Linux dummy type interfaces.

                        SMCRoute
                 .------ router -----.
                /                     \
    MC -----> a1                       a2 ------> MC


### Multi

Same as Basic, but with multiple output interfaces, useful for testing
wildcard interface matching.

                        SMCRoute
                 .====== router =====.
                ////               \\\\
     MC ----> a1///                 \\\b1 ------> MC 
     MC ----> a2//                   \\b2 ------> MC 
     MC ----> a3/                     \b3 ------> MC 
     MC ----> a4                       b4 ------> MC 


### Basic w/ VLANs

Interfaces `a1` and `a2` are Linux dummy type interfaces with VLAN
interfaces created on top.  The topology sets up two VLAN interfaces
per dummy interface, VID 100 and 110.

                         SMCRoute
                  .------ router -----.
                 /                     \
    MC -----> a1.110                  a2.110 ------> MC
                |                       |
               a1                      a2


### Bridged w/ VLANs

Two VETH pairs (a1:b1 and a2:b2) are attached to a bridge with VLAN
filtering enabled.  On top of the bridge two VLAN interfaces are
created on which routing takes place.

                       SMCRoute
                    .-- router --.
                   /              \
                 vlan1         vlan2
                      \       /
                       bridge0
    MC -----> a1       /     \        a2 -----> MC
               '------'       '------'

Both bridge ports, `a1` and `a2`, are untagged members of each VLAN.

> **Note:** interface `a1` and `vlan1` are in the same VLAN (VID 1), and
>           interface `a2` and `vlan2` are in the same VLAN (VID 2).


### Isolated Endpoints Bridged w/ VLANs

Like the default bridge, but each endpoint is in an isolated network
namespace.  This allows setting both IPv4 & IPv6 addresses on all
interfaces and using ping6 as emitter instead of requiring [nemesis][1].

                            SMCRoute
                         .-- router --.
                        /              \
      netnst: left    vlan1         vlan2    netns: right
     .-------------.       \       /        .-------------.
     |             |        bridge0         |             |
     | MC --> eth0 |        /     \         | eth0 --> MC |
     |            `--------'       '--------'             |
     '-------------'                        '-------------'

Both bridge ports, `a1` and `a2`, are untagged members of each VLAN.

> **Note:** interface `a1` and `vlan1` are in the same VLAN (VID 1), and
>           interface `a2` and `vlan2` are in the same VLAN (VID 2).


### Isolated

Similar to Basic, but with two VETH pairs with the outer end of each in
an isolated network namespace.  Purpose is to emulate true end devices.

                            SMCRoute
     netns: left         .-- router --.        netns: right
    .-----------.       /              \      .-----------.
    |           |     b1                b2    |           |
    | MC --> a1-|-----'                  `----|-a2 --> MC |
    |           |                             |           |
    '-----------'     VETH pairs: aN//brN     '-----------'
                        In netns: eth0

Tests
-----

### Basic Routing

Verifies routing between two interfaces a1 and a2.  Multicast is
injected on a1 and tcpdump verifies function on a2.

**Topology:** Basic


### VLAN Interfaces

Similar to the basic routing test, except VLAN interfaces are created on
top of the base interfaces, and routing takes place there.

**Topology:** Basic w/ VLANs

												 
### Bridge VLANs

Slightly more advanced test case, a bridge with two VLAN interfaces on
top and two VETH pairs acting as untagged ports to the bridge in each of
the VLANs.  The other end of each VETH pair is placed in an isolated
network namespace to allow proper IP networking to be set up.

**Topology:** Isolated Bridged w/ VLANs


### IPv6 (S,G) and (*,G) Forwarding

Similar to the Bridged VLAN test, only with IPv6.

**Topology:** Basic


### Isolated (*,G) Forwarding

This test is currently very similar to the Basic test, but can easily be
extended with IPv6 support as well.  The trick here is to use the nested
network namespace support, introduced in the new Isolated topology.

The Isolated topology allows setting interface addresses, both IPv4 and
IPv6 (!), regardless of the environment (and as long as the underlying
Linux kernel supports it).  This means a standard tool like `ping` can
be used to send multicast.  Lowering the barrier of entry to run tests.

**Topology:** Isolated
