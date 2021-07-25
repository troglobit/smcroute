Module Tests
============

These following tests verify fundamental functionality of SMCRoute.  The
`configure` script enables running them only if it finds the required
capabilities.

Required tools to be installed and available in `$PATH`:

  - `iproute2` (`ip` and `bridge`)
  - `ping`
  - `tshark` (because `tcpdump -w foo.pcap` doesn't work in an unshare)
  - [nemesis][]

You need to have `CAP_NET_ADMIN`, which you need to be root to set up,
or e.g., run the tests in a Docker container:

    ~$ docker pull ghcr.io/troglobit/misc:latest
    ~$ docker run --cap-add=NET_ADMIN -v`pwd`:`pwd` -w `pwd` -it ghcr.io/troglobit/misc:latest

To manually run select tests, it is also possible to `cd test/` followed
by `sudo ./testname.sh`.  Each test is standalone.  However, it is still
highly recommended to use a container to protect against side effects
from the host system.

`ping`/`nemesis` and `tcpdump` are used to create and listen to
multicast streams "routed by" SMCRoute.

> **Note:** these tests must be run in sequence, not in parallel,
>   because they use the same interface names *and*, most importantly,
>   we may run on a kernel w/o multicast policy routing support!


Basic Routing
-------------

Verifies routing between two interfaces b1 and b2.  Multicast is
injected on a1 and tcpdump verifies function on a2.

                            SMCRoute
                     .------ router -----.
                    /                     \
    MC -----> dummy0                      dummy1 ------> MC


VLAN Interfaces
---------------

Similar to the basic routing test, except that VLAN interfaces are
created on top of the base interfaces, and routing takes place there.
												 
                             SMCRoute
                      .------ router -----.
                     /                     \
    MC -----> dummy0.110              dummy1.110 ------> MC
                    |                       |
               dummy0                       dummy1


Bridge VLANs
------------

Slightly more advanced test case, a bridge with two VLAN interfaces on
top and two VETH pairs acting as untagged ports to the bridge in each
of the VLANs.

                       SMCRoute
                    .-- router --.
                   /              \
                 vlan1         vlan2
                      \       /
                       bridge0
    MC -----> a1       /     \        a2 -----> MC
               '------'       '------'

Unlike the previous tests, this test makes use of [nemesis][] to inject
multicast frames on a1.  The because of limitations in the networking
stack of Linux, having two interfaces in the same IP network (a1 and
vlan1) does not work, so a1 (and a2) need to be in separate network
namespaces.  However, since GitHub Actions don't allow creating netns,
we instead revert to use nemesis.  The socat tool could also be used,
but injecting directly on a1 requires composing the packet from the
Ethernet header and up, and nemesis is so much better at that.

[nemesis]: https://github.com/libnet/nemesis
