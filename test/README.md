Module Tests
============

These tests verify fundamental functionality of SMCRoute.  Currently
they require `unshare`, `iproute2`, `ping`, and `tcpdump` to be
installed and available in `$PATH`.

`unshare` along with `iproute2` are used to set up an isolated network
namespace with VETH pairs in various use-cases.

`ping` and `tcpdump` are used to create and listen to multicast streams
"routed by" SMCRoute.


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
