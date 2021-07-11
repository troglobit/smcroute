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

                          .----- routing -----.
    MC ----->            /                     \           ------> MC
             a1        b1                      b2        a2
              `--------'                        `--------'

