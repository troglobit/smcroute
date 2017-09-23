Support for (re-)enumerating VIFs at runtime
--------------------------------------------

Currently the `-t SEC` startup delay option has to be used if not all
interfaces are available when `smcrouted` starts.  Commonly a problem at
boot, but also if adding a pluggable interface (PCMCIA/USB) at runtime.

Hence, it would be a great addition to SMCRoute if new interface VIF/MIF
mappings could be at least added at runtime.


Support for filtering based on source ADDRESS/LEN
-------------------------------------------------

When setting up a (*,G/LEN) route it may be necessary to filter out some
senders of multicast.  The following is a suggestion for how that might
look, notice the omitted `source` argument:

    mroute from eth0 except 192.168.1.0/24 group 225.1.2.0/24 to eth1 eth2

Filtering multiple sources:

    mroute from eth0 except 192.168.1.0/24,192.168.2.3 group 225.1.2.0/24 to eth1 eth2


Basic support for IGMP/MLD proxying
-----------------------------------

In some setups a semi-dynamic behavior is required, but the only
signaling available is IGMP/MLD.  There exist tools like [igmpproxy][]
and [mcproxy][] for this purpose, which do a great job, but why should
you need to go elsewhere for your basic multicast routing needs?

The idea itself is simple, listen for IGMP/MLD join/leave messages on
enabled interfaces and add/remove routes dynamically from an `upstream`
marked interface.

Possibly an `igmp` flag may be needed as well, for downstream interfaces
we should proxy for.  Resulting `smcroute.conf` may then look like this:

    phyint eth0 upstream
    phyint eth1 igmp

**Note:** the IGMP/MLD signaling may also need to be "proxied" to the
  `upstream` interface, although this could be an optional second step
  enabled by also setting the `igmp` flag on that `upstream` interface.

For more information, see the above mentioned tools and [RFC4605][],
which details exactly this use-case.


IPv6 support for (*,G) on-demand routing rules
----------------------------------------------

As of SMCRoute v1.99.0 IPv4 support for (*,G) routes was added.  Adding
support for IPv6 should be fairly straight forward but needs figuring
out the kernel interface and some basic testing.


IPv6 support for listing joined groups and routes
-------------------------------------------------

The current `smcroutectl show` command only lists IPv4 groups and
routes.  Adding support for IPv6 as well is quite straight forward,
but requires someone with IPv6 knowledge.


Add unit tests
--------------

    ./configure --enable-maintainer-mode
    make test

[igmpproxy]: https://github.com/pali/igmpproxy
[mcproxy]:   https://github.com/mcproxy/mcproxy
[RFC4605]:   https://www.ietf.org/rfc/rfc4605.txt
