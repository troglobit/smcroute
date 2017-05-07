Support for (re-)enumerating VIFs at runtime
--------------------------------------------

Currently the `-t SEC` startup delay option has to be used if not all
interfaces are available when `smcrouted` starts.  Commonly a problem at
boot, but also if adding a pluggable interface (PCMCIA/USB) at runtime.

Hence, it would be a great addition to SMCRoute if new interface VIF/MIF
mappings could be at least added at runtime.


Support for filtering based on source ADDRESS/LEN
-------------------------------------------------

    mroute from eth0 except 192.168.1.0/24 group 225.1.2.0/24 to eth1 eth2


IPv6 support for (*,G) on-demand routing rules
----------------------------------------------

As of SMCRoute v1.99.0 IPv4 support for (*,G) routes was added.  Adding
support for IPv6 should be fairly straight forward but needs figuring
out the kernel interface and some basic testing.


Add unit tests
--------------

    ./configure --enable-maintainer-mode
    make test
