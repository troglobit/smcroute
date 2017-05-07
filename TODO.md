
BEFORE RELEASE
--------------

- Audit socket close and `ipc_exit()` ordering, during `SIGHUP`
- Add `smcroutectl show` commadn to list both (*,G) and active kernel routes + mgroups
- Add `compat.c` for an optional old smcroute interface, `--enable-old-smcroute`


Support for re-enumerating VIFs at runtime
------------------------------------------

The main requirement is to be able to add/remove interface VIF/MIF
mappings at runtime, e.g. if an interface has not yet been created when
smcrouted has started.  Currently the -t startup delay option has to be
used for this.

Optimal behavior would be to handle such transitions without losing any
traffic for already established/active routing rules.

May also require updating VIF/MIFs and mroutes accordingly.


Support for filtering based on source ADDRESS/LEN
-------------------------------------------------

    mroute from eth0 except 192.168.1.0/24 group 225.1.2.0/24 to eth1 eth2


IPv6 support for (*, G), on-demand, routing rules
-------------------------------------------------

In SMCRoute 1.99.0 IPv4 support for source-less multicast routes was
added. Adding support for IPv6 should be fairly straight forward, but
needs figuring out the kernel interface and extensive testing.


Add unit tests
--------------

    ./configure --enable-maintainer-mode
    make test
