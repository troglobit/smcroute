SMCRoute - A static multicast routing daemon
============================================
[![License Badge][]][License] [![Travis Status][]][Travis] [![Coverity Status][]][Coverity Scan]

SMCRoute is a UNIX/Linux tool to manage and monitor multicast routes.
It supports both IPv4 and IPv6 multicast routing.

SMCRoute can be used as an alternative to dynamic multicast routers
like [mrouted][] or [pimd][] in setups where static multicast routes
should be maintained and/or no proper IGMP or MLD signaling exists.

Multicast routes exist in the UNIX kernel as long as a multicast routing
daemon is running.  Only one multicast routing daemon can be active at a
time, so it is not possible to run `smcrouted` and, e.g.  `mrouted` at
the same time.


Features
--------

- Configuration file support, `/etc/smcroute.conf`
- Support for restarting and reloading the `.conf` on `SIGHUP`
- Source-less on-demand routing, a.k.a. (*,G) based static routing
- Optional built-in [mrdisc][] support, [RFC4286][]
- Client with built-in support to show routes and joined groups


Usage
-----

SMCRoute is both a daemon and a client.  You must start the daemon first
to be able to set up multicast routes.  Use `smcroute -n` to start the
daemon in foreground, for systemd or [Finit][].

    # smcrouted

or

    # smcrouted -N

or

    # smcrouted -e /path/to/script

The latter syntax calls your own script whenever `smcroute` receives a
`SIGHUP` or installs a multicast route to the kernel.  This is useful if
you, for instance, also run a NAT firewall and need to flush connection
tracking after installing a multicast route.

With the `-N` command line option SMCRoute does *not* prepare all system
interfaces for multicast routing.  Very useful if your system has a lot
of interfaces but only a select few are required for multicast routing.
Use the following configuration file syntax to enable interfaces:

    phyint eth0 enable
    phyint eth1 enable
    phyint eth2 enable

By default SMCRoute looks for its configuration in `/etc/smcroute.conf`,
which can look something like this:

    mgroup from eth0 group 225.1.2.3
    mgroup from eth0 group 225.1.2.3 source 192.168.1.42
    mroute from eth0 group 225.1.2.3 source 192.168.1.42 to eth1 eth2

The first line means "Join multicast group 225.1.2.3 on interface eth0".
Useful if `eth0` is not directly connected to the source, but to a LAN
with switches with IGMP snooping.  Joining the group opens up multicast
for that group towards `eth0`.  Only 20 groups can be joined, for large
setups investigate enabling multicast router ports in the switches, or
possibly use a dynamic multicast routing protocol.

The second `mgroup` is for source specific group join, i.e. the host
specifies that it wants packets from 192.168.1.42 and no other source.

The third `mroute` line is the actual layer-3 routing entry.  Here we
say that multicast data originating from 192.168.1.42 on `eth0` to the
multicast group 225.1.2.3 should be forwarded to interfaces `eth1` and
`eth2`.

**Note:** To test the above you can use ping from another device.  The
   multicast should be visible as long as your IP# matches the source
   above and you ping 225.1.2.3 AND REMEMBER TO SET TTL >1!
   
    $ ping -I eth0 -t 2 225.1.2.3

The TTL is what usually bites people trying out multicast routing.  Most
TCP/IP stacks default to a TTL of 1 for multicast sockets, e.g. ping
requires `-t 2`, or greater, for multicast.  This limitation reduces the
risk of accidentally flooding multicast.  Remember, multicast behaves
like broadcast unless limited.

SMCRoute also has a client interface to interact with the daemon:

    # smcroutectl join eth0 225.1.2.3
    # smcroutectl add  eth0 192.168.1.42 225.1.2.3 eth1 eth2


Experimental
------------

Often multicast can originate from several different sources but never
at the same time.  For a more generic setup, and to reduce the number of
rules required, it is possible to set (*,G) IPv4 multicast routes.

Example smcroute.conf:

    mgroup from eth0 group 225.1.2.3
    mroute from eth0 group 225.1.2.3 to eth1 eth2

or, from the command line:

    # smcroutectl join eth0 225.1.2.3
    # smcroutectl add  eth0 225.1.2.3 eth1 eth2

Another experimental feature is multicast router discovery, [mrdisc][],
described in [RFC4286][].  This feature is disabled by default, enable
with `configure --enable-mrdisc`.  When enabled it periodically sends
out an IGMP message on all inbound interfaces (above `eth0`) to alert
switches to open up multicast in that direction.  Not many managed
switches have support for this yet.


Build & Install
---------------

SMCRoute should in theory work on any UNIX like operating system which
supports the BSD MROUTING API.  Both Linux and FreeBSD are tested on a
regular basis.

On Linux the following kernel config is needed:

    CONFIG_IP_MROUTE=y
    CONFIG_IP_PIMSM_V1=y
    CONFIG_IP_PIMSM_V2=y

Check the list of multicast capable interfaces:

    cat /proc/net/dev_mcast

On *BSD:

    options    MROUTING    # Multicast routing
    options    PIM         # Enable for pimd

As of SMCRoute v2.2, the `libcap` library is required for full privilege
separation using POSIX capabilities.  At startup this library is used to
drop full root privileges, retaining only `CAP_NET_ADMIN` for managing
the multicast routes.  Use `--without-libcap` to disable this feature.

    $ ./configure
    $ make -j5
	$ sudo make install-strip

The `configure` script and the `Makefile.in` files are generated and not
stored in GIT.  So if you checkout the sources from GitHub you first
need to generated these files using `./autogen.sh`.


Origin & References
-------------------

SMCRoute is maintained collaboratively at [GitHub][].  Previously the
code was hosted and maintained by Debian at [Alioth][] and before that
by [Carsten Schill][], the original author.


[Finit]:           https://github.com/troglobit/finit
[mrouted]:         https://github.com/troglobit/mrouted
[pimd]:            https://github.com/troglobit/pimd
[mrdisc]:          https://github.com/troglobit/mrdisc
[RFC4286]:         https://tools.ietf.org/html/rfc4286
[GitHub]:          https://github.com/troglobit/smcroute
[Alioth]:          https://alioth.debian.org/projects/smcroute
[Carsten Schill]:  http://www.cschill.de/smcroute/
[License]:         https://en.wikipedia.org/wiki/GPL_license
[License Badge]:   https://img.shields.io/badge/License-GPL%20v2-blue.svg
[Travis]:          https://travis-ci.org/troglobit/smcroute
[Travis Status]:   https://travis-ci.org/troglobit/smcroute.png?branch=master
[Coverity Scan]:   https://scan.coverity.com/projects/3061
[Coverity Status]: https://scan.coverity.com/projects/3061/badge.svg

<!--
  -- Local Variables:
  -- mode: markdown
  -- End:
  -->
