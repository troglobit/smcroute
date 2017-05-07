SMCRoute - A static multicast routing daemon
============================================
[![License Badge][]][License] [![Travis Status][]][Travis] [![Coverity Status][]][Coverity Scan]

SMCRoute is a command line tool to manipulate the multicast routes in
the UNIX kernel.  It supports both IPv4 and IPv6 multicast routing.

SMCRoute can be used as an alternative to dynamic multicast routers like
`mrouted` or `pimd` in setups where static multicast routes should be
maintained and/or no proper IGMP or MLD signaling exists.

Multicast routes exist in the UNIX kernel only as long as a multicast
routing daemon is running.  Only one multicast routing daemon can be
active at a time, so it's impossible to run SMCRoute and, e.g.,
`mrouted` at the same time.  Linux does however support multiple routing
tables, which SMCRoute not yet supports.


Features
--------

- Configuration file support, `/etc/smcroute.conf`
- Support for restarting and re-reading `.conf` on `SIGHUP`
- Source-less on-demand routing, a.k.a. (*,G) based static routing


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

The first line means "Join multicast group 225.1.2.3 on interface eth0",
and is for layer-2 devices (switches) with IGMP snooping implemented to
open up multicast for that group to be flooded to us.  You *should not*
need the `mgroup` line, it will cause routing performance loss and is
only intended to be used when you have problems with switches that do
not forward multicast to us by default.  Only 20 groups can be "joined"
this way, for more groups you should investigate the root cause for not
receiving multicast at the multicast router, or use a dynamic multicast
routing protocol.

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

The TTL is what usually bites people trying out multicast the first time.
There is a good reason for applications, e.g., ping to default to a TTL=1
for multicast.  That is to reduce the risk of flooding your network with
data, remember multicast is like broadcast in nature.  Only IGMP snooping
aware switches can help mitigate its broadcast effect.

Traditionally, however, SMCRoute only had the client interface to interact
with the daemon.  To achieve the above two config file lines you have to:

    # sleep 1

To allow the daemon to startup properly (above) before interacting with it.

    # smcroutectl join eth0 225.1.2.3
    # smcroutectl add  eth0 192.168.1.42 225.1.2.3 eth1 eth2


Experimental
------------

Many people sometimes do not know where the multicast will originate
from, or it will originate from several different sources but never at
the same time.  Up until 1.98.3 a user had to setup a unique routing
rule for each possible source and group to be routed.  However, as of
1.99.0 it is possible to use the wildcard address 0.0.0.0 (INADDR_ANY)
for IPv4 multicast routes.

Example smcroute.conf:

    mgroup from eth0 group 225.1.2.3
    mroute from eth0 group 225.1.2.3 to eth1 eth2

or, from the command line:

    # smcroutectl join eth0 225.1.2.3
    # smcroutectl add  eth0 225.1.2.3 eth1 eth2


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
