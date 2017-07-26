SMCRoute - A static multicast routing daemon
============================================
[![License Badge][]][License] [![Travis Status][]][Travis] [![Coverity Status][]][Coverity Scan]

Table of Contents
-----------------
* [About](#about)
* [Features](#features)
* [Usage](#usage)
  * [Actions Scripts](#action-scripts)
  * [Many Interfaces](#many-interfaces)
  * [Multiple Routing Tables](#multiple-routing-tables)
  * [Client Tool](#client-tool)
* [Experimental](#experimental)
* [Build & Install](#build--install)
  * [Linux Requirements](#linux-requirements)
  * [*BSD Requirements](#bsd-requirements)
  * [General Requirements](#general-requirements)
  * [Configure & Build](#configure--build)
  * [Integration with systemd](#integration-with-systemd)
  * [Static Build](#static-build)
  * [Building from GIT](#building-from-git)
* [Origin & References](#origin--references)


About
-----

SMCRoute is a UNIX/Linux tool to manage and monitor multicast routes.
It supports both IPv4 and IPv6 multicast routing.

SMCRoute can be used as an alternative to dynamic multicast routers
like [mrouted][] or [pimd][] in setups where static multicast routes
should be maintained and/or no proper IGMP or MLD signaling exists.

Multicast routes exist in the UNIX kernel as long as a multicast routing
daemon runs.  On Linux, multiple multicast routers can run simltaneously
using different multicast routing tables.


Features
--------

- Configuration file support, `/etc/smcroute.conf`
- Support for restarting and reloading the `.conf` on `SIGHUP`
- Source-less on-demand routing, a.k.a. (*,G) based static routing
- Optional built-in [mrdisc][] support, [RFC4286][]
- Support for multiple routing tables on Linux
- Client with built-in support to show routes and joined groups


Usage
-----

    smcrouted [-nNhsv] [-c SEC] [-d SEC] [-e CMD] [-f CONF] [-l LVL] [-p USER:GROUP] [-t ID]
    smcroutectl [-Fkhv] [COMMAND] [⟨add | rem⟩ ⟨ROUTE⟩] [⟨join | leave⟩ ⟨GROUP⟩]

To set multicast routes and join groups you must first start the daemon,
which needs *root privileges*, or `CAP_NET_ADMIN`.  Use `smcrouted -n`
to run the daemon in the foreground, as required by modern init daemons
like systemd and [Finit][].

By default `smcrouted` reads `/etc/smcroute.conf`, which can look
something like this:

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
TCP/IP stacks default to a TTL of 1 for multicast frames, e.g. ping
requires `-t 2`, or greater, for multicast.  This limitation reduces the
risk of accidentally flooding multicast.  Remember, multicast behaves
like broadcast unless limited.

### Action Scripts

    # smcrouted -e /path/to/script

With `-e CMD` a user script or command can be called when `smcrouted`
receives a `SIGHUP` or installs a multicast route to the kernel.  This
is useful if you, for instance, also run a NAT firewall and need to
flush connection tracking after installing a multicast route.

### Many Interfaces

    # smcrouted -N

With the `-N` command line option SMCRoute does *not* prepare all system
interfaces for multicast routing.  Very useful if your system has a lot
of interfaces but only a select few are required for multicast routing.
Use the following in `/etc/smcroute.conf` to enable interfaces:

    phyint eth0 enable
    phyint eth1 enable
    phyint eth2 enable

It is possible to use any interface that supports the `MULTICAST` flag.


### Multiple Routing Tables

On Linux it is possible to run multiple multicast routing daemons due to
its support for multiple multicast routing tables.  In such setups it
may be useful to change the default identity of SMCRoute:

    # smcrouted -I mrt1 -t 1
    # smcrouted -I mrt2 -t 2

The `-I NAME` option alters the default syslog name, config file, PID
file, and client socket file name used.  In the first instance above,
`smcrouted` will use:

- `/etc/mrt1.conf`
- `/var/run/mrt1.pid`
- `/var/run/mrt1.sock`

and syslog messages will use the `mrt1` identity as well.  Remember to
use the same `-I NAME` also to `smcroutectl`.


### Client Tool

SMCRoute also has a client interface to interact with the daemon:

    # smcroutectl join eth0 225.1.2.3
    # smcroutectl add  eth0 192.168.1.42 225.1.2.3 eth1 eth2

If the damon runs with a different identity the client needs to be
called using the same identity:

    # smcrouted   -I mrt
    # smcroutectl -I mrt show

There are more commands.  See the man page or the online help for
details:

    # smcroutectl help

**Note:** Root privileges are required by default for `smcroutectl` due
  to the IPC socket permissions.


Experimental
------------

Multicast often originates from different sources but usually not at the
same time.  For a more generic setup, and to reduce the number of rules
required, it is possible to set (*,G) IPv4 multicast routes.

Example `smcroute.conf`:

    phyint eth0 enable mrdisc
    phyint eth1 enable
    phyint eth1 enable
    
    mgroup from eth0 group 225.1.2.3
    mroute from eth0 group 225.1.2.3 to eth1 eth2

or, from the command line:

    # smcroutectl join eth0 225.1.2.3
    # smcroutectl add  eth0 225.1.2.3 eth1 eth2

Also, see the `smcrouted -c SEC` option for periodic flushing of learned
(*,G) rules, including the automatic blocking of unknown multicast, and
the `smcroutectl flush` command.

Another experimental feature is multicast router discovery, [mrdisc][],
described in [RFC4286][].  This feature is disabled by default, enable
with `configure --enable-mrdisc`.  When enabled it periodically sends
out an IGMP message on inbound interfaces¹ to alert switches to open up
multicast in that direction.  Not many managed switches have support for
this yet.

____  
¹ Notice the `mrdisc` flag to the above `phyint eth0` directive, which
is missing for `eth1` and `eth2`.


Build & Install
---------------

SMCRoute should in theory work on any UNIX like operating system which
supports the BSD MROUTING API.  Both Linux and FreeBSD are tested on a
regular basis.

### Linux Requirements

On Linux the following kernel config is required:

    CONFIG_IP_MROUTE=y
    CONFIG_IP_PIMSM_V1=y
    CONFIG_IP_PIMSM_V2=y
    CONFIG_IP_MROUTE_MULTIPLE_TABLES=y       # For multiple routing tables
    CONFIG_IPV6_MROUTE_MULTIPLE_TABLES=y     # For multiple routing tables

### *BSD Requirements

On *BSD the following kernel config is required:

    options    MROUTING    # Multicast routing
    options    PIM         # pimd extensions used for (*,G) support

### General Requirements

Check the list of multicast capable interfaces:

    cat /proc/net/dev_mcast

or look for interfaces with the `MULTICAST` flag in the output from:

    ifconfig

Some interfaces have the `MULTICAST` flag disabled by default, like `lo`
and `greN`.  Usually this flag can be enabled administratively.

### Configure & Build

As of SMCRoute v2.2, the `libcap` library is used to gain full privilege
separation using POSIX capabilities.  At startup this library is used to
drop full root privileges, retaining only `CAP_NET_ADMIN` for managing
the multicast routes.  Use `--without-libcap` to disable this feature.

**Note:** On RHEL/CentOS 6 you must `configure --without-libcap`

    $ ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
    $ make -j5
    $ sudo make install-strip

### Integration with systemd

For systemd integration you need to install `pkg-config`, which helps
the SMCRoute build system figure out the systemd paths.  When installed
simply call `systemctl` to enable and start `smcrouted`:

    $ sudo systemctl enable smcroute.service
    $ sudo systemctl start smcroute.service

Check that it started properly by inspecting the system log, or:

    $ sudo systemctl status smcroute.service

### Static Build

Some people want to build statically, to do this with autoconf add the
following `LDFLAGS=` *after* the configure script.  You may also need to
add `LIBS=...`, which will depend on your particular system:

    $ ./configure LDFLAGS="-static" ...

### Building from GIT

The `configure` script and the `Makefile.in` files are generated and not
stored in GIT.  So if you checkout the sources from GitHub you first
need to generated these files using `./autogen.sh`.


Origin & References
-------------------

SMCRoute is maintained collaboratively at [GitHub][].  Bug reports,
feature requests, patches/pull requests, and documentation fixes are
most welcome.  The project was previously hosted and maintained by
Debian at [Alioth][] and before that by [Carsten Schill][], the original
author.


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
