SMCRoute - A static multicast route tool
========================================
[![Build Status](https://travis-ci.org/troglobit/smcroute.png?branch=master)](https://travis-ci.org/troglobit/smcroute)

SMCRoute is a command line tool to manipulate the multicast routes of a
UNIX kernel.  It supports both IPv4 and IPv6 multicast routing.

SMCRoute can be used as an alternative to dynamic multicast routers like
mrouted or pimd in setups where static multicast routes should be
maintained and/or no proper IGMP or MLD signaling exists.

Generally multicast routes exists in the kernel only as long as SMCRoute
or another multicast routing daemon is running.  Only one multicast
routing daemon can be active at a time, so it's impossible to run
SMCRoute and, e.g., mrouted at the same time.

SMCRoute is maintained at GitHub.  Previously the code has been hosted by
Debian at Alioth and before that by Carsten Schill, the original author.


Usage
-----

SMCRoute is both a daemon and a client.  You must start the daemon to be
able to setup multicast routes.

    # smcroute -d

By default SMCRoute looks for its configuration in `/etc/smcroute.conf`,
which can look something like this:

    mgroup from eth0 group 225.1.2.3
    mroute from eth0 group 225.1.2.3 source 192.168.1.42 to eth1 eth2

The first line means "Join multicast group 225.1.2.3 on interface eth0",
and is for layer-2 devices (switches) with IGMP snooping implemented to
open up multicast for that group to be flooded to us.

The second line is the actual layer-3 routing entry.  Here we say that
multicast data originating from 192.168.1.42 on eth0 to multicast group
225.1.2.3 should be routed to interfaces eth1 and eth2.

*Note:* To test the above you can use ping from another device.  The
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

    # smcroute -j eth0 225.1.2.3
    # smcroute -a eth0 192.168.1.42 225.1.2.3 eth1 eth2


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

    # smcroute -j eth0 225.1.2.3
    # smcroute -a eth0 0.0.0.0 225.1.2.3 eth1 eth2

Good Luck!
The SMCRoute Maintainers
