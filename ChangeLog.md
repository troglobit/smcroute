ChangeLog
=========

All notable changes to the project are documented in this file.


[v2.4.0][UNRELEASED] - 2017-08-xx
---------------------------------

### Changes
- Interface wildcard support, Linux `iptables` like syntax, `eth+`
  matches `eth0`, `eth1`, `eth32`.  It can be used where an interface
  name is used: `phyint`, `mroute`, `mgroup`, and even on the command
  line to `smcroutectl`.  Contributed by Martin Buck
- Disable IPv4 [mrdisc][] by default, enable per `phyint` in the `.conf`
  file instead.  When *not* started with `smcrouted -N` mrdisc would
  otherwise be enabled on *all* interfaces found at startup
- Minor doc updates, e.g. clarify need for root or `CAP_NET_ADMIN`
  including some minor man page fixes

### Fixes
- Fix #75: Not possible to remove (*,G) routes using `smcroutectl`
- Fix #76: When removing a kernel route, also remove from internal lists
  otherwise route is shown in `smcroutectl show`.  Conversely, adding a
  route to internal list shall only be done after successful kernel add
- Fix #77: Counter overflow due to wrong type used in `smcroutectl show`


[v2.3.1][] - 2017-06-13
-----------------------

Bug fix release courtesy of the Westermo WeOS automated testing
framework.  Many thanks to Johan Askerin at Westermo for working
on integrating SMCRoute v2.3 into WeOS v4.22!

### Changes
- Add `utimensat()` replacement for systems that don't have it
- Ignore error messages from `send()` on interface link down

### Fixes
- Fix build error(s) on FreeBSD 9/9.3-RELEASE
- Fix possible invalid interface name reference in new mrdisc support
- Fix log macro bug in the .conf parser
- Fix buggy interface and VIF re-initialization on `SIGHUP`


[v2.3.0][] - 2017-05-28
-----------------------

### Changes
- Support GROUP/LEN matching for IPv4 (*,G) routes
- Support for IPv4 [mrdisc][], [RFC4286][]
- Support for multiple routing tables on Linux, `-t ID`
- `ssmgroup` code folded into general code, now with optional source
- Separation of daemon and client into `smcrouted` and `smcroutectl`
  - Complete new client user interface, `smcroutectl`
  - Support for disabling IPC and client, `--disable-client`
  - Support for disabling `.conf` file support, `--disable-config`
- Show multicast routes and joined groups in client, including stats:
  `smcroutectl show [groups|routes]`
- Support for `-d SEC` startup delay in `smcrouted`
- Unknown (*,G) multicast now blocked by default
- Flush timer, `-c SEC`, for (*,G) routes now enabled by default, 60 sec
- Build ID removed from `configure` script
- Massive code cleanup, refactor and separation into stand-alone modules
- Default system paths are no longer taken from `/usr/include/paths.h`,
  instead the settings from `configure --prefix` are used
- Use of `libcap` for privilige separation is now auto-detected

### Fixes
- Allow use of loopback interface for multicast routes
- Fix IPv4-only build, by Martin Buck
- Fix IPv4 network interface address identification, by Martin Buck
- Support unlimited number of network interfaces, by Martin Buck


[v2.2.2][] - 2017-02-02
-----------------------

### Changes
- New client command, `-F`, for immediately flushing dynamically learned
  (*,G) routes from the cache.

### Fixes
- Fix issue #51: New cache flush timeout option causes endless
  `select()` loop.  Reported by Ramon Fried, @mellowcandle


[v2.2.1][] - 2017-01-09
-----------------------

### Changes
- Add support for a new command line option, `-c SEC`, for timing out
  dynamically learned (*,G) routes.  Issue #17

### Fixes
- Portability, replace use of non-std `__progname` with small function
- Issue #49: systemd unit file missing `-d` to start daemon


[v2.2.0][] - 2016-12-03
-----------------------

### Changes
- Support for dropping root privileges after opening the multicast
  routing socket and creating the PID file
- Support for Source Specific Multicast group subscription (only IPv4)
- Support for systemd, service file included and installed by default

### Fixes
- Remove GNUisms to be able to build and run on Alpine Linux (musl libc)
- Add OpenBSD `queue.h` for systems that do not have any *BSD `sys/queue.h`
- Coding style cleanup and minor refactor


[v2.1.1][] - 2016-08-19
-----------------------

### Changes
- When `SIGHUP` is received SMCRoute now touches its PID file as an
  acknowledgement.  This is used by some process supervision daemons,
  like [Finit](https://github.com/troglobit/finit), on system
  configuration changes to detect when a daemon is done.  The mtime is
  set using the `utimensat()` function to ensure nanosecond resolution.

### Fixes
- Fix issue #38: Minor memory leak at exit.  The Valgrind tool warns
  that all memory is not freed when smcroute exits.  On most modern
  UNIX systems, on platforms with MMU, this is not a problem, but on
  older systems, or uClinux, memory is not freed at program exit.
- Fix issue #39: Removing wildcard route at runtime does not work if no
  kernel routes have been set.
- Fix issue #44: IPv6 disabled by default, despite what `configure` says
  in its help text.  Enabling it disables it ... fixed by enabling IPv6
  by default.


[v2.1.0][] - 2016-02-17
-----------------------

### Changes
- Allow more interfaces to be used for multicast routing, in particular
  on Linux, where interfaces without an IP address can now be used!
  Making it possible to run SMCRoute on DHCP/PPP interaces, issue #13
- Add support for TTL scoping on interfaces, very useful for filtering
  multicast without a firewall: `phyint IFNAME ttl-threshold TTL`
- On Linux a socket filter now filters out ALL traffic on the helper
  sockets where SMCRoute does IGMP/MLD join/leave on multicast groups.
  This should eliminate the extra overhad required to, not only route
  streams, but also send a copy of each packet to SMCRoute.
- Add support for limiting the amount of multicast interfaces (VIFs)
  SMCRoute creates at startup.  Two options are now available, by
  default all multicast capable interfaces are given a VIF and the user
  can selectively disable them one by one.  However, if the `-N` command
  line option is given SMCRoute does *not* enable any VIFs by default,
  the user must then selectively enable interface one by one.  The
  syntax in the config file is:

        phyint IFNAME <enable|disable>

  Use `enable` per interface with `-N` option, or `disable` by default.

- Make build ID optional.  SMCRoute has always had the build date
  hard coded in the binary.  This change makes this optional, and
  defaults to disabled, to facilitate reproducible builds.  For
  more info, see https://wiki.debian.org/ReproducibleBuilds
- Remove generated files from GIT.  Files generated by GNU autotools are
  now only part of the distribution archive, not the GIT repository.
  Use `./autogen.sh` to create the required files when using GIT.
- Updated man page and example `smcroute.conf` with limitations on
  the amount of mgroup rules.
- Add support for executing an external script on config reload and when
  installing a multicast route.  Issue #14

        smcroute -e /path/to/cmd

  The script is called when SMCRoute has started up, or has received
  `SIGHUP` and just reloaded the configuration file, and when a new
  source-less rule have been installed.  See the documentation for
  more information on set environment variables etc.  Issue #14
- Add `--disable-ipv6` option to `configure` script.  Disables IPv6
  support in SMCRoute even though the kernel may support it
- Replaced `-D` option with `-L LVL` to alter log level, issue #24
- The smcroute daemon now behaves more like a regular UNIX daemon.  It
  defaults to using syslog when running in the background and stderr
  when running in the foreground.  A new option `-s` can be used to
  enable syslog when running in the foreground, issue #25
- The smcroute client no longer use syslog, only stderr, issue #25
- When starting the smcroute daemon it is no longer possible to also
  send client commands on the same command line.
- Remove the (unmaintained) in-tree `mcsender` tool.  Both ping(8) and
  iperf(1) can be used in its stead.  The omping(8) tool is another
  tool, engineered specifically for testing multicast.  Issue #30

### Fixes
- Fix issue #10: `smcroute` client loops forever on command if no
  `smcroute` daemon is running
- Install binaries to `/usr/sbin` rather than `/usr/bin`, regression
  introduced in [v2.0.0][].  Fixed by Micha Lenk
- Cleanup fix for no-MMU systems.  Multicast groups were not properly
  cleaned up in the `atexit()` handler -- *only* affects no-MMU systems.
- Do not force automake v1.11, only require *at least* v.11
- SMCRoute operates fine without a config file, so use a less obtrusive
  warning message for missing `/etc/smcroute.conf`


[v2.0.0][] - 2014-09-30
-----------------------

### Changes
- Migrate to full GNU Configure and Build system, add Makefile.am,
  GitHub issue #6 -- heads up, packagers!
- Add standard SysV init script, from Debian. GitHub issue #9

### Fixes
- Multiple fixes of nasty bugs thanks to Coverity static code analysis!
- Cleanup of Linux system anachronisms to make FreeBSD work again,
  GitHub issue #5


[v1.99.2][] - 2013-07-16
------------------------

### Fixes
* Fix issue #2: Loop forever bug when deleting new (*,G) sourceless routes
  Bug report and patch by Jean-Baptiste Maillet


[v1.99.1][] - 2013-07-11
------------------------

### Fixes
- Fix possible memory leak on Linux
- Fix missing #ifdefs when building on systems w/o IPv6
- Fix possible race in Makefile when building in (massive) parallel
- Fix build problems on RedHat EL5/CentOS5, i.e., Linux <= 2.6.25


[v1.99.0][] - 2012-05-13
-------------------------

### Changes
- Feature: Experimental source-less `(*,G)` IPv4 multicast routing.
  Most UNIX kernels are (S,G) based, i.e., you need to supply the
  source address with the multicast group to setup a kernel routing
  rule.  However, daemons like mrouted and pimd emulate `(*,G)` by
  listening for IGMPMSG_NOCACHE messages from the kernel. SMCRoute now
  also implements this, for IPv4 only atm, by placing all `(*,G)`
  routes in a list and adding matching (S,G) routes on-demand at
  runtime. All routes matching this (*,G) are removed when reloading
  the conf file on SIGHUP or when the user sends an IPC (-r) command to
  remove the (*,G) rule.

### Fixes
- Bugfix: SMCRoute segfaults when starting on interface that is up but
  has no valid IPv4 address yet.  Bug introduced in 1.98.3
- Improved error messages including some minor cleanup and readability
  improvements
- Bugfix: Actually check if running as root at startup


[v1.98.3][] - 2011-11-05
------------------------

### Changes
- Check for existence of `asprintf()` to `pidfile()` and add
  `-D_GNU_SOURCE` to `CPPFLAGS` using `AC_GNU_SOURCE` in `configure.ac`
- Cleanup IPv6 `#ifdefs` and replace `IN6_MULTICAST()` with standard
  `IN6_IS_ADDR_MULTICAST()`.  This commit cleans up a lot of the IPv6
  related `#ifdefs`, some minor function name refactoring and squash of
  some `_init` and `_enable` funcs into one for clarity and clearer
  error messages to the user

### Fixes
- Fixes FTBFS when host lacks IPv6 support.


[v1.98.1][] - 2011-11-05
------------------------

### Fixes
- Bugfix: Client failed to send commands to daemon.
- Bugfix: Several FTBFS fixed for GCC 4.6.x and -W -Wall


[v1.98.0][] - 2011-11-04
------------------------

SMCRoute2 Announced!

### Changes
- Feature: Support for `smcroute.conf` configuration file for daemon.
  Add support for reading multicast routes and multicast groups from a
  configuration file.

        mgroup from IFNAME group MCGROUP
        mroute from IFNAME source ADDRESS group MCGROUP to IFNAME [IFNAME ...]

  Both IPv4 and IPv6 address formats are supported
- Feature: Support for signals, reload conf file on `SIGHUP`
- Feature: Add -n switch to support running smcroute in foreground.
- Refactor: Insecure handling of pointers potentially outside array boundaries.
- Refactor: Major cleanup, reindent to Linux C-style, for improved maintainability.

### Fixes
- Bugfix: Invalid use of varargs in call to `snprintf()`, use
  `vsnprintf()` instead
- Bugfix: Invalid `MRouterFD6` fd crashes smcroute, always check for
  valid fd
- Bugfix: Several minor bugfixes; type mismatches and unused return
  values


[v0.95][] - 2011-08-08
----------------------

### Changes
- Feature request #313278: Added support for FreeBSD
  SMCRoute now builds and runs on FreeBSD kernels.  This was successfully
  tested with the FreeBSD port of Debian using FreeBSD 8.1.  Other BSD
  flavours or versions might work too.  Any feedback is appreciated.
  https://alioth.debian.org/tracker/index.php?func=detail&aid=313278
- Feature request #313190: Debug logging is now disabled by default. If you
  want to enable debug logging again, start the daemon with parameter '-D'.
  https://alioth.debian.org/tracker/index.php?func=detail&aid=313190


[v0.94.1][] - 2010-01-13
------------------------

### Fixes
- Bugfix: In case the kernel refuses write access to the file
  /proc/sys/net/ipv6/conf/all/mc_forwarding, don't let smcroute exit
  with an error, but proceed with normal operation without writing a
  "1" to this file.  Apparently newer Linux kernels take care for the
  correct content of this file automatically whenever the IPv6
  multicast routing API is initialized by a process.


[v0.94][] - 2009-11-01
----------------------

### Changes
- Added support for IPv6 multicast routing in smcroute. SMCRoute now
   supports addition and removal of IPv6 multicast routes. It will
   automatically detect which type of route to add or delete based
   on the type (IPv4/IPv6) of addresses provided for the add and
   remove commands.
- Added support for joins and leaves ('j'/'l') to IPv6 multicast groups.
- Added support for sending to IPv6 multicast addresses to mcsender tool.
- Added command line option to mcsender tool to allow user to specify the
   outgoing interface for datagrams sent.
- Added autoconf support for smcroute build.


v0.93 - UNRELEASED
------------------

### Fixes
- Fixed the "smcroute looses output interfaces" bug.
  Carsten Schill, 0.93 unreleased


v0.92 - July 2002
-----------------

### Changes
- Increased the number of supported interfaces
  The 16 interface limit of version 0.90 (interfaces as listed with
  ifconfig) was to small, especially when alias interfaces where
  defined.
  - up to 40 interfaces are no recognized by smcroute
  - this does not change the number of 'virtual interfaces' supported
    by the kernel (32)
  - not all interfaces recognized by smcroute (40) results in a
    'virtual interface' of the kernel (32)

### Fixes
- Fixed the 'mroute: pending queue full, dropping entries' error
  Smcroute 0.90 didn't care about the IGMP messages delivered to the
  UDP socket that establish the MC-Router API. After some time the
  queue for the sockets filled up and the 'pending queue full' message
  was send from the kernel. To my knowledge this didn't affect smcroute
  or the operating system.
  - version 0.92 reads the ICMP messages now from the UDP socket and
    logs them to syslog with daemon/debug
  - smcroute does no further processing of this messages


v0.9 - September 2001
---------------------

### Changes
* Added MC group join (-j) and leave (-l) functionality
  - the options enable/disable the sending of IGMP join messages for
    a multicast group on a specific interface
* Removed the '<OutputIntf> [<OutputIntf>] ...' for the '-r' option
  - they are not used by the kernel to identify the route to remove
  - smcroute will not complain about extra arguments for the '-r' option
    to stay compatible with releases <= 0.80
* Improved error handling for some typical error situations
* Added a test script (tst-smcroute.pl)
* Added a man page

### Fixes
* Fixed some minor bugs


v0.8 - August 2001
------------------

Initial public release by Carsten Schill.


[mrdisc]:     https://github.com/troglobit/mrdisc
[RFC4286]:    https://tools.ietf.org/html/rfc4286
[UNRELEASED]: https://github.com/troglobit/smcroute/compare/2.3.1...HEAD
[v2.4.0]:     https://github.com/troglobit/smcroute/compare/2.3.1...2.4.0
[v2.3.1]:     https://github.com/troglobit/smcroute/compare/2.3.0...2.3.1
[v2.3.0]:     https://github.com/troglobit/smcroute/compare/2.2.2...2.3.0
[v2.2.2]:     https://github.com/troglobit/smcroute/compare/2.2.1...2.2.2
[v2.2.1]:     https://github.com/troglobit/smcroute/compare/2.2.0...2.2.1
[v2.2.0]:     https://github.com/troglobit/smcroute/compare/2.1.1...2.2.0
[v2.1.1]:     https://github.com/troglobit/smcroute/compare/2.1.0...2.1.1
[v2.1.0]:     https://github.com/troglobit/smcroute/compare/2.0.0...2.1.0
[v2.0.0]:     https://github.com/troglobit/smcroute/compare/1.99.2...2.0.0
[v1.99.2]:    https://github.com/troglobit/smcroute/compare/1.99.1...1.99.2
[v1.99.1]:    https://github.com/troglobit/smcroute/compare/1.99.0...1.99.1
[v1.99.0]:    https://github.com/troglobit/smcroute/compare/1.98.3...1.99.0
[v1.98.3]:    https://github.com/troglobit/smcroute/compare/1.98.2...1.98.3
[v1.98.2]:    https://github.com/troglobit/smcroute/compare/1.98.1...1.98.2
[v1.98.1]:    https://github.com/troglobit/smcroute/compare/1.98.0...1.98.1
[v1.98.0]:    https://github.com/troglobit/smcroute/compare/0.95...1.98.0
[v0.95]:      https://github.com/troglobit/smcroute/compare/0.94.1...0.95
[v0.94.1]:    https://github.com/troglobit/smcroute/compare/0.94...0.94.1
[v0.94]:      https://github.com/troglobit/smcroute/compare/0.94.1...0.95
