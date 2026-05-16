Troubleshooting SMCRoute
========================

This file maps common error messages from `smcrouted` to their root
cause and recommended fix.  Run with `-l debug` for the most detailed
log output, but most of the messages below are visible at the default
log level.

`mroute: inbound X is not a known phyint`
-----------------------------------------

The interface `X` is not present in the kernel at the time `smcrouted`
read the configuration.

- **Cause:** the interface is created later than `smcrouted` starts
  (typical for WireGuard, 6LoWPAN, late-binding bridges, etc.).
- **Fix:** delay startup with `smcrouted -d SEC`, or send `SIGHUP` to
  the daemon (or `smcroutectl reload`) once the interface is up.

`mroute: inbound X is not multicast capable`
--------------------------------------------

The interface exists, but the kernel reports it without the
`IFF_MULTICAST` flag.

- **Cause:** the interface type does not support multicast (`dummy`
  without `multicast on`), or a bridge that has no forwarding ports
  yet, or a driver that masks the flag.
- **Fix:** verify with `ip -d link show X`.  For bridges, attach a port
  and ensure multicast snooping/flooding is configured correctly.  For
  `dummy` interfaces, `ip link set X multicast on`.

`mroute: inbound X has no VIF, VIF table exhausted?`
----------------------------------------------------

The interface is multicast capable but `smcrouted` could not allocate a
kernel VIF/MIF for it.  The kernel supports a fixed number of VIFs
(usually 32 on Linux).

- **Cause:** the host has more multicast-capable interfaces than the
  kernel can map.  By default `smcrouted` allocates a VIF for every
  multicast-capable interface, which exhausts the table before the
  configured `phyint` lines are reached.  Tracked in
  [#71](https://github.com/troglobit/smcroute/issues/71).
- **Fix:** start `smcrouted` with `-N` and list only the interfaces you
  actually need in `smcroute.conf`:

        phyint eth0 enable
        phyint eth1 enable

`IPv4 multicast routing API already in use`
-------------------------------------------

Only one process per network namespace and routing table can hold the
kernel multicast routing API.

- **Cause:** another multicast routing daemon (`igmpproxy`, `mcpd`,
  `pimd`, ...) is already running.  Reported on asuswrt-merlin in
  discussion [#201](https://github.com/troglobit/smcroute/discussions/201).
- **Fix:** stop the other daemon, or on Linux use a separate routing
  table with `smcrouted -t N`.

`mgroup from X matches no valid phyint, skipping ...`
-----------------------------------------------------

Same as the first entry above, but for an `mgroup` line.  Same fixes
apply.

Interfaces appear and disappear at runtime
------------------------------------------

`smcrouted` does not yet listen for kernel link events, so it will not
notice when an interface comes up after startup.  Workarounds:

- Use `-d SEC` to delay startup until interfaces are expected.
- Send `SIGHUP` (or run `smcroutectl reload`) from a script triggered
  by your network manager / `udev` / similar.

Native runtime re-enumeration is tracked in
[#55](https://github.com/troglobit/smcroute/issues/55).
