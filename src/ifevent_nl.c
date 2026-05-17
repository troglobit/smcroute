/* Linux netlink listener for interface arrival/removal events.
 *
 * Subscribes to RTNLGRP_LINK plus the IPv4/IPv6 address groups, refreshes
 * the iface list on any event, and drains the pending list so routes/
 * groups whose inbound interface just arrived install automatically.
 *
 * Copyright (C) 2026  Joachim Wiberg <troglobit@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "config.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "ifevent.h"
#include "iface.h"
#include "log.h"
#include "pending.h"
#include "socket.h"

static int nl_sd = -1;

static void nl_cb(int sd, void *arg)
{
	char buf[8192];
	ssize_t n;
	int got = 0;

	(void)arg;

	/* Drain whatever the kernel has queued; we don't parse the
	 * payload — being woken up is the only signal we need. */
	do {
		n = recv(sd, buf, sizeof(buf), MSG_DONTWAIT);
		if (n > 0)
			got = 1;
	} while (n > 0);

	if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		smclog(LOG_WARNING, "netlink recv: %s", strerror(errno));

	if (!got)
		return;

	iface_update();
	pending_drain();
}

void ifevent_init(void)
{
	struct sockaddr_nl addr = { 0 };
	int type = SOCK_RAW;

#ifdef HAVE_SOCK_CLOEXEC
	type |= SOCK_CLOEXEC;
#endif
	nl_sd = socket(AF_NETLINK, type, NETLINK_ROUTE);
	if (nl_sd < 0) {
		smclog(LOG_ERR, "Failed opening netlink socket: %s", strerror(errno));
		return;
	}

	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
	if (bind(nl_sd, (struct sockaddr *)&addr, sizeof(addr))) {
		smclog(LOG_ERR, "Failed binding netlink socket: %s", strerror(errno));
		close(nl_sd);
		nl_sd = -1;
		return;
	}

	socket_register(nl_sd, nl_cb, NULL);
}

void ifevent_exit(void)
{
	if (nl_sd < 0)
		return;
	socket_close(nl_sd);
	nl_sd = -1;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
