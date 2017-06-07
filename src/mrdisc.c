/* Multicast Router Discovery Protocol, RFC4286 (IPv4 only)
 *
 * Copyright (C) 2017  Joachim Nilsson <troglobit@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include "config.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>

#include "log.h"
#include "inet.h"
#include "mrdisc.h"
#include "queue.h"
#include "timer.h"
#include "util.h"

struct ifsock {
	LIST_ENTRY(ifsock) link;

	short  vif;
	size_t refcnt;

	int    sd;
	char  ifname[IFNAMSIZ + 1];
};

static uint8_t interval       = 20;
static LIST_HEAD(, ifsock) il = LIST_HEAD_INITIALIZER();


static struct ifsock *find(int sd)
{
	struct ifsock *entry;

	LIST_FOREACH(entry, &il, link) {
		if (entry->sd == sd)
			return entry;
	}

	return NULL;
}

static void announce(struct ifsock *entry)
{
	if (!entry)
		return;

	smclog(LOG_DEBUG, "Sending mrdisc announcement on %s", entry->ifname);
	if (inet_send(entry->sd, IGMP_MRDISC_ANNOUNCE, interval)) {
		if (ENETUNREACH == errno || ENETDOWN == errno)
			return;	/* Link down, ignore. */

		smclog(LOG_WARNING, "Failed sending IGMP control message 0x%x on %s, error %d: %s",
		       IGMP_MRDISC_ANNOUNCE, entry->ifname, errno, strerror(errno));
	}
}

int mrdisc_init(int period)
{
	interval = period;
	if (timer_add(interval, mrdisc_send, NULL) < 0) {
		smclog(LOG_ERR, "Failed starting mrdisc announcement timer.");
		return -1;
	}

	return 0;
}

int mrdisc_exit(void)
{
	struct ifsock *entry, *tmp;

	LIST_FOREACH_SAFE(entry, &il, link, tmp) {
		inet_close(entry->sd);
		LIST_REMOVE(entry, link);
		free(entry);
	}

	return 0;
}

/*
 * Register possible interface for mrdisc
 */
int mrdisc_register(char *ifname, short vif)
{
	struct ifsock *entry;

	LIST_FOREACH(entry, &il, link) {
		if (!strcmp(entry->ifname, ifname)) {
			errno = EEXIST;
			return -1;
		}
	}

	entry = malloc(sizeof(*entry));
	if (!entry)
		return -1;

	entry->refcnt = 0;
	entry->vif    = vif;
	entry->sd     = -1;
	strlcpy(entry->ifname, ifname, sizeof(entry->ifname));
	LIST_INSERT_HEAD(&il, entry, link);

	return 0;
}

/*
 * Unregister mrdisc interface, regardless of refcnt
 */
int mrdisc_deregister(short vif)
{
	struct ifsock *entry;

	LIST_FOREACH(entry, &il, link) {
		if (entry->vif == vif) {
			if (entry->refcnt)
				inet_close(entry->sd);
			LIST_REMOVE(entry, link);
			free(entry);
			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

/*
 * Enable multicast router discovery for inbound interface
 */
int mrdisc_enable(short vif)
{
	struct ifsock *entry;

	LIST_FOREACH(entry, &il, link) {
		if (entry->vif == vif) {
			if (entry->refcnt == 0) {
				entry->sd = inet_open(entry->ifname);
				if (entry->sd < 0)
					return -1;
				entry->refcnt++;
				announce(entry);
			}

			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

/*
 * Disable multicast router discovery for inbound interface
 */
int mrdisc_disable(short vif)
{
	struct ifsock *entry;

	LIST_FOREACH(entry, &il, link) {
		if (entry->vif == vif) {
			if (entry->refcnt > 0)
				entry->refcnt--;

			if (entry->refcnt == 0)
				inet_close(entry->sd);
			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

void mrdisc_send(void *arg)
{
	struct ifsock *entry;

	(void)arg;
	LIST_FOREACH(entry, &il, link) {
		if (entry->refcnt == 0) {
			smclog(LOG_DEBUG, "Skipping mrdisc on inactive %s", entry->ifname);
			continue;
		}

		announce(entry);
	}
}

void mrdisc_recv(int sd, void *arg)
{
	struct ifsock *entry;

	(void)arg;

	/* Verify we are reading from an active socket */
	entry = find(sd);
	if (!entry) {
		smclog(LOG_WARNING, "Bug in mrdisc, received frame on unknown socket %d", sd);
		return;
	}

	/* Only do a "dummy" read on inactive interfaces */
	if (inet_recv(sd, entry->refcnt ? interval : 0))
		smclog(LOG_WARNING, "Failed receiving IGMP control message from %s", entry->ifname);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
