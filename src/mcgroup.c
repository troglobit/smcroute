/* Multicast group management (join/leave) API
 *
 * Copyright (C) 2001-2005  Carsten Schill <carsten@cschill.de>
 * Copyright (C) 2006-2009  Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2009       Todd Hayton <todd.hayton@gmail.com>
 * Copyright (C) 2009-2011  Micha Lenk <micha@debian.org>
 * Copyright (C) 2011-2020  Joachim Wiberg <troglobit@gmail.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#ifdef HAVE_LINUX_FILTER_H
#include <linux/filter.h>
#endif

#include "log.h"
#include "ipc.h"
#include "util.h"
#include "ifvc.h"
#include "socket.h"
#include "mcgroup.h"

extern int kern_join_leave(int sd, int cmd, struct mcgroup *mcg);

/*
 * Track IGMP join, any-source and source specific
 */
LIST_HEAD(, mgroup) mgroup_static_list = LIST_HEAD_INITIALIZER();
LIST_HEAD(, mcgroup) mcgroup_conf_list = LIST_HEAD_INITIALIZER();

static int mcgroup4_socket = -1;
static int mcgroup6_socket = -1;

#ifdef HAVE_LINUX_FILTER_H
/*
 * Extremely simple "drop everything" filter for Linux so we do not get
 * a copy each packet of every routed group we join.
 */
static struct sock_filter filter[] = {
	{ 0x6, 0, 0, 0x00000000 },
};

static struct sock_fprog fprog = {
	sizeof(filter) / sizeof(filter[0]),
	filter
};
#endif /* HAVE_LINUX_FILTER_H */


static struct iface *match_valid_iface(const char *ifname, struct ifmatch *state)
{
	struct iface *iface = iface_match_by_name(ifname, state);

	if (!iface && !state->match_count)
		smclog(LOG_DEBUG, "unknown interface %s", ifname);

	return iface;
}

static void list_add(struct iface *iface, inet_addr_t *source, inet_addr_t *group, int len)
{
	struct mgroup *entry;

	entry = malloc(sizeof(*entry));
	if (!entry) {
		smclog(LOG_ERR, "Failed adding mgroup to list: %s", strerror(errno));
		return;
	}

	memset(entry, 0, sizeof(*entry));
	entry->iface   = iface;
	entry->source  = *source;
	entry->group   = *group;
	entry->len     = len;

	LIST_INSERT_HEAD(&mgroup_static_list, entry, link);
}

static void list_rem(struct iface *iface, inet_addr_t *source, inet_addr_t *group, int len)
{
	struct mgroup *entry, *tmp;

	LIST_FOREACH_SAFE(entry, &mgroup_static_list, link, tmp) {
		if (entry->iface->ifindex != iface->ifindex)
			continue;

		if (inet_addr_cmp(&entry->source, source) ||
		    inet_addr_cmp(&entry->group, group)   ||
		    entry->len != len)
			continue;

		LIST_REMOVE(entry, link);
		free(entry);
	}
}

static void mcgroup_init(void)
{
	if (mcgroup4_socket < 0) {
		mcgroup4_socket = socket_create(AF_INET, SOCK_DGRAM, 0, NULL, NULL);
		if (mcgroup4_socket < 0) {
			smclog(LOG_ERR, "failed creating IPv4 mcgroup socket: %s", strerror(errno));
			exit(255);
		}

#ifdef HAVE_LINUX_FILTER_H
		if (setsockopt(mcgroup4_socket, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
			smclog(LOG_WARNING, "failed setting IPv4 socket filter, continuing anyway");
#endif
	}

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (mcgroup6_socket < 0) {
		mcgroup6_socket = socket_create(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, NULL, NULL);
		if (mcgroup6_socket < 0) {
			smclog(LOG_WARNING, "failed creating IPv6 mcgroup socket: %s", strerror(errno));
			return;
		}

#ifdef HAVE_LINUX_FILTER_H
		if (setsockopt(mcgroup6_socket, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
			smclog(LOG_WARNING, "failed setting IPv6 socket filter, continuing anyway");
#endif
	}
#endif
}

/*
 * Close IPv4/IPv6 multicast sockets to kernel to leave any joined groups
 */
void mcgroup_exit(void)
{
	struct mcgroup *centry, *ctmp;
	struct mgroup *entry, *tmp;

	if (mcgroup4_socket != -1) {
		socket_close(mcgroup4_socket);
		mcgroup4_socket = -1;
	}

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (mcgroup6_socket != -1) {
		socket_close(mcgroup6_socket);
		mcgroup6_socket = -1;
	}
#endif

	LIST_FOREACH_SAFE(centry, &mcgroup_conf_list, link, ctmp) {
		LIST_REMOVE(centry, link);
		free(centry);
	}
	LIST_FOREACH_SAFE(entry, &mgroup_static_list, link, tmp) {
		LIST_REMOVE(entry, link);
		free(entry);
	}
}

static struct mcgroup *find_conf(const char *ifname, inet_addr_t *source, inet_addr_t *group, int len)
{
	struct mcgroup *entry, *tmp;

	LIST_FOREACH_SAFE(entry, &mcgroup_conf_list, link, tmp) {
		if (strcmp(entry->ifname, ifname))
			continue;
		if (inet_addr_cmp(&entry->source, source))
			continue;
		if (inet_addr_cmp(&entry->group, group) || entry->len != len)
			continue;

		return entry;
	}

	return NULL;
}

int mcgroup_action(int cmd, const char *ifname, inet_addr_t *source, inet_addr_t *group, int len)
{
	struct mcgroup *mcg;
	struct ifmatch state;
	int rc = 0;
	int sd;

	mcg = find_conf(ifname, source, group, len);
	if (mcg) {
		if (cmd == 'j') {
			errno = EALREADY;
			return 1;
		}
	} else {
		if (cmd != 'j') {
			errno = ENOENT;
			return 1;
		}

		mcg = calloc(1, sizeof(*mcg));
		if (!mcg)
			return 1;

		strlcpy(mcg->ifname, ifname, sizeof(mcg->ifname));
		mcg->source  = *source;
		mcg->group   = *group;
		mcg->len     = len;

		LIST_INSERT_HEAD(&mcgroup_conf_list, mcg, link);
	}

	mcgroup_init();
#ifdef HAVE_IPV6_MULTICAST_HOST
	if (group->ss_family == AF_INET6)
		sd = mcgroup6_socket;
	else
#endif
		sd = mcgroup4_socket;

	iface_match_init(&state);
	while ((mcg->iface = match_valid_iface(ifname, &state))) {
		if (kern_join_leave(sd, cmd, mcg)) {
			rc++;
			continue;
		}

		if (cmd == 'j')
			list_add(mcg->iface, source, group, len);
		else
			list_rem(mcg->iface, source, group, len);
	}

	if (cmd != 'j') {
		LIST_REMOVE(mcg, link);
		free(mcg);
	}

	if (!state.match_count)
		return 1;

	return rc;
}

#ifdef ENABLE_CLIENT
/* Write all joined IGMP/MLD groups to client socket */
int mcgroup_show(int sd, int detail)
{
	struct mcgroup *entry;
	char buf[256];
	char sg[INET_ADDRSTR_LEN * 2 + 5 + 3];
 
	LIST_FOREACH(entry, &mcgroup_conf_list, link) {
		struct iface *iface;
		char src[INET_ADDRSTR_LEN] = "*";
		char grp[INET_ADDRSTR_LEN];

		iface = iface_find_by_name(entry->ifname);
		if (!iface)
			continue;

		if (!is_anyaddr(&entry->source))
			inet_addr2str(&entry->source, src, sizeof(src));
		inet_addr2str(&entry->group, grp, sizeof(grp));

		if (entry->len > 0)
			snprintf(sg, sizeof(sg), "(%s, %s/%d)", src, grp, entry->len);
		else
			snprintf(sg, sizeof(sg), "(%s, %s)", src, grp);
		snprintf(buf, sizeof(buf), "%-46s %s\n", sg, iface->name);

		if (ipc_send(sd, buf, strlen(buf)) < 0) {
			smclog(LOG_ERR, "Failed sending reply to client: %s", strerror(errno));
			return -1;
		}
	}

	if (detail) {
		/* XXX: Show all from mgroup_static_list as well */
	}

	return 0;
}
#endif

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
