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
#include "iface.h"
#include "socket.h"
#include "mcgroup.h"
#include "kern.h"

/*
 * Track IGMP join, any-source and source specific
 */
LIST_HEAD(, mcgroup) kern_list = LIST_HEAD_INITIALIZER();
LIST_HEAD(, mcgroup) conf_list = LIST_HEAD_INITIALIZER();

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

/* Linux net.ipv4.igmp_max_memberships defaults to 20 */
#define MAX_GROUPS 20

struct mc_sock {
	LIST_ENTRY(mc_sock) link;

	int family;			/* address family */
	int sd;				/* socket for join/leave ops */
	int cnt;			/* max 20 on linux */
};

LIST_HEAD(, mc_sock) mc_sock_list= LIST_HEAD_INITIALIZER();

static int alloc_mc_sock(int family)
{
	struct mc_sock *entry;

	LIST_FOREACH(entry, &mc_sock_list, link) {
		if (entry->cnt < MAX_GROUPS && entry->family == family)
			break;
	}

	if (!entry) {
#ifdef IP_MULTICAST_ALL
		int val = 0;
#endif
		entry = malloc(sizeof(struct mc_sock));
		if (!entry) {
			smclog(LOG_ERR, "Out of memory in %s()", __func__);
			return -1;
		}

		entry->family = family;
		entry->cnt = 0;
		entry->sd = socket_create(family, SOCK_DGRAM, 0, NULL, NULL);
		if (entry->sd == -1) {
			smclog(LOG_ERR, "Failed creating mc socket: %s", strerror(errno));
			free(entry);
			return -1;
		}

#ifdef HAVE_LINUX_FILTER_H
		if (setsockopt(entry->sd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
			smclog(LOG_WARNING, "failed setting IPv4 socket filter, continuing anyway");
#endif

#ifdef HAVE_IPV6_MULTICAST_HOST
		if (family == AF_INET6) {
#ifdef IPV6_MULTICAST_ALL
			if (setsockopt(entry->sd, SOL_SOCKET, IPV6_MULTICAST_ALL, &val, sizeof(val)))
				smclog(LOG_WARNING, "failed disabling IPV6_MULTICAST_ALL: %s", strerror(errno));
#endif
		} else
#endif

#ifdef IP_MULTICAST_ALL
		if (setsockopt(entry->sd, SOL_SOCKET, IP_MULTICAST_ALL, &val, sizeof(val)))
			smclog(LOG_WARNING, "failed disabling IP_MULTICAST_ALL: %s", strerror(errno));
#endif

		LIST_INSERT_HEAD(&mc_sock_list, entry, link);
	}

	entry->cnt++;

	return entry->sd;
}

static void free_mc_sock(int sd)
{
	struct mc_sock *entry, *tmp;

	LIST_FOREACH_SAFE(entry, &mc_sock_list, link, tmp) {
		if (entry->sd == sd)
			break;
	}

	if (entry) {
		if (--entry->cnt == 0) {
			LIST_REMOVE(entry, link);
			socket_close(entry->sd);
			free(entry);
		}
	}
}

static struct iface *match_valid_iface(const char *ifname, struct ifmatch *state)
{
	struct iface *iface = iface_match_by_name(ifname, state);

	if (!iface && !state->match_count)
		smclog(LOG_DEBUG, "unknown interface %s", ifname);

	return iface;
}

static void list_add(int sd, struct mcgroup *mcg)
{
	struct mcgroup *entry;

	entry = malloc(sizeof(*entry));
	if (!entry) {
		smclog(LOG_ERR, "Failed adding mgroup to list: %s", strerror(errno));
		return;
	}

	*entry = *mcg;
#if 0
	strlcpy(entry->ifname, iface->name, sizeof(entry->ifname));
	entry->iface   = iface;
	entry->source  = *source;
	entry->group   = *group;
	entry->len     = len;
#endif
	entry->sd      = sd;

	LIST_INSERT_HEAD(&kern_list, entry, link);
}

static void list_rem(int sd, struct mcgroup *mcg)
{
	struct mcgroup *entry, *tmp;

	(void)sd;
	LIST_FOREACH_SAFE(entry, &kern_list, link, tmp) {
		if (entry->iface->ifindex != mcg->iface->ifindex)
			continue;

		if (inet_addr_cmp(&entry->source, &mcg->source) ||
		    inet_addr_cmp(&entry->group, &mcg->group))
			continue;

		LIST_REMOVE(entry, link);
		free_mc_sock(entry->sd);
		free(entry);
	}
}

/*
 * Close IPv4/IPv6 multicast sockets to kernel to leave any joined groups
 */
void mcgroup_exit(void)
{
#if 0
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

	LIST_FOREACH_SAFE(centry, &conf_list, link, ctmp) {
		LIST_REMOVE(centry, link);
		free(centry);
	}
	LIST_FOREACH_SAFE(entry, &kern_list, link, tmp) {
		LIST_REMOVE(entry, link);
		free(entry);
	}
#endif
}

static struct mcgroup *find_conf(const char *ifname, inet_addr_t *source, inet_addr_t *group, int len)
{
	struct mcgroup *entry;

	LIST_FOREACH(entry, &conf_list, link) {
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

static struct mcgroup *find_kern(struct mcgroup *mcg)
{
	struct mcgroup *entry;

	LIST_FOREACH(entry, &kern_list, link) {
		if (strcmp(entry->ifname, mcg->ifname))
			continue;
		if (inet_addr_cmp(&entry->source, &mcg->source))
			continue;
		if (inet_addr_cmp(&entry->group, &mcg->group))
			continue;

		return entry;
	}

	return NULL;
}

int mcgroup_action(int cmd, const char *ifname, inet_addr_t *source, inet_addr_t *group, int len)
{
	char src[INET_ADDRSTR_LEN] = "*", grp[INET_ADDRSTR_LEN];
	struct mcgroup *mcg;
	struct ifmatch state;
	int rc = 0;
	int sd;

	if (!is_anyaddr(source))
		inet_addr2str(source, src, sizeof(src));
	inet_addr2str(group, grp, sizeof(grp));

	mcg = find_conf(ifname, source, group, len);
	if (mcg) {
		if (cmd) {
			smclog(LOG_INFO, "Already joined (%s,%s) on %s", src, grp, ifname);
			errno = EALREADY;
			return 1;
		}
	} else {
		if (!cmd) {
			smclog(LOG_INFO, "No group (%s,%s) on %s to leave", src, grp, ifname);
			errno = ENOENT;
			return 1;
		}

		mcg = calloc(1, sizeof(*mcg));
		if (!mcg) {
			smclog(LOG_ERR, "Out of memory to %s (%s,%s) on %s",
			       cmd ? "join" : "leave", src, grp, ifname);
			return 1;
		}

		strlcpy(mcg->ifname, ifname, sizeof(mcg->ifname));
		mcg->source  = *source;
		mcg->group   = *group;
		mcg->len     = len;

		LIST_INSERT_HEAD(&conf_list, mcg, link);
	}

	iface_match_init(&state);
	while ((mcg->iface = match_valid_iface(ifname, &state))) {
		uint32_t addr = 0, addr_max = 0;
		struct in_addr orig, next;

		if (mcg->group.ss_family == AF_INET) {
			int mask;

			if (mcg->len > 0)
				mask = 0xFFFFFFFFu << (32 - mcg->len);
			else
				mask = 0xFFFFFFFFu;

			orig = *inet_addr_get(&mcg->group);
			addr = ntohl(orig.s_addr) & mask;
			addr_max = addr | ~mask;
		}

		while (addr <= addr_max) {
			if (addr) {
				next.s_addr = htonl(addr);
				inet_addr_set(&mcg->group, &next);
			}
			addr++;

			if (!cmd) {
				struct mcgroup *kmcg;

				kmcg = find_kern(mcg);
				if (!kmcg)
					continue;

				sd = kmcg->sd;
			} else
				sd = alloc_mc_sock(group->ss_family);

			if (kern_join_leave(sd, cmd, mcg)) {
				if (cmd && errno == EADDRINUSE)
					continue; /* Already joined, ignore */

				rc++;
				break;
			}

			if (cmd)
				list_add(sd, mcg);
			else
				list_rem(sd, mcg);
		}

		if (addr && mcg->group.ss_family == AF_INET)
			inet_addr_set(&mcg->group, &orig);
	}

	if (!cmd) {
		LIST_REMOVE(mcg, link);
		free(mcg);
	}

	if (!state.match_count)
		return 1;

	return rc;
}

/* Write all joined IGMP/MLD groups to client socket */
int mcgroup_show(int sd, int detail)
{
	struct mcgroup *entry;
	char buf[256];
	char sg[INET_ADDRSTR_LEN * 2 + 5 + 3];
 
	LIST_FOREACH(entry, &conf_list, link) {
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
		/* XXX: Show all from kern_list as well */
	}

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
