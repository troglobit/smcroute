/* Generic kernel multicast routing API for Linux and *BSD
 *
 * Copyright (C) 2001-2005  Carsten Schill <carsten@cschill.de>
 * Copyright (C) 2006-2009  Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2009       Todd Hayton <todd.hayton@gmail.com>
 * Copyright (C) 2009-2011  Micha Lenk <micha@debian.org>
 * Copyright (C) 2011-2021  Joachim Wiberg <troglobit@gmail.com>
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
#include <stdio.h>		/* snprintf() */
#include <netinet/ip.h>
#include <unistd.h>
#include <time.h>

#include "log.h"
#include "iface.h"
#include "ipc.h"
#include "script.h"
#include "mrdisc.h"
#include "mroute.h"
#include "kern.h"
#include "timer.h"
#include "util.h"

/*
 * Cache flush timeout, used for learned S in (*,G) that stop xmit
 */
static int cache_timeout = 0;

/*
 * User added/configured (*,G) matched on-demand at runtime.  See
 * mroute4_dyn_list for the (S,G) routes set from this "template".
 */
LIST_HEAD(, mroute) mroute_asm_conf_list = LIST_HEAD_INITIALIZER();

/*
 * Dynamically, on-demand, set (S,G) routes.  Tracks if the user
 * removes a configured (*,G) route.
 */
LIST_HEAD(, mroute) mroute_asm_kern_list = LIST_HEAD_INITIALIZER();

/*
 * Tracks regular static routes, mostly for 'smcroutectl show'
 */
LIST_HEAD(, mroute) mroute_ssm_list = LIST_HEAD_INITIALIZER();

static int  mroute4_add_vif    (struct iface *iface);
static int  mroute_dyn_add     (struct mroute *route);
static int  is_match           (struct mroute *rule, struct mroute *cand);
static int  is_exact_match     (struct mroute *rule, struct mroute *cand);

/* Check for kernel IGMPMSG_NOCACHE for (*,G) hits. I.e., source-less routes. */
static void handle_nocache4(int sd, void *arg)
{
	char origin[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];
	struct mroute mroute = { 0 };
	struct igmpmsg *im;
	struct iface *iface;
	struct ip *ip;
	char tmp[128];
	int result;

	(void)arg;
	result = read(sd, tmp, sizeof(tmp));
	if (result < 0) {
		smclog(LOG_WARNING, "Failed reading IGMP message from kernel: %s", strerror(errno));
		return;
	}

	ip = (struct ip *)tmp;

	/* Basic validation, filter out non igmpmsg */
	im = (struct igmpmsg *)tmp;
	if (im->im_mbz != 0 || im->im_msgtype == 0)
		return;

	/* packets sent up from kernel to daemon have ip->ip_p = 0 */
	if (ip->ip_p != 0)
		return;

	inet_addr_set(&mroute.source, &im->im_src);
	inet_addr_set(&mroute.group, &im->im_dst);
	mroute.inbound = im->im_vif;
	mroute.len     = 0;
	mroute.src_len = 0;

	inet_addr2str(&mroute.source, origin, sizeof(origin));
	inet_addr2str(&mroute.group, group, sizeof(group));

	iface = iface_find_by_inbound(&mroute);
	if (!iface) {
		smclog(LOG_WARNING, "No matching interface for VIF %u, cannot handle IGMP message %d.",
		       mroute.inbound, im->im_msgtype);
		return;
	}

	/* check for IGMPMSG_NOCACHE to do (*,G) based routing. */
	switch (im->im_msgtype) {
	case IGMPMSG_NOCACHE:
		/* Find any matching route for this group on that iif. */
		smclog(LOG_DEBUG, "New multicast data from %s to group %s on VIF %u",
		       origin, group, mroute.inbound);

		result = mroute_dyn_add(&mroute);
		if (result) {
			/*
			 * This is a common error, the router receives streams it is not
			 * set up to route -- we ignore these by default, but if the user
			 * sets a more permissive log level we help out by showing what
			 * is going on.
			 */
			if (ENOENT == errno)
				smclog(LOG_INFO, "Multicast from %s, group %s, on %s does not match any (*,G) rule",
				       origin, group, iface->ifname);
			return;
		}

		script_exec(&mroute);
		break;

	case IGMPMSG_WRONGVIF:
		smclog(LOG_WARNING, "Multicast from %s, group %s, coming in on wrong VIF %u, iface %s",
		       origin, group, mroute.inbound, iface->ifname);
		break;

	case IGMPMSG_WHOLEPKT:
#ifdef IGMPMSG_WRVIFWHOLE
	case IGMPMSG_WRVIFWHOLE:
#endif
		smclog(LOG_WARNING, "Receiving PIM register data from %s, group %s", origin, group);
		break;

	default:
		smclog(LOG_DEBUG, "Unknown IGMP message %d from kernel", im->im_msgtype);
		break;
	}
}

static void cache_flush(void *arg)
{
	(void)arg;

	smclog(LOG_INFO, "Cache timeout, flushing unused IPv4 (*,G) routes!");
	mroute_expire(cache_timeout);
}

/**
 * mroute4_enable - Initialise IPv4 multicast routing
 *
 * Setup the kernel IPv4 multicast routing API and lock the multicast
 * routing socket to this program (only!).
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
static int mroute4_enable(int do_vifs, int table_id)
{
	struct iface *iface;

	if (kern_mroute_init(table_id, handle_nocache4, NULL)) {
		switch (errno) {
		case ENOPROTOOPT:
			smclog(LOG_WARNING, "Kernel does not even support IGMP, skipping ...");
			break;

		case EPROTONOSUPPORT:
			smclog(LOG_ERR, "Cannot set IPv4 multicast routing table id: %s", strerror(errno));
			smclog(LOG_ERR, "Make sure your kernel has CONFIG_IP_MROUTE_MULTIPLE_TABLES=y");
			break;

		case EADDRINUSE:
			smclog(LOG_ERR, "IPv4 multicast routing API already in use: %s",
			       strerror(errno));
			break;

		case EOPNOTSUPP:
			smclog(LOG_ERR, "Kernel does not support IPv4 multicast routing, skipping ...");
			break;

		default:
			smclog(LOG_ERR, "Failed initializing IPv4 multicast routing API: %s",
			       strerror(errno));
			break;
		}

		return 1;
	}

	/* Create virtual interfaces (VIFs) for all IFF_MULTICAST interfaces */
	if (do_vifs) {
		for (iface = iface_iterator(1); iface; iface = iface_iterator(0))
			mroute4_add_vif(iface);
	}

	return 0;
}

/**
 * mroute4_disable - Disable IPv4 multicast routing
 *
 * Disable IPv4 multicast routing and release kernel routing socket.
 */
static void mroute4_disable(void)
{
	struct mroute *entry, *tmp;

	if (kern_mroute_exit())
		return;

	/* Free list of (*,G) routes on SIGHUP */
	LIST_FOREACH_SAFE(entry, &mroute_asm_conf_list, link, tmp) {
		LIST_REMOVE(entry, link);
		free(entry);
	}
	LIST_FOREACH_SAFE(entry, &mroute_asm_kern_list, link, tmp) {
		LIST_REMOVE(entry, link);
		free(entry);
	}
	LIST_FOREACH_SAFE(entry, &mroute_ssm_list, link, tmp) {
		LIST_REMOVE(entry, link);
		free(entry);
	}
}


/* Create a virtual interface from @iface so it can be used for IPv4 multicast routing. */
static int mroute4_add_vif(struct iface *iface)
{
	if (kern_vif_add(iface)) {
		switch (errno) {
		case ENOPROTOOPT:
			smclog(LOG_INFO, "Interface %s is not multicast capable, skipping VIF.",
			       iface->ifname);
			return -1;

		case EAGAIN:
			smclog(LOG_DEBUG, "No IPv4 multicast socket");
			return -1;

		case ENOMEM:
			smclog(LOG_WARNING, "Not enough available VIFs to create %s", iface->ifname);
			return 1;

		case EEXIST:
			smclog(LOG_DEBUG, "Interface %s already has VIF %d.", iface->ifname, iface->vif);
			return 0;

		default:
			break;
		}

		smclog(LOG_DEBUG, "Failed creating VIF for %s: %s", iface->ifname, strerror(errno));
		return -1;
	}

	if (iface->mrdisc)
		return mrdisc_register(iface->ifname, iface->vif);

	return 0;
}

static int mroute4_del_vif(struct iface *iface)
{
	if (iface->mrdisc)
		return mrdisc_deregister(iface->vif);

	if (kern_vif_del(iface) && errno != ENOENT) {
		smclog(LOG_ERR, "Failed deleting VIF for iface %s: %s", iface->ifname, strerror(errno));
		return -1;
	}
	iface->vif = -1;

	return 0;
}

/*
 * Used for exact (S,G) matching
 */
static int is_exact_match4(struct mroute *a, struct mroute *b)
{
	if (!inet_addr_cmp(&a->source, &b->source) &&
	    !inet_addr_cmp(&a->group,  &b->group)  &&
	    a->len     == b->len &&
	    a->inbound == b->inbound)
		return 1;

	return 0;
}

/*
 * Used for (*,G) matches
 *
 * The incoming candidate is compared to the configured rule, e.g.
 * does 225.1.2.3 fall inside 225.0.0.0/8?  => Yes
 * does 225.1.2.3 fall inside 225.0.0.0/15? => Yes
 * does 225.1.2.3 fall inside 225.0.0.0/16? => No
 */
static int is_match4(struct mroute *rule, struct mroute *cand)
{
	struct in_addr *addr1, *addr2;
	inet_addr_t a, b;
	uint32_t mask;
	int rc = 0;

	if (rule->inbound != cand->inbound)
		return rc;

	if (rule->len > 0)
		mask = 0xFFFFFFFFu << (32 - rule->len);
	else
		mask = 0xFFFFFFFFu;
	mask = htonl(mask);

	a = rule->group;
	b = cand->group;

	addr1 = inet_addr_get(&a);
	addr2 = inet_addr_get(&b);
	addr1->s_addr &= mask;
	addr2->s_addr &= mask;

	rc = !inet_addr_cmp(&a, &b);
	if (is_anyaddr(&rule->source))
		return rc;

	if (rule->src_len > 0)
		mask = 0xFFFFFFFFu << (32 - rule->src_len);
	else
		mask = 0xFFFFFFFFu;
	mask = htonl(mask);

	a = rule->source;
	b = cand->source;

	addr1 = inet_addr_get(&a);
	addr2 = inet_addr_get(&b);
	addr1->s_addr &= mask;
	addr2->s_addr &= mask;
	rc &= !inet_addr_cmp(&a, &b);

	return rc;
}

static int is_mroute_static(struct mroute *route)
{
	return !is_anyaddr(&route->source) && route->src_len == 0 && route->len == 0;
}

static int is_active(struct mroute *route)
{
	size_t i;

	for (i = 0; i < NELEMS(route->ttl); i++) {
		if (route->ttl[i])
			return 1;
	}

	return 0;
}

/*
 * Get valid packet usage statistics (i.e. number of actually forwarded
 * packets) from the kernel for an installed MFC entry
 */
static unsigned long get_valid_pkt(struct mroute *route)
{
	struct mroute_stats ms = { 0 };

	if (kern_stats(route, &ms))
		return 0;

	return ms.ms_pktcnt - ms.ms_wrong_if;
}

/**
 * mroute_expire - Expire dynamically added (*,G) routes
 * @max_idle: Timeout for routes in seconds, 0 to expire all dynamic routes
 *
 * This function flushes all (*,G) routes which haven't been used (i.e. no
 * packets matching them have been forwarded) in the last max_idle seconds.
 * It is called periodically on cache-timeout or on request of smcroutectl.
 * The latter is useful in case of topology changes (e.g. VRRP fail-over)
 * or similar.
 */
void mroute_expire(int max_idle)
{
	struct mroute *entry, *tmp;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	LIST_FOREACH_SAFE(entry, &mroute_asm_kern_list, link, tmp) {
		if (!entry->last_use) {
			/* New entry */
			entry->last_use = now.tv_sec;
			entry->valid_pkt = get_valid_pkt(entry);
		}

		if (entry->last_use + max_idle <= now.tv_sec) {
			unsigned long valid_pkt;

			valid_pkt = get_valid_pkt(entry);
			if (valid_pkt != entry->valid_pkt) {
				/* Used since last check, update */
				entry->last_use = now.tv_sec;
				entry->valid_pkt = valid_pkt;
				continue;
			}

			/* Not used, expire */
			kern_mroute_del(entry, is_active(entry));
			LIST_REMOVE(entry, link);
			free(entry);
		}
	}
}

/* find any existing route, with matching inbound interface */
static struct mroute *mroute_find(struct mroute *route)
{
	struct mroute *entry;

	LIST_FOREACH(entry, &mroute_asm_conf_list, link) {
		if (is_match(entry, route))
			return entry;
	}
	LIST_FOREACH(entry, &mroute_ssm_list, link) {
		if (is_match(entry, route))
			return entry;
	}

	return NULL;
}

/* Matching (S,G) but S has moved interface -- L3 topology change */
static struct mroute *mroute_source_moved(struct mroute *route)
{
	struct mroute *entry;

	LIST_FOREACH(entry, &mroute_ssm_list, link) {
		if (!inet_addr_cmp(&entry->source, &route->source) &&
		    !inet_addr_cmp(&entry->group, &route->group) &&
		    entry->len     == route->len &&
		    entry->src_len == route->src_len)
			return entry;
	}

	return NULL;
}

/**
 * mroute_add_route - Add route to kernel, or save a wildcard route for later use
 * @route: Pointer to multicast route to add
 *
 * Adds the given multicast @route to the kernel multicast routing table
 * unless it is ASM, i.e., a (*,G) route.  Those we save for and check
 * against at runtime when the kernel signals us.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute_add_route(struct mroute *route)
{
	struct mroute *entry;

	entry = mroute_find(route);
	if (entry) {
		size_t i;

		/* .conf: replace found entry with new outbounds */
		if (entry->unused) {
			for (i = 0; i < NELEMS(entry->ttl); i++)
				entry->ttl[i] = 0;
		}

		/* ipc: add any new outbound interafces */
		for (i = 0; i < NELEMS(entry->ttl); i++) {
			if (route->ttl[i])
				entry->ttl[i] = route->ttl[i];
		}

		entry->unused = 1;  /* don't add to below lists again */
	} else {
		/* ... (S,G) matches and inbound differs, then replace route */
		entry = mroute_source_moved(route);
		if (entry) {
			kern_mroute_del(entry, is_active(entry));
			LIST_REMOVE(entry, link);
			free(entry);
		}

		entry = calloc(1, sizeof(struct mroute));
		if (!entry) {
			smclog(LOG_WARNING, "Cannot add multicast route: %s", strerror(errno));
			return 1;
		}

		memcpy(entry, route, sizeof(struct mroute));
	}

	/*
	 * For (*,G) we save to a linked list to be added on-demand when
	 * the kernel sends IGMPMSG_NOCACHE.
	 */
	if (!is_mroute_static(entry)) {
		struct mroute *dyn, *tmp;

		if (!entry->unused)
			LIST_INSERT_HEAD(&mroute_asm_conf_list, entry, link);
		entry->unused = 0;	/* unmark from reload */

		/* Also, immediately expire any currently blocked traffic */
		LIST_FOREACH_SAFE(dyn, &mroute_asm_kern_list, link, tmp) {
			if (!is_active(dyn) && is_match(entry, dyn)) {
				char origin[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];
				struct iface *ifdyn;

				inet_addr2str(&dyn->group, group, sizeof(group));
				inet_addr2str(&dyn->source, origin, sizeof(origin));
				ifdyn = iface_find_by_inbound(dyn);
				smclog(LOG_DEBUG, "Flushing (%s,%s) on %s, new matching (*,G) rule ...",
				       origin, group, ifdyn ? ifdyn->ifname : "UNKNOWN");

				kern_mroute_del(dyn, 0);
				LIST_REMOVE(dyn, link);
				free(dyn);
			}
		}

		return 0;
	}

	if (!entry->unused)
		LIST_INSERT_HEAD(&mroute_ssm_list, entry, link);
	entry->unused = 0;	/* unmark from reload */

	return kern_mroute_add(entry, 1);
}

/* Remove from kernel and linked list */
static int do_mroute_del(struct mroute *entry)
{
	int ret;

	ret = kern_mroute_del(entry, is_active(entry));
	if (ret && ENOENT != errno)
		return ret;

	/* Also remove on ENOENT */
	LIST_REMOVE(entry, link);
	free(entry);

	return ret;
}

/*
 * We get here when called by `smcroutectl del`, not from .conf parser.
 * Removes one or more outbound interfaces from an active route, or if
 * no interfaces are given, remove the route.  The former is useful to
 * be able to remove all outbound interfaces from a route, and thus
 * block an (S,G) pair.  Similar to how add works.
 */
static int do_mroute_del_outbound(struct mroute *entry, struct mroute *route)
{
	size_t i, num = 0;

	/* remove any listed interafces */
	for (i = 0; i < NELEMS(entry->ttl); i++) {
		if (!route->ttl[i])
			continue;

		entry->ttl[i] = 0;
		num++;
	}

	/* if no outbound in route => remove route altogether */
	if (!num)
		return do_mroute_del(entry);

	return kern_mroute_add(entry, 1);
}

/**
 * mroute_del_route - Remove route from kernel, or all matching routes if wildcard
 * @route: Pointer to multicast route to remove
 *
 * Removes the given multicast @route from the kernel multicast routing
 * table, or if the @route is a wildcard, then all matching kernel
 * routes are removed, as well as the wildcard.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute_del_route(struct mroute *route)
{
	struct mroute *entry, *set, *tmp;

	if (is_mroute_static(route)) {
		LIST_FOREACH_SAFE(entry, &mroute_ssm_list, link, tmp) {
			if (!is_exact_match(entry, route))
				continue;

			if (entry->unused)
				return do_mroute_del(entry);

			return do_mroute_del_outbound(entry, route);
		}

		/* Not found in static list, check if spawned from a (*,G) rule. */
		LIST_FOREACH_SAFE(entry, &mroute_asm_kern_list, link, tmp) {
			if (!is_exact_match(entry, route))
				continue;

			if (entry->unused)
				return do_mroute_del(entry);

			return do_mroute_del_outbound(entry, route);
		}

		smclog(LOG_NOTICE, "Cannot delete multicast route: not found");
		errno = ENOENT;
		return -1;
	}

	/* Find matching (*,G) ... and interface .. and prefix length. */
	LIST_FOREACH_SAFE(entry, &mroute_asm_conf_list, link, tmp) {
		int ret = 0;

		if (!is_match(entry, route) || entry->len != route->len ||
		    entry->src_len != route->src_len)
			continue;

		/* Remove all (S,G) routes spawned from the (*,G) as well ... */
		LIST_FOREACH_SAFE(set, &mroute_asm_kern_list, link, tmp) {
			if (!is_match(entry, set) || entry->len != route->len)
				continue;

			if (entry->unused)
				ret += do_mroute_del(set);
			else
				ret += do_mroute_del_outbound(set, route);
		}

		if (!ret && entry->unused) {
			LIST_REMOVE(entry, link);
			free(entry);
		}

		return ret;
	}

	smclog(LOG_NOTICE, "Cannot delete multicast route: not found");
	errno = ENOENT;
	return -1;
}

#ifdef HAVE_IPV6_MULTICAST_ROUTING
static int mroute6_add_mif(struct iface *iface);

/*
 * Receive and drop ICMPv6 stuff. This is either MLD packets or upcall
 * messages sent up from the kernel.
 *
 * XXX: Currently MRT6MSG_NOCACHE messages for IPv6 (*,G) is unsupported.
 */
static void handle_nocache6(int sd, void *arg)
{
	char origin[INET_ADDRSTR_LEN], group[INET_ADDRSTR_LEN];
	struct mroute mroute = { 0 };
	struct mrt6msg *im6;
	struct iface *iface;
	char tmp[128];
	int result;

	(void)arg;
	result = read(sd, tmp, sizeof(tmp));
	if (result < 0) {
		smclog(LOG_INFO, "Failed clearing MLD message from kernel: %s", strerror(errno));
		return;
	}

	/*
	 * Basic input validation, filter out all non-mrt messages (e.g.
	 * our join for each group).  The mrt6msg struct is overlayed on
	 * the MLD header, so the im6_mbz field (must-be-zero) is the
	 * MLD type, e.g. 143, and im6_msgtype is the MLD code for an
	 * MLDv2 Join.
	 */
	im6 = (struct mrt6msg *)tmp;
	if (im6->im6_mbz != 0 || im6->im6_msgtype == 0)
		return;

	inet_addr6_set(&mroute.source, &im6->im6_src);
	inet_addr6_set(&mroute.group, &im6->im6_dst);
	mroute.inbound = im6->im6_mif;
	mroute.len     = 0;
	mroute.src_len = 0;

	inet_addr2str(&mroute.source, origin, sizeof(origin));
	inet_addr2str(&mroute.group, group, sizeof(group));

	iface = iface_find_by_inbound(&mroute);
	if (!iface) {
		smclog(LOG_WARNING, "No matching interface for VIF %u, cannot handle MRT6MSG %u:%u. "
		       "Multicast source %s, dest %s", mroute.inbound, im6->im6_mbz, im6->im6_msgtype,
		       origin, group);
		return;
	}

	switch (im6->im6_msgtype) {
	case MRT6MSG_NOCACHE:
		smclog(LOG_DEBUG, "New multicast data from %s to group %s on VIF %u",
		       origin, group, mroute.inbound);

		/* Find any matching route for this group on that iif. */
		result = mroute_dyn_add(&mroute);
		if (result) {
			/*
			 * This is a common error, the router receives streams it is not
			 * set up to route -- we ignore these by default, but if the user
			 * sets a more permissive log level we help out by showing what
			 * is going on.
			 */
			if (ENOENT == errno)
				smclog(LOG_INFO, "Multicast from %s, group %s, on %s does not match any (*,G) rule",
				       origin, group, iface->ifname);
			return;
		}

		script_exec(&mroute);
		break;

	case MRT6MSG_WRONGMIF:
		smclog(LOG_WARNING, "Multicast from %s, group %s, coming in on wrong MIF %u, iface %s",
		       origin, group, mroute.inbound, iface->ifname);
		break;

	case MRT6MSG_WHOLEPKT:
		smclog(LOG_WARNING, "Receiving PIM6 register data from %s, group %s", origin, group);
		break;

	default:
		smclog(LOG_DEBUG, "Unknown MRT6MSG %u from kernel", im6->im6_msgtype);
		break;
	}
}
#endif /* HAVE_IPV6_MULTICAST_ROUTING */

/**
 * mroute6_enable - Initialise IPv6 multicast routing
 *
 * Setup the kernel IPv6 multicast routing API and lock the multicast
 * routing socket to this program (only!).
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
static int mroute6_enable(int do_vifs, int table_id)
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
	(void)do_vifs;
	(void)table_id;
#else
	struct iface *iface;

	if (kern_mroute6_init(table_id, handle_nocache6, NULL)) {
		switch (errno) {
		case ENOPROTOOPT:
			smclog(LOG_WARNING, "Kernel does not even support IPv6 ICMP, skipping ...");
			break;

		case EPROTONOSUPPORT:
			smclog(LOG_ERR, "Cannot set IPv6 multicast routing table id: %s",
			       strerror(errno));
			smclog(LOG_ERR, "Make sure your kernel has CONFIG_IPV6_MROUTE_MULTIPLE_TABLES=y");
			break;

		case EADDRINUSE:
			smclog(LOG_ERR, "IPv6 multicast routing API already in use: %s",
			       strerror(errno));
			break;

		case EOPNOTSUPP:
			smclog(LOG_ERR, "Kernel does not support IPv6 multicast routing, skipping ...");
			break;

		default:
			smclog(LOG_ERR, "Failed initializing IPv6 multicast routing API: %s",
			       strerror(errno));
			break;
		}

		return 1;
	}

	/* Create virtual interfaces, IPv6 MIFs, for all IFF_MULTICAST interfaces */
	if (do_vifs) {
		for (iface = iface_iterator(1); iface; iface = iface_iterator(0))
			mroute6_add_mif(iface);
	}

	return 0;
#endif /* HAVE_IPV6_MULTICAST_ROUTING */

	return -1;
}

/**
 * mroute6_disable - Disable IPv6 multicast routing
 *
 * Disable IPv6 multicast routing and release kernel routing socket.
 */
static void mroute6_disable(void)
{
#ifdef HAVE_IPV6_MULTICAST_ROUTING
	kern_mroute6_exit();
#endif
}

#ifdef HAVE_IPV6_MULTICAST_ROUTING
/* Create a virtual interface from @iface so it can be used for IPv6 multicast routing. */
static int mroute6_add_mif(struct iface *iface)
{
	if (kern_mif_add(iface)) {
		switch (errno) {
		case ENOPROTOOPT:
			smclog(LOG_INFO, "Interface %s is not multicast capable, skipping MIF.",
			       iface->ifname);
			return -1;

		case EAGAIN:
			smclog(LOG_DEBUG, "No IPv6 multicast socket");
			return -1;

		case ENOMEM:
			smclog(LOG_WARNING, "Not enough available MIFs to create %s", iface->ifname);
			return 1;

		case EEXIST:
			smclog(LOG_DEBUG, "Interface %s already has MIF %d.", iface->ifname, iface->mif);
			return 0;

		default:
			break;
		}

		smclog(LOG_DEBUG, "Failed creating MIF for %s: %s", iface->ifname, strerror(errno));

		return -1;
	}

	return 0;
}

static int mroute6_del_mif(struct iface *iface)
{
	if (kern_mif_del(iface) && errno != ENOENT) {
		smclog(LOG_ERR, "Failed deleting MIF for iface %s: %s", iface->ifname, strerror(errno));
		return -1;
	}
	iface->mif = -1;

	return 0;
}

/*
 * Used for exact (S,G) matching
 */
static int is_exact_match6(struct mroute *rule, struct mroute *cand)
{
	int result;

	result =  !inet_addr_cmp(&rule->group, &cand->group);
	result &= !inet_addr_cmp(&rule->source, &cand->source);

	return result;
}

/*
 * Used for (*,G) matches
 *
 * The incoming candidate is compared to the configured rule, e.g.
 * does ff05:bad1::1 fall inside ff05:bad0::/16? => Yes
 * does ff05:bad1::1 fall inside ff05:bad0::/31? => Yes
 * does ff05:bad1::1 fall inside ff05:bad0::/32? => No
 */
static int is_match6(struct mroute *rule, struct mroute *cand)
{
	int rc = 0;

	if (rule->inbound != cand->inbound)
		return rc;

	if (rule->len == 0 && cand->len == 0)
		rc = !inet_addr_cmp(&rule->group, &cand->group);
	else
		/* TODO: Match based on prefix length */
		rc = 1;

	if (rule->src_len > 0 && cand->src_len > 0)
		rc &= !inet_addr_cmp(&rule->source, &cand->source);

	return rc;
}
#endif /* HAVE_IPV6_MULTICAST_ROUTING */

static int is_match(struct mroute *rule, struct mroute *cand)
{
	if (rule->group.ss_family != cand->group.ss_family)
		return 0;
#ifdef HAVE_IPV6_MULTICAST_ROUTING
	if (rule->group.ss_family == AF_INET6)
		return is_match6(rule, cand);
#endif
	return is_match4(rule, cand);
}

static int is_exact_match(struct mroute *rule, struct mroute *cand)
{
	if (rule->group.ss_family != cand->group.ss_family)
		return 0;
#ifdef HAVE_IPV6_MULTICAST_ROUTING
	if (rule->group.ss_family == AF_INET6)
		return is_exact_match6(rule, cand);
#endif
	return is_exact_match4(rule, cand);
}

/**
 * mroute_dyn_add - Add route to kernel if it matches a known (*,G) route.
 * @route: Pointer to candidate multicast route
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
static int mroute_dyn_add(struct mroute *route)
{
	struct mroute *entry, *new_entry;
	int ret;

	LIST_FOREACH(entry, &mroute_asm_conf_list, link) {
		/* Find matching (*,G) ... and interface. */
		if (!is_match(entry, route))
			continue;

		/* Use configured template (*,G) outbound interfaces. */
		memcpy(route->ttl, entry->ttl, NELEMS(route->ttl) * sizeof(route->ttl[0]));
		break;
	}

	if (!entry) {
		/*
		 * No match, add entry without outbound interfaces
		 * nevertheless to avoid continuous cache misses from
		 * the kernel. Note that this still gets reported as an
		 * error (ENOENT) below.
		 */
		memset(route->ttl, 0, NELEMS(route->ttl) * sizeof(route->ttl[0]));
	}

	ret = kern_mroute_add(route, entry ? 1 : 0);
	if (ret)
		return ret;

	/*
	 * Add to list of dynamically added routes. Necessary if the user
	 * removes the (*,G) using the command line interface rather than
	 * updating the conf file and SIGHUP. Note: if we fail to alloc()
	 * memory we don't do anything, just add kernel route silently.
	 */
	new_entry = malloc(sizeof(struct mroute));
	if (new_entry) {
		memcpy(new_entry, route, sizeof(struct mroute));
		LIST_INSERT_HEAD(&mroute_asm_kern_list, new_entry, link);
	}

	/* Signal to cache handler we've added a stop filter */
	if (!entry) {
		errno = ENOENT;
		return -1;
	}

	return 0;
}

int mroute_init(int do_vifs, int table_id, int cache_tmo)
{
	static int running = 0;

	LIST_INIT(&mroute_asm_conf_list);
	LIST_INIT(&mroute_asm_kern_list);
	LIST_INIT(&mroute_ssm_list);

	if (cache_tmo > 0 && !running) {
		running++;
		cache_timeout = cache_tmo;
		timer_add(cache_tmo, cache_flush, NULL);
	}

	return  mroute4_enable(do_vifs, table_id) ||
		mroute6_enable(do_vifs, table_id);
}

void mroute_exit(void)
{
	mroute4_disable();
	mroute6_disable();
}

/* Used by file parser to add VIFs/MIFs after setup */
int mroute_add_vif(char *ifname, uint8_t mrdisc, uint8_t threshold)
{
	struct ifmatch state;
	struct iface *iface;
	int ret = 0;

	iface_match_init(&state);
	while ((iface = iface_match_by_name(ifname, &state))) {
		smclog(LOG_DEBUG, "Creating/updating multicast VIF for %s", iface->ifname);
		iface->unused    = 0;
		iface->mrdisc    = mrdisc;
		iface->threshold = threshold;
		ret += mroute4_add_vif(iface);
#ifdef HAVE_IPV6_MULTICAST_ROUTING
		ret += mroute6_add_mif(iface);
#endif
	}

	if (!state.match_count)
		return 1;

	return ret;
}

/* Used by file parser to remove VIFs/MIFs after setup */
int mroute_del_vif(char *ifname)
{
	struct ifmatch state;
	struct iface *iface;
	int ret = 0;

	iface_match_init(&state);
	while ((iface = iface_match_by_name(ifname, &state))) {
		ret += mroute4_del_vif(iface);
#ifdef HAVE_IPV6_MULTICAST_ROUTING
		ret += mroute6_del_mif(iface);
#endif
	}

	if (!state.match_count)
		return 1;

	return ret;
}

/*
 * Called on SIGHUP/reload.  Mark all known configured routes as
 * 'unused', let mroute*_add() unmark and mroute_reload_end() take
 * care to remove routes that still have the 'unused' flag.
 */
void mroute_reload_beg(void)
{
	struct mroute *entry;
	struct iface *iface;
	int first = 1;

	LIST_FOREACH(entry, &mroute_ssm_list, link)
		entry->unused = 1;
	LIST_FOREACH(entry, &mroute_asm_kern_list, link)
		entry->unused = 1;
	LIST_FOREACH(entry, &mroute_asm_conf_list, link)
		entry->unused = 1;

	while ((iface = iface_iterator(first))) {
		first = 0;
		iface->unused = 1;
	}
}

void mroute_reload_end(void)
{
	struct mroute *entry, *tmp;
	struct iface *iface;
	int first = 1;

	LIST_FOREACH_SAFE(entry, &mroute_ssm_list, link, tmp) {
		if (entry->unused)
			mroute_del_route(entry);
	}
	LIST_FOREACH_SAFE(entry, &mroute_asm_kern_list, link, tmp) {
		if (entry->unused)
			mroute_del_route(entry);
	}
	LIST_FOREACH_SAFE(entry, &mroute_asm_conf_list, link, tmp) {
		if (entry->unused)
			mroute_del_route(entry);
	}

	while ((iface = iface_iterator(first))) {
		first = 0;
		if (iface->unused) {
			mroute_del_vif(iface->ifname);
			iface->unused = 0;
		}
	}
}

static int show_mroute(int sd, struct mroute *r, int detail)
{
	struct iface *iface;
	char src[INET_ADDRSTRLEN] = "*";
	char src_len[5] = "";
	char grp[INET_ADDRSTRLEN];
	char grp_len[5] = "";
	char sg[(INET_ADDRSTRLEN + 3) * 2 + 5];
	char buf[MAX_MC_VIFS * 17 + 80];

	if (!is_anyaddr(&r->source)) {
		inet_addr2str(&r->source, src, sizeof(src));
		if (r->src_len)
			snprintf(src_len, sizeof(src_len), "/%u", r->src_len);
	}
	inet_addr2str(&r->group, grp, sizeof(grp));
	if (r->len)
		snprintf(grp_len, sizeof(grp_len), "/%u", r->len);

	iface = iface_find_by_inbound(r);
	snprintf(sg, sizeof(sg), "(%s%s, %s%s)", src, src_len, grp, grp_len);
	snprintf(buf, sizeof(buf), "%-46s %-16s", sg, iface->ifname);

	if (detail) {
		struct mroute_stats ms = { 0 };
		char stats[30];

#ifdef HAVE_IPV6_MULTICAST_ROUTING
		if (r->group.ss_family == AF_INET6)
			kern_stats(r, &ms);
		else
#endif
		kern_stats(r, &ms);
		snprintf(stats, sizeof(stats), " %10lu %10lu ", ms.ms_pktcnt, ms.ms_bytecnt);
		strlcat(buf, stats, sizeof(buf));
	}

	iface = iface_outbound_iterator(r, 1);
	while (iface) {
		char tmp[22];

		snprintf(tmp, sizeof(tmp), " %s", iface->ifname);
		strlcat(buf, tmp, sizeof(buf));

		iface = iface_outbound_iterator(r, 0);
	}
	strlcat(buf, "\n", sizeof(buf));

	if (ipc_send(sd, buf, strlen(buf)) < 0) {
		smclog(LOG_ERR, "Failed sending reply to client: %s", strerror(errno));
		return -1;
	}

	return 0;
}

/* Write all (*,G) routes to client socket */
int mroute_show(int sd, int detail)
{
	struct mroute *r;

	LIST_FOREACH(r, &mroute_asm_conf_list, link) {
		if (show_mroute(sd, r, detail) < 0)
			return 1;
	}

	LIST_FOREACH(r, &mroute_asm_kern_list, link) {
		if (show_mroute(sd, r, detail) < 0)
			return 1;
	}

	LIST_FOREACH(r, &mroute_ssm_list, link) {
		if (show_mroute(sd, r, detail) < 0)
			return 1;
	}

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
