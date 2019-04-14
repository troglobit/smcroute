/* Generic kernel multicast routing API for Linux and *BSD
 *
 * Copyright (C) 2001-2005  Carsten Schill <carsten@cschill.de>
 * Copyright (C) 2006-2009  Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2009       Todd Hayton <todd.hayton@gmail.com>
 * Copyright (C) 2009-2011  Micha Lenk <micha@debian.org>
 * Copyright (C) 2011-2017  Joachim Nilsson <troglobit@gmail.com>
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
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <string.h>
#include <stdio.h>		/* snprintf() */
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>

#include "log.h"
#include "ifvc.h"
#include "ipc.h"
#include "script.h"
#include "socket.h"
#include "mrdisc.h"
#include "mroute.h"
#include "timer.h"
#include "util.h"

/* MAX_MC_VIFS from mroute.h must have same value as MAXVIFS from mroute.h */
#if MAX_MC_VIFS != MAXVIFS
#error "IPv4 constants do not match, 'mroute.h' needs to be fixed!"
#endif

#ifdef HAVE_IPV6_MULTICAST_ROUTING
/* MAX_MC_MIFS from mroute.h must have same value as MAXVIFS from mroute6.h */
#if MAX_MC_MIFS != MAXMIFS
#error "IPv6 constants do not match, 'mroute.h' needs to be fixed!"
#endif
#endif

/*
 * Cache flush timeout, used only for IPv4 (*,G) atm.
 */
static int cache_timeout = 0;

/*
 * Indicates whether or not the timer is running.
 */
static int running = 0;

/*
 * Raw IGMP socket used as interface for the IPv4 mrouted API.
 * Receives IGMP packets and upcall messages from the kernel.
 */
static int mroute4_socket = -1;

/*
 * User added/configured (*,G) matched on-demand at runtime.  See
 * mroute4_dyn_list for the (S,G) routes set from this "template".
 */
LIST_HEAD(, mroute4) mroute4_conf_list = LIST_HEAD_INITIALIZER();

/*
 * Dynamically, on-demand, set (S,G) routes.  Tracks if the user
 * removes a configured (*,G) route.
 */
LIST_HEAD(, mroute4) mroute4_dyn_list = LIST_HEAD_INITIALIZER();

/*
 * Tracks regular static routes, mostly for 'smcroutectl show'
 */
LIST_HEAD(, mroute4) mroute4_static_list = LIST_HEAD_INITIALIZER();

/* IPv4 internal virtual interfaces (VIF) descriptor vector */
static struct {
	struct iface *iface;
} vif_list[MAXVIFS];

static int mroute4_add_vif(struct iface *iface);

#ifdef HAVE_IPV6_MULTICAST_ROUTING
/*
 * Raw ICMPv6 socket used as interface for the IPv6 mrouted API.
 * Receives MLD packets and upcall messages from the kenrel.
 */
static int mroute6_socket = -1;

/*
 * User added/configured (*,G) matched on-demand at runtime.  See
 * mroute6_dyn_list for the (S,G) routes set from this "template".
 */
LIST_HEAD(, mroute6) mroute6_conf_list = LIST_HEAD_INITIALIZER();

/*
 * Dynamically, on-demand, set (S,G) routes.  Tracks if the user
 * removes a configured (*,G) route.
 */
LIST_HEAD(, mroute6) mroute6_dyn_list = LIST_HEAD_INITIALIZER();

/*
 * Tracks regular static routes, mostly for 'smcroutectl show'
 */
LIST_HEAD(, mroute6) mroute6_static_list = LIST_HEAD_INITIALIZER();

/* IPv6 internal virtual interfaces (VIF) descriptor vector */
static struct mif {
	struct iface *iface;
	uint16_t scope_mask;
} mif_list[MAXMIFS];

static int mroute6_add_mif(struct iface *iface);
static int get_stats6(struct mroute6 *route, unsigned long *pktcnt, unsigned long *bytecnt, unsigned long *wrong_if);
static unsigned long get_valid_pkt6(struct mroute6 *route);
static int is_match6(struct mroute6 *rule, struct mroute6 *cand);
static int is_exact_match6(struct mroute6 *a, struct mroute6 *b);
static int mroute6_exists(struct mroute6 *route);
static struct mroute6 *mroute6_similar(struct mroute6 *route);
static int is_mroute6_static(struct mroute6 *route);
static int is_active6(struct mroute6 *route);
static int kern_add6(struct mroute6 *route, int active);
static int do_mroute6_del(struct mroute6 *entry);
static int kern_del6(struct mroute6 *route, int active);
static int show_mroute6(int sd, struct mroute6 *r, int detail);
#endif

/* Check for kernel IGMPMSG_NOCACHE for (*,G) hits. I.e., source-less routes. */
static void handle_nocache4(int sd, void *arg)
{
	int result;
	char tmp[128];
	struct ip *ip;
	struct igmpmsg *igmpctl;

	(void)arg;
	memset(tmp, 0, sizeof(tmp));
	result = read(sd, tmp, sizeof(tmp));
	if (result < 0) {
		smclog(LOG_WARNING, "Failed reading IGMP message from kernel: %s", strerror(errno));
		return;
	}

	/* packets sent up from kernel to daemon have ip->ip_p = 0 */
	ip = (struct ip *)tmp;
	igmpctl = (struct igmpmsg *)tmp;

	/* Check for IGMPMSG_NOCACHE to do (*,G) based routing. */
	if (ip->ip_p == 0 && igmpctl->im_msgtype == IGMPMSG_NOCACHE) {
		struct iface *iface;
		struct mroute mrt;
		struct mroute4 mroute;
		char origin[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];

		memset(&mroute, 0, sizeof(mroute));
		mroute.group.s_addr  = igmpctl->im_dst.s_addr;
		mroute.source.s_addr = igmpctl->im_src.s_addr;
		mroute.inbound       = igmpctl->im_vif;

		inet_ntop(AF_INET, &mroute.group,  group,  INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &mroute.source, origin, INET_ADDRSTRLEN);
		smclog(LOG_DEBUG, "New multicast data from %s to group %s on VIF %d", origin, group, mroute.inbound);

		iface = iface_find_by_vif(mroute.inbound);
		if (!iface) {
			smclog(LOG_WARNING, "No matching interface for VIF %d, cannot add mroute.", mroute.inbound);
			return;
		}

		/* Find any matching route for this group on that iif. */
		result = mroute4_dyn_add(&mroute);
		if (result) {
			/*
			 * This is a common error, the router receives streams it is not
			 * set up to route -- we ignore these by default, but if the user
			 * sets a more permissive log level we help out by showing what
			 * is going on.
			 */
			if (ENOENT == errno)
				smclog(LOG_INFO, "Multicast from %s, group %s, on %s does not match any (*,G) rule",
				       origin, group, iface->name);
			return;
		}

		mrt.version = 4;
		mrt.u.mroute4 = mroute;
		script_exec(&mrt);
	}
}

static void cache_flush(void *arg)
{
	(void)arg;

	smclog(LOG_INFO, "Cache timeout, flushing unused (*,G) routes!");
	mroute4_dyn_expire(cache_timeout);

#ifdef HAVE_IPV6_MULTICAST_ROUTING
	mroute6_dyn_expire(cache_timeout);
#endif

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
int mroute4_enable(int do_vifs, int table_id, int timeout)
{
	int arg = 1;
	struct iface *iface;

	if (mroute4_socket < 0) {
		mroute4_socket = socket_create(AF_INET, SOCK_RAW, IPPROTO_IGMP, handle_nocache4, NULL);
		if (mroute4_socket < 0) {
			if (ENOPROTOOPT == errno)
				smclog(LOG_WARNING, "Kernel does not even support IGMP, skipping ...");

			return -1;
		}
	}

#ifdef MRT_TABLE /* Currently only available on Linux  */
	if (table_id != 0) {
		smclog(LOG_INFO, "Setting IPv4 multicast routing table id %d", table_id);
		if (setsockopt(mroute4_socket, IPPROTO_IP, MRT_TABLE, &table_id, sizeof(table_id)) < 0) {
			smclog(LOG_ERR, "Cannot set IPv4 multicast routing table id: %s", strerror(errno));
			smclog(LOG_ERR, "Make sure your kernel has CONFIG_IP_MROUTE_MULTIPLE_TABLES=y");
			goto error;
		}
	}
#else
	(void)table_id;
#endif

	if (setsockopt(mroute4_socket, IPPROTO_IP, MRT_INIT, (void *)&arg, sizeof(arg))) {
		switch (errno) {
		case EADDRINUSE:
			smclog(LOG_ERR, "IPv4 multicast routing API already in use: %s", strerror(errno));
			break;

		case EOPNOTSUPP:
			smclog(LOG_ERR, "Kernel does not support IPv4 multicast routing, skipping ...");
			break;

		default:
			smclog(LOG_ERR, "Failed initializing IPv4 multicast routing API: %s", strerror(errno));
			break;
		}

		goto error;
	}

	/* Initialize virtual interface table */
	memset(&vif_list, 0, sizeof(vif_list));

	/* Create virtual interfaces (VIFs) for all IFF_MULTICAST interfaces */
	if (do_vifs) {
		for (iface = iface_iterator(1); iface; iface = iface_iterator(0))
			mroute4_add_vif(iface);
	}

	LIST_INIT(&mroute4_conf_list);
	LIST_INIT(&mroute4_dyn_list);
	LIST_INIT(&mroute4_static_list);

	if (timeout && !running) {
		running++;
		cache_timeout = timeout;
		timer_add(timeout, cache_flush, NULL);
	}

	return 0;
error:
	socket_close(mroute4_socket);
	mroute4_socket = -1;

	return -1;
}

/**
 * mroute4_disable - Disable IPv4 multicast routing
 *
 * Disable IPv4 multicast routing and release kernel routing socket.
 */
void mroute4_disable(int close_socket)
{
	struct mroute4 *entry, *tmp;

	if (mroute4_socket < 0)
		return;

	/* Drop all kernel routes set by smcroute */
	if (setsockopt(mroute4_socket, IPPROTO_IP, MRT_DONE, NULL, 0))
		smclog(LOG_WARNING, "Failed shutting down IPv4 multicast routing socket: %s", strerror(errno));

	if (close_socket) {
		socket_close(mroute4_socket);
		mroute4_socket = -1;
	}

	/* Free list of (*,G) routes on SIGHUP */
	LIST_FOREACH_SAFE(entry, &mroute4_conf_list, link, tmp) {
		LIST_REMOVE(entry, link);
		free(entry);
	}
	LIST_FOREACH_SAFE(entry, &mroute4_dyn_list, link, tmp) {
		LIST_REMOVE(entry, link);
		free(entry);
	}
	LIST_FOREACH_SAFE(entry, &mroute4_static_list, link, tmp) {
		LIST_REMOVE(entry, link);
		free(entry);
	}
}


/* Create a virtual interface from @iface so it can be used for IPv4 multicast routing. */
static int mroute4_add_vif(struct iface *iface)
{
	struct vifctl vc;
	int vif = -1;
	size_t i;

	if (mroute4_socket < 0)
		return -1;

	if ((iface->flags & IFF_MULTICAST) != IFF_MULTICAST) {
		smclog(LOG_INFO, "Interface %s is not multicast capable, skipping VIF.", iface->name);
		iface->vif = -1;
		return 0;
	}

	/* find a free vif */
	for (i = 0; i < NELEMS(vif_list); i++) {
		if (!vif_list[i].iface) {
			vif = i;
			break;
		}
	}

	/* no more space */
	if (vif == -1) {
		errno = ENOMEM;
		smclog(LOG_WARNING, "Kernel MAXVIFS (%d) too small for number of interfaces: %s", MAXVIFS, strerror(errno));
		return 1;
	}

	memset(&vc, 0, sizeof(vc));
	vc.vifc_vifi = vif;
	vc.vifc_flags = 0;      /* no tunnel, no source routing, register ? */
	vc.vifc_threshold = iface->threshold;
	vc.vifc_rate_limit = 0;	/* hopefully no limit */
#ifdef VIFF_USE_IFINDEX		/* Register VIF using ifindex, not lcl_addr, since Linux 2.6.33 */
	vc.vifc_flags |= VIFF_USE_IFINDEX;
	vc.vifc_lcl_ifindex = iface->ifindex;
#else
	vc.vifc_lcl_addr.s_addr = iface->inaddr.s_addr;
#endif
	vc.vifc_rmt_addr.s_addr = htonl(INADDR_ANY);

	smclog(LOG_DEBUG, "Map iface %-16s => VIF %-2d ifindex %2d flags 0x%04x TTL threshold %u",
	       iface->name, vc.vifc_vifi, iface->ifindex, vc.vifc_flags, iface->threshold);

	if (setsockopt(mroute4_socket, IPPROTO_IP, MRT_ADD_VIF, (void *)&vc, sizeof(vc))) {
		smclog(LOG_ERR, "Failed adding VIF for iface %s: %s", iface->name, strerror(errno));
		iface->vif = -1;
		return 1;
	}

	iface->vif = vif;
	vif_list[vif].iface = iface;

	if (iface->mrdisc)
		return mrdisc_register(iface->name, vif);

	return 0;
}

static int mroute4_del_vif(struct iface *iface)
{
	int ret;
	int16_t vif = iface->vif;

	if (mroute4_socket < 0)
		return -1;

	if (-1 == vif)
		return 0;	/* No VIF setup for iface, skip */

	smclog(LOG_DEBUG, "Removing  %-16s => VIF %-2d", iface->name, vif);

#ifdef __linux__
	struct vifctl vc = { .vifc_vifi = vif };
	ret = setsockopt(mroute4_socket, IPPROTO_IP, MRT_DEL_VIF, (void *)&vc, sizeof(vc));
#else
	ret = setsockopt(mroute4_socket, IPPROTO_IP, MRT_DEL_VIF, (void *)&vif, sizeof(vif));
#endif
	if (ret)
		smclog(LOG_ERR, "Failed deleting VIF for iface %s: %s", iface->name, strerror(errno));
	else
		iface->vif = -1;

	if (iface->mrdisc)
		return mrdisc_deregister(vif);

	return 0;
}

/* Actually set in kernel - called by mroute4_add() and mroute4_check_add() */
static int kern_add4(struct mroute4 *route, int active)
{
	char origin[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];
	struct mfcctl mc;

	if (mroute4_socket < 0)
		return -1;

	memset(&mc, 0, sizeof(mc));

	mc.mfcc_origin = route->source;
	mc.mfcc_mcastgrp = route->group;
	mc.mfcc_parent = route->inbound;

	/* copy the TTL vector */
	if (sizeof(mc.mfcc_ttls[0]) != sizeof(route->ttl[0]) || NELEMS(mc.mfcc_ttls) != NELEMS(route->ttl)) {
		smclog(LOG_ERR, "Critical data type validation error in %s!", __FILE__);
		exit(255);
	}

	memcpy(mc.mfcc_ttls, route->ttl, NELEMS(mc.mfcc_ttls) * sizeof(mc.mfcc_ttls[0]));
	if (setsockopt(mroute4_socket, IPPROTO_IP, MRT_ADD_MFC, &mc, sizeof(mc))) {
		smclog(LOG_WARNING, "failed adding IPv4 multicast route: %s", strerror(errno));
		return 1;
	}

	if (active) {
		smclog(LOG_DEBUG, "Add %s -> %s from VIF %d",
		       inet_ntop(AF_INET, &mc.mfcc_origin,   origin, INET_ADDRSTRLEN),
		       inet_ntop(AF_INET, &mc.mfcc_mcastgrp, group,  INET_ADDRSTRLEN), mc.mfcc_parent);

		/* Only enable mrdisc for active routes, i.e. with outbound */
		mrdisc_enable(route->inbound);
	}

	return 0;
}

/* Actually remove from kernel - called by mroute4_del() */
static int kern_del4(struct mroute4 *route, int active)
{
	char origin[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];
	struct mfcctl mc;

	if (mroute4_socket < 0)
		return -1;

	memset(&mc, 0, sizeof(mc));
	mc.mfcc_origin = route->source;
	mc.mfcc_mcastgrp = route->group;
	if (setsockopt(mroute4_socket, IPPROTO_IP, MRT_DEL_MFC, &mc, sizeof(mc))) {
		if (ENOENT == errno)
			smclog(LOG_DEBUG, "failed removing multicast route, does not exist.");
		else
			smclog(LOG_DEBUG, "failed removing IPv4 multicast route: %s", strerror(errno));
		return 1;
	}

	if (active) {
		smclog(LOG_DEBUG, "Del %s -> %s",
		       inet_ntop(AF_INET, &mc.mfcc_origin,  origin, INET_ADDRSTRLEN),
		       inet_ntop(AF_INET, &mc.mfcc_mcastgrp, group, INET_ADDRSTRLEN));

		/* Only disable mrdisc for active routes. */
		mrdisc_disable(route->inbound);
	}

	return 0;
}

/*
 * Used for exact (S,G) matching
 */
static int is_exact_match4(struct mroute4 *a, struct mroute4 *b)
{
	if (a->source.s_addr == b->source.s_addr &&
	    a->group.s_addr  == b->group.s_addr  &&
	    a->len           == b->len &&
	    a->inbound       == b->inbound)
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
static int is_match4(struct mroute4 *rule, struct mroute4 *cand)
{
	uint32_t addr1, addr2, mask;
	int ret = 0;

	if (rule->inbound != cand->inbound)
		return 0;

	if (rule->len > 0)
		mask = 0xFFFFFFFFu << (32 - rule->len);
	else
		mask = 0xFFFFFFFFu;
	mask = htonl(mask);
	addr1 = rule->group.s_addr & mask;
	addr2 = cand->group.s_addr & mask;

	ret = (addr1 == addr2);

	if (!ret || rule->source.s_addr == htonl(INADDR_ANY)) {
		return ret;
	}

	if (rule->src_len > 0)
		mask = 0xFFFFFFFFu << (32 - rule->src_len);
	else
		mask = 0xFFFFFFFFu;
	mask = htonl(mask);
	addr1 = rule->source.s_addr & mask;
	addr2 = cand->source.s_addr & mask;

	return ret && (addr1 == addr2);
}

static int is_mroute4_static(struct mroute4 *route)
{
	return route->source.s_addr != htonl(INADDR_ANY) &&
	       route->src_len == 0 && route->len == 0;
}

/**
 * mroute4_dyn_add - Add route to kernel if it matches a known (*,G) route.
 * @route: Pointer to candidate struct mroute4 IPv4 multicast route
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute4_dyn_add(struct mroute4 *route)
{
	struct mroute4 *entry, *new_entry;
	int ret;

	LIST_FOREACH(entry, &mroute4_conf_list, link) {
		/* Find matching (*,G) ... and interface. */
		if (!is_match4(entry, route))
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

	ret = kern_add4(route, entry ? 1 : 0);
	if (ret)
		return ret;

	/*
	 * Add to list of dynamically added routes. Necessary if the user
	 * removes the (*,G) using the command line interface rather than
	 * updating the conf file and SIGHUP. Note: if we fail to alloc()
	 * memory we don't do anything, just add kernel route silently.
	 */
	new_entry = malloc(sizeof(struct mroute4));
	if (new_entry) {
		memcpy(new_entry, route, sizeof(struct mroute4));
		LIST_INSERT_HEAD(&mroute4_dyn_list, new_entry, link);
	}

	/* Signal to cache handler we've added a stop filter */
	if (!entry) {
		errno = ENOENT;
		return -1;
	}

	return 0;
}

/*
 * Query kernel for route usage statistics
 */
static int get_stats4(struct mroute4 *route, unsigned long *pktcnt, unsigned long *bytecnt, unsigned long *wrong_if)
{
	struct sioc_sg_req sg_req;

	if (mroute4_socket < 0)
		return -1;

	memset(&sg_req, 0, sizeof(sg_req));
	sg_req.src = route->source;
	sg_req.grp = route->group;

	if (ioctl(mroute4_socket, SIOCGETSGCNT, &sg_req) < 0) {
		if (wrong_if)
			smclog(LOG_WARNING, "Failed getting MFC stats: %s", strerror(errno));
		return errno;
	}

	if (pktcnt)
		*pktcnt = sg_req.pktcnt;
	if (bytecnt)
		*bytecnt = sg_req.bytecnt;
	if (wrong_if)
		*wrong_if = sg_req.wrong_if;

	return 0;
}

static int is_active4(struct mroute4 *route)
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
static unsigned long get_valid_pkt4(struct mroute4 *route)
{
	unsigned long pktcnt = 0, wrong_if = 0;

	if (get_stats4(route, &pktcnt, NULL, &wrong_if) < 0)
		return 0;

	return pktcnt - wrong_if;
}

/**
 * mroute4_dyn_expire - Expire dynamically added (*,G) routes
 * @max_idle: Timeout for routes in seconds, 0 to expire all dynamic routes
 *
 * This function flushes all (*,G) routes which haven't been used (i.e. no
 * packets matching them have been forwarded) in the last max_idle seconds.
 * It is called periodically on cache-timeout or on request of smcroutectl.
 * The latter is useful in case of topology changes (e.g. VRRP fail-over)
 * or similar.
 */
void mroute4_dyn_expire(int max_idle)
{
	struct mroute4 *entry, *tmp;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	LIST_FOREACH_SAFE(entry, &mroute4_dyn_list, link, tmp) {
		if (!entry->last_use) {
			/* New entry */
			entry->last_use = now.tv_sec;
			entry->valid_pkt = get_valid_pkt4(entry);
		}

		if (entry->last_use + max_idle <= now.tv_sec) {
			unsigned long valid_pkt;

			valid_pkt = get_valid_pkt4(entry);
			if (valid_pkt != entry->valid_pkt) {
				/* Used since last check, update */
				entry->last_use = now.tv_sec;
				entry->valid_pkt = valid_pkt;
				continue;
			}

			/* Not used, expire */
			kern_del4(entry, is_active4(entry));
			LIST_REMOVE(entry, link);
			free(entry);
		}
	}
}

static int mroute4_exists(struct mroute4 *route)
{
	struct mroute4 *entry;

	LIST_FOREACH(entry, &mroute4_conf_list, link) {
		if (is_match4(entry, route)) {
			smclog(LOG_INFO, "(*,G) route already exists");
			return 1;
		}
	}
	LIST_FOREACH(entry, &mroute4_static_list, link) {
		if (is_exact_match4(entry, route)) {
			smclog(LOG_INFO, "Static route already exists");
			return 1;
		}
	}

	return 0;
}

/* Only inbound differs, there can only be one ... */
static struct mroute4 *mroute4_similar(struct mroute4 *route)
{
	struct mroute4 *entry;

	LIST_FOREACH(entry, &mroute4_static_list, link) {
		if (entry->source.s_addr == route->source.s_addr &&
		    entry->group.s_addr  == route->group.s_addr  &&
		    entry->len           == route->len &&
		    entry->src_len       == route->src_len)
			return entry;
	}

	return NULL;
}

/**
 * mroute4_add - Add route to kernel, or save a wildcard route for later use
 * @route: Pointer to struct mroute4 IPv4 multicast route to add
 *
 * Adds the given multicast @route to the kernel multicast routing table
 * unless the source IP is %INADDR_ANY, i.e., a (*,G) route.  Those we
 * save for and check against at runtime when the kernel signals us.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute4_add(struct mroute4 *route)
{
	struct mroute4 *entry;

	/* Exact match, then skip ... */
	if (mroute4_exists(route)){
		errno = EEXIST;
		return 1;
	}

	/* ... (S,G) matches and inbound differs, then replace route */
	entry = mroute4_similar(route);
	if (entry) {
		kern_del4(entry, is_active4(entry));
		LIST_REMOVE(entry, link);
		free(entry);
	}

	entry = malloc(sizeof(struct mroute4));
	if (!entry) {
		smclog(LOG_WARNING, "Cannot add multicast route: %s", strerror(errno));
		return 1;
	}

	memcpy(entry, route, sizeof(struct mroute4));

	/*
	 * For (*,G) we save to a linked list to be added on-demand when
	 * the kernel sends IGMPMSG_NOCACHE.
	 */
	if (!is_mroute4_static(route)) {
		struct mroute4 *dyn, *tmp;

		LIST_INSERT_HEAD(&mroute4_conf_list, entry, link);

		/* Also, immediately expire any currently blocked traffic */
		LIST_FOREACH_SAFE(dyn, &mroute4_dyn_list, link, tmp) {
			if (!is_active4(dyn) && is_match4(entry, dyn)) {
				char origin[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];

				inet_ntop(AF_INET, &dyn->group,  group,  INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &dyn->source, origin, INET_ADDRSTRLEN);
				smclog(LOG_DEBUG, "Flushing (%s,%s) on VIF %d, new matching (*,G) rule ...",
				       origin, group, dyn->inbound);

				kern_del4(dyn, 0);
				LIST_REMOVE(dyn, link);
				free(dyn);
			}
		}

		return 0;
	}

	LIST_INSERT_HEAD(&mroute4_static_list, entry, link);
	return kern_add4(route, 1);
}

/* Remove from kernel and linked list */
static int do_mroute4_del(struct mroute4 *entry)
{
	int ret;

	ret = kern_del4(entry, is_active4(entry));
	if (ret && ENOENT != errno)
		return ret;

	/* Also remove on ENOENT */
	LIST_REMOVE(entry, link);
	free(entry);

	return ret;
}

/**
 * mroute4_del - Remove route from kernel, or all matching routes if wildcard
 * @route: Pointer to struct mroute4 IPv4 multicast route to remove
 *
 * Removes the given multicast @route from the kernel multicast routing
 * table, or if the @route is a wildcard, then all matching kernel
 * routes are removed, as well as the wildcard.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute4_del(struct mroute4 *route)
{
	struct mroute4 *entry, *set, *tmp;

	if (is_mroute4_static(route)) {
		LIST_FOREACH_SAFE(entry, &mroute4_static_list, link, tmp) {
			if (!is_exact_match4(entry, route))
				continue;

			return do_mroute4_del(entry);
		}

		/* Not found in static list, check if spawned from a (*,G) rule. */
		LIST_FOREACH_SAFE(entry, &mroute4_dyn_list, link, tmp) {
			if (!is_exact_match4(entry, route))
				continue;

			return do_mroute4_del(entry);
		}

		smclog(LOG_NOTICE, "Cannot delete multicast route: not found");
		errno = ENOENT;
		return -1;
	}

	/* Find matching (*,G) ... and interface .. and prefix length. */
	LIST_FOREACH_SAFE(entry, &mroute4_conf_list, link, tmp) {
		int ret = 0;

		if (!is_match4(entry, route) || entry->len != route->len ||
		    entry->src_len != route->src_len)
			continue;

		/* Remove all (S,G) routes spawned from the (*,G) as well ... */
		LIST_FOREACH_SAFE(set, &mroute4_dyn_list, link, tmp) {
			if (!is_match4(entry, set) || entry->len != route->len)
				continue;

			ret += do_mroute4_del(set);
		}

		if (!ret) {
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
#ifdef __linux__
#define IPV6_ALL_MC_FORWARD "/proc/sys/net/ipv6/conf/all/mc_forwarding"

static int proc_set_val(char *file, int val)
{
	int fd, result = 0;

	fd = open(file, O_WRONLY);
	if (fd < 0)
		return 1;

	if (-1 == write(fd, "1", val))
		result = 1;

	close(fd);

	return result;
}
#endif /* Linux only */

/*
 * Receive and drop ICMPv6 stuff. This is either MLD packets or upcall
 * messages sent up from the kernel.
 *
 * Done:Check for kernel IGMPMSG_NOCACHE for (*,G) hits. I.e., source-less routes.
 */
static void handle_nocache6(int sd, void *arg)
{
	int result;
	char tmp[128];

	(void)arg;
	result = read(sd, tmp, sizeof(tmp));
	if (result < 0)
		smclog(LOG_INFO, "Failed clearing MLD message from kernel: %s", strerror(errno));

	struct mrt6msg *msg = (struct mrt6msg *)tmp;
	if (msg->im6_msgtype == MRT6MSG_NOCACHE &&
		IN6_IS_ADDR_MULTICAST(&msg->im6_dst)) {
		struct mroute mrt;
		struct mroute6 route;
		struct iface *iface;
		char origin[INET6_ADDRSTRLEN], group[INET6_ADDRSTRLEN];

		memset(&route, 0, sizeof(route));

		route.source.sin6_addr = msg->im6_src;
		route.group.sin6_addr = msg->im6_dst;
		route.inbound = msg->im6_mif;
		route.src_len = 128;
		route.len = 128;
		inet_ntop(AF_INET6, &route.group.sin6_addr,  group,  INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &route.source.sin6_addr, origin, INET6_ADDRSTRLEN);
		smclog(LOG_DEBUG, "New multicast data from %s to group %s on MIF %d", origin, group, route.inbound);

		iface = iface_find_by_mif(route.inbound);
		if (!iface) {
			smclog(LOG_WARNING, "No matching interface for MIF %d, cannot add mroute.", route.inbound);
			return;
		}

		result = mroute6_dyn_add(&route);

		if (result) {
			/*
			 * This is a common error, the router receives streams it is not
			 * set up to route -- we ignore these by default, but if the user
			 * sets a more permissive log level we help out by showing what
			 * is going on.
			 */
			if (ENOENT == errno)
				smclog(LOG_INFO, "Multicast from %s, group %s, on %s does not match any (*,G) rule",
				       origin, group, iface->name);

			return;
		}

		mrt.version = 6;
		mrt.u.mroute6 = route;
		script_exec(&mrt);
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
int mroute6_enable(int do_mifs, int table_id, int timeout)
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
	(void)do_vifs;
	(void)table_id;
#else
	int arg = 1;
	struct iface *iface;

	if (mroute6_socket < 0) {
		mroute6_socket = socket_create(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, handle_nocache6, NULL);
		if (mroute6_socket < 0) {
			if (ENOPROTOOPT == errno)
				smclog(LOG_WARNING, "Kernel does not even support IPv6 ICMP, skipping ...");

			return -1;
		}
	}

#ifdef MRT6_TABLE /* Currently only available on Linux  */
	if (table_id != 0) {
		smclog(LOG_INFO, "Setting IPv6 multicast routing table id %d", table_id);
		if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_TABLE, &table_id, sizeof(table_id)) < 0) {
			smclog(LOG_ERR, "Cannot set IPv6 multicast routing table id: %s", strerror(errno));
			smclog(LOG_ERR, "Make sure your kernel has CONFIG_IPV6_MROUTE_MULTIPLE_TABLES=y");
			goto error;
		}
	}
#else
	(void)table_id;
#endif

	if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_INIT, (void *)&arg, sizeof(arg))) {
		switch (errno) {
		case EADDRINUSE:
			smclog(LOG_ERR, "IPv6 multicast routing API already in use: %s", strerror(errno));
			break;

		case EOPNOTSUPP:
			smclog(LOG_ERR, "Kernel does not support IPv6 multicast routing, skipping ...");
			break;

		default:
			smclog(LOG_ERR, "Failed initializing IPv6 multicast routing API: %s", strerror(errno));
			break;
		}

		goto error;
	}

	/* Initialize virtual interface table */
	memset(&mif_list, 0, sizeof(mif_list));

#ifdef __linux__
	/* On Linux pre 2.6.29 kernels net.ipv6.conf.all.mc_forwarding
	 * is not set on MRT6_INIT so we have to do this manually */
	if (proc_set_val(IPV6_ALL_MC_FORWARD, 1)) {
		if (errno != EACCES) {
			smclog(LOG_ERR, "Failed enabling IPv6 multicast forwarding: %s", strerror(errno));
			goto error;
		}
	}
#endif
	/* Create virtual interfaces, IPv6 MIFs, for all IFF_MULTICAST interfaces */
	if (do_mifs) {
		for (iface = iface_iterator(1); iface; iface = iface_iterator(0))
			mroute6_add_mif(iface);
	}

	if (timeout && !running) {
		running++;
		cache_timeout = timeout;
		timer_add(timeout, cache_flush, NULL);
	}

	return 0;
error:
	socket_close(mroute6_socket);
	mroute6_socket = -1;
#endif /* HAVE_IPV6_MULTICAST_ROUTING */

	return -1;
}

/**
 * mroute6_disable - Disable IPv6 multicast routing
 *
 * Disable IPv6 multicast routing and release kernel routing socket.
 */
void mroute6_disable(int close_socket)
{
#ifdef HAVE_IPV6_MULTICAST_ROUTING
	if (mroute6_socket < 0)
		return;

	if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_DONE, NULL, 0))
		smclog(LOG_WARNING, "Failed shutting down IPv6 multicast routing socket: %s", strerror(errno));

	if (close_socket) {
		socket_close(mroute6_socket);
		mroute6_socket = -1;
	}
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
}

#ifdef HAVE_IPV6_MULTICAST_ROUTING
static int show_mroute6(int sd, struct mroute6 *r, int detail)
{
	int mif;
	char src[INET6_ADDRSTRLEN] = "::";
	char src_len[6] = "";
	char grp[INET6_ADDRSTRLEN];
	char grp_len[6] = "";
	char mask[7] = "";
	char sg[INET6_ADDRSTRLEN + 5];
	char buf[MAX_MC_MIFS * 17 + 100];
	struct iface *i;

	inet_ntop(AF_INET6, &r->source.sin6_addr, src, sizeof(src));
	if (r->src_len && r->src_len != 128) {
		snprintf(src_len, sizeof(src_len), "/%u", r->src_len);
	}

	inet_ntop(AF_INET6, &r->group.sin6_addr, grp, sizeof(grp));
	if (r->len && r->len != 128) {
		snprintf(grp_len, sizeof(grp_len), "/%u", r->len);
	}

	i = iface_find_by_mif(r->inbound);

	if (IN6_IS_ADDR_ANY(&r->source.sin6_addr) &&
	   IN6_IS_ADDR_ANY(&r->group.sin6_addr))
	{
		snprintf(mask, sizeof(mask), "<%04X>", r->scope_mask);
	}

	snprintf(sg, sizeof(sg), "(%s%s, %s%s%s)", src, src_len, grp, grp_len, mask);
	snprintf(buf, sizeof(buf), "%-70s %-16s", sg, i->name);

	if (detail) {
		char stats[30];
		unsigned long p = 0, b = 0;

		get_stats6(r, &p, &b, NULL);
		snprintf(stats, sizeof(stats), " %10lu %10lu ", p, b);
		strlcat(buf, stats, sizeof(buf));
	}

	for (mif = 0; mif < MAX_MC_MIFS; mif++) {
		char tmp[22];

		if (r->ttl[mif] == 0)
			continue;

		i = iface_find_by_mif(mif);
		if (!i)
			continue;

		snprintf(tmp, sizeof(tmp), " %s", i->name);
		strlcat(buf, tmp, sizeof(buf));
	}

	strlcat(buf, "\n", sizeof(buf));

	if (ipc_send(sd, buf, strlen(buf)) < 0) {
		smclog(LOG_ERR, "Failed sending reply to client: %s", strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * Query kernel for route usage statistics
 */
static int get_stats6(struct mroute6 *route, unsigned long *pktcnt, unsigned long *bytecnt, unsigned long *wrong_if)
{
	struct sioc_sg_req6 sg_req;

	if (mroute6_socket < 0)
		return -1;

	memset(&sg_req, 0, sizeof(sg_req));
	sg_req.src = route->source;
	sg_req.grp = route->group;

	if (ioctl(mroute6_socket, SIOCGETSGCNT_IN6, &sg_req) < 0) {
		if (wrong_if)
			smclog(LOG_WARNING, "Failed getting MFC stats: %s", strerror(errno));
		return errno;
	}

	if (pktcnt)
		*pktcnt = sg_req.pktcnt;
	if (bytecnt)
		*bytecnt = sg_req.bytecnt;
	if (wrong_if)
		*wrong_if = sg_req.wrong_if;

	return 0;
}

/**
 * mroute6_dyn_expire - Expire dynamically added (*,G) routes
 * @max_idle: Timeout for routes in seconds, 0 to expire all dynamic routes
 *
 * This function flushes all (*,G) routes which haven't been used (i.e. no
 * packets matching them have been forwarded) in the last max_idle seconds.
 * It is called periodically on cache-timeout or on request of smcroutectl.
 * The latter is useful in case of topology changes (e.g. VRRP fail-over)
 * or similar.
 */
void mroute6_dyn_expire(int max_idle)
{
	struct mroute6 *entry, *tmp;
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	LIST_FOREACH_SAFE(entry, &mroute6_dyn_list, link, tmp) {
		if (!entry->last_use) {
			/* New entry */
			entry->last_use = now.tv_sec;
			entry->valid_pkt = get_valid_pkt6(entry);
		}

		if (entry->last_use + max_idle <= now.tv_sec) {
			unsigned long valid_pkt;

			valid_pkt = get_valid_pkt6(entry);
			if (valid_pkt != entry->valid_pkt) {
				/* Used since last check, update */
				entry->last_use = now.tv_sec;
				entry->valid_pkt = valid_pkt;
				continue;
			}

			/* Not used, expire */
			kern_del6(entry, is_active6(entry));
			LIST_REMOVE(entry, link);
			free(entry);
		}
	}
}

/*
 * Get valid packet usage statistics (i.e. number of actually forwarded
 * packets) from the kernel for an installed MFC entry
 */
static unsigned long get_valid_pkt6(struct mroute6 *route)
{
	unsigned long pktcnt = 0, wrong_if = 0;

	if (get_stats6(route, &pktcnt, NULL, &wrong_if) < 0)
		return 0;

	return pktcnt - wrong_if;
}

/* Create a virtual interface from @iface so it can be used for IPv6 multicast routing. */
static int mroute6_add_mif(struct iface *iface)
{
	struct mif6ctl mc;
	int mif = -1;
	size_t i;

	if (mroute6_socket == -1)
		return 0;

	if ((iface->flags & IFF_MULTICAST) != IFF_MULTICAST) {
		smclog(LOG_INFO, "Interface %s is not multicast capable, skipping MIF.", iface->name);
		iface->mif = -1;
		return 0;
	}

	/* find a free mif */
	for (i = 0; i < NELEMS(mif_list); i++) {
		if (!mif_list[i].iface) {
			mif = i;
			break;
		}
	}

	/* no more space */
	if (mif == -1) {
		errno = ENOMEM;
		smclog(LOG_WARNING, "Kernel MAXMIFS (%d) too small for number of interfaces: %s", MAXMIFS, strerror(errno));
		return 1;
	}

	memset(&mc, 0, sizeof(mc));
	mc.mif6c_mifi = mif;
	mc.mif6c_flags = 0;	/* no register */
#ifdef HAVE_MIF6CTL_VIFC_THRESHOLD
	mc.vifc_threshold = iface->threshold;
#endif
	mc.mif6c_pifi = iface->ifindex;	/* physical interface index */
#ifdef HAVE_MIF6CTL_VIFC_RATE_LIMIT
	mc.vifc_rate_limit = 0;	/* hopefully no limit */
#endif

	smclog(LOG_DEBUG, "Map iface %-16s => MIF %-2d ifindex %2d flags 0x%04x TTL threshold %u",
	       iface->name, mc.mif6c_mifi, mc.mif6c_pifi, mc.mif6c_flags, iface->threshold);

	if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_ADD_MIF, (void *)&mc, sizeof(mc))) {
		smclog(LOG_ERR, "Failed adding MIF for iface %s: %s", iface->name, strerror(errno));
		iface->mif = -1;
		return 1;
	}

	iface->mif = mif;
	mif_list[mif].iface = iface;
	mif_list[mif].scope_mask = IN6_ALLOW_DEFAULT_MULTICAST_SCOPE;

	return 0;
}

static int mroute6_del_mif(struct iface *iface)
{
	int16_t mif = iface->mif;

	if (mroute6_socket == -1)
		return 0;

	if (-1 == mif)
		return 0;	/* No MIF setup for iface, skip */

	smclog(LOG_DEBUG, "Removing  %-16s => MIF %-2d", iface->name, mif);

	if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_DEL_MIF, (void *)&mif, sizeof(mif)))
		smclog(LOG_ERR, "Failed deleting MIF for iface %s: %s", iface->name, strerror(errno));
	else
		iface->mif = -1;

	return 0;
}

static int is_any_match6(struct mroute6 *rule, struct mroute6 *cand)
{
	if ((rule->inbound == cand->inbound) && rule->src_len == 0 && rule->len == 0)
	{
		return 1;
	}

	return 0;
}

static uint8_t get_multicast_scope6(struct in6_addr *addr)
{
	return ((addr->s6_addr[1]) & 0xf);
}

static int is_match6(struct mroute6 *rule, struct mroute6 *cand)
{
	int i, j;

	if (rule->inbound != cand->inbound)
		return 0;

	i = rule->len / 8;
	if (i > 0 &&
		memcmp(rule->group.sin6_addr.s6_addr, cand->group.sin6_addr.s6_addr, i))
	{
		return 0;
	}

	j = rule->len % 8;
	if (j > 0 &&
		(rule->group.sin6_addr.s6_addr[i] >> (8 - j)) == (cand->group.sin6_addr.s6_addr[i] >> (8 - j))) {
		return 0;
	}

	return 1;
}


/*
 * Used for exact (S,G) matching
 */
static int is_exact_match6(struct mroute6 *a, struct mroute6 *b)
{
	if (memcmp(&a->source.sin6_addr, &b->source.sin6_addr, sizeof(struct in6_addr)) == 0 &&
	    memcmp(&a->group.sin6_addr, &b->group.sin6_addr, sizeof(struct in6_addr)) == 0 &&
	    a->len           == b->len &&
	    a->inbound       == b->inbound)
		return 1;

	return 0;
}

static int mroute6_exists(struct mroute6 *route)
{
	struct mroute6 *entry;

	LIST_FOREACH(entry, &mroute6_conf_list, link) {
		if (is_match6(entry, route)) {
			if (is_any_match6(entry, route)) {
				if (IN6_IS_ADDR_ANY(&route->source.sin6_addr) &&
						IN6_IS_ADDR_ANY(&route->group.sin6_addr)) {
					if (entry->scope_mask != route->scope_mask)
					{
						smclog(LOG_INFO, "scope mask is updated from %04X to %04X",
								entry->scope_mask, route->scope_mask);
						mif_list[route->inbound].scope_mask = route->scope_mask;
						entry->scope_mask = route->scope_mask;
					}
				}
				else if (!IN6_IS_ADDR_ANY(&route->group.sin6_addr)) {
					uint8_t scope = get_multicast_scope6(&route->group.sin6_addr);

					if (!(mif_list[route->inbound].scope_mask & (uint16_t)(1 << scope)))
					{
						smclog(LOG_WARNING, "scope_mask %04x, mroute rule for scope (%d) is not allowed",
								mif_list[route->inbound].scope_mask, scope);
					}
					// FIXME: whether allowing to add finer-grade rule
				}
			}
			smclog(LOG_INFO, "(*,G) route already exists");
			return 1;
		}
	}

	LIST_FOREACH(entry, &mroute6_static_list, link) {
		if (is_exact_match6(entry, route)) {
			smclog(LOG_INFO, "Static route already exists");
			return 1;
		}
	}

	return 0;
}

static int is_mroute6_static(struct mroute6 *route)
{
	return route->src_len == 128;
}

static int is_active6(struct mroute6 *route)
{
	size_t i;

	for (i = 0; i < NELEMS(route->ttl); i++) {
		if (route->ttl[i])
			return 1;
	}

	return 0;
}

/* Actually set in kernel - called by mroute6_add() */
static int kern_add6(struct mroute6 *route, int active)
{
	char origin[INET6_ADDRSTRLEN], group[INET6_ADDRSTRLEN];
	struct mf6cctl mc;
	size_t i = 0;

	if (mroute6_socket == -1)
		return 0;

	memset(&mc, 0, sizeof(mc));

	mc.mf6cc_origin   = route->source;
	mc.mf6cc_mcastgrp = route->group;
	mc.mf6cc_parent   = route->inbound;

	/* copy the outgoing MIFs */
	for (; i < NELEMS(route->ttl); i++) {
		if (route->ttl[i] > 0)
			IF_SET(i, &mc.mf6cc_ifset);
	}

	if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_ADD_MFC, (void *)&mc, sizeof(mc))) {
		smclog(LOG_DEBUG, "failed adding IPv6 multicast route: %s", strerror(errno));
		return 1;
	}

	smclog(LOG_DEBUG, "Add %s -> %s from MIF %d",
	       inet_ntop(AF_INET6, &mc.mf6cc_origin.sin6_addr, origin, INET6_ADDRSTRLEN),
	       inet_ntop(AF_INET6, &mc.mf6cc_mcastgrp.sin6_addr, group, INET6_ADDRSTRLEN),
	       mc.mf6cc_parent);

	if (active) {
		/* Only enable mrdisc for active routes, i.e. with outbound */
		mrdisc_enable(route->inbound);
	}

	return 0;
}

/* Remove from kernel and linked list */
static int do_mroute6_del(struct mroute6 *entry)
{
	int ret;

	ret = kern_del6(entry, is_active6(entry));
	if (ret && ENOENT != errno)
		return ret;

	/* Also remove on ENOENT */
	LIST_REMOVE(entry, link);
	free(entry);

	return ret;
}

/* Actually remove from kernel - called by mroute6_del() */
static int kern_del6(struct mroute6 *route, int active)
{
	char origin[INET6_ADDRSTRLEN], group[INET6_ADDRSTRLEN];
	struct mf6cctl mc;

	if (mroute6_socket == -1)
		return 0;

	memset(&mc, 0, sizeof(mc));
	mc.mf6cc_origin = route->source;
	mc.mf6cc_mcastgrp = route->group;
	if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_DEL_MFC, (void *)&mc, sizeof(mc))) {
		if (ENOENT == errno)
			smclog(LOG_DEBUG, "failed removing multicast route, does not exist.");
		else
			smclog(LOG_DEBUG, "failed removing IPv6 multicast route: %s", strerror(errno));
		return 1;
	}

	smclog(LOG_DEBUG, "Del %s -> %s",
	       inet_ntop(AF_INET6, &mc.mf6cc_origin.sin6_addr, origin, INET6_ADDRSTRLEN),
	       inet_ntop(AF_INET6, &mc.mf6cc_mcastgrp.sin6_addr, group, INET6_ADDRSTRLEN));

	if (active) {
		/* Only disable mrdisc for active routes. */
		mrdisc_disable(route->inbound);
	}

	return 0;
}

/* Only inbound differs, there can only be one ... */
static struct mroute6 *mroute6_similar(struct mroute6 *route)
{
	struct mroute6 *entry;

	LIST_FOREACH(entry, &mroute6_static_list, link) {

		if (!IN6_IS_ADDR_ANY(&route->source.sin6_addr) &&
				memcmp(&entry->source.sin6_addr, &route->source.sin6_addr, sizeof(struct in6_addr)) == 0 &&
				!IN6_IS_ADDR_ANY(&route->group.sin6_addr) &&
				memcmp(&entry->group.sin6_addr, &route->group.sin6_addr, sizeof(struct in6_addr)) == 0 &&
				entry->len           == route->len &&
				entry->src_len       == route->src_len)
			return entry;
	}

	return NULL;
}

/**
 * mroute6_dyn_add - Add route to kernel if it matches a known (*,G) route.
 * @route: Pointer to candidate struct mroute6 IPv6 multicast route
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute6_dyn_add(struct mroute6 *route)
{
	struct mroute6 *entry, *new_entry;
	int ret;
	uint8_t scope = get_multicast_scope6(&route->group.sin6_addr);

	if (!(mif_list[route->inbound].scope_mask & (uint16_t)(1 << scope)))
	{
		smclog(LOG_WARNING, "scope_mask %04x, multicast to scope (%d) is not allowed",
				mif_list[route->inbound].scope_mask, scope);
		errno = EINVAL;
		return 1;
	}

	smclog(LOG_DEBUG, "scope_mask %04x, multicast to scope (%d) is allowed",
				mif_list[route->inbound].scope_mask, scope);

	LIST_FOREACH(entry, &mroute6_conf_list, link) {
		/* Find matching (*,G) ... and interface. */
		if (!is_match6(entry, route))
			continue;

		/* Use configured template (*,G) outbound interfaces. */
		memcpy(route->ttl, entry->ttl, NELEMS(route->ttl) * sizeof(route->ttl[0]));
		smclog(LOG_DEBUG, "%s matched (*, G) or (*,*)", __FUNCTION__);
		break;
	}

	if (!entry) {
		/*
		 * No match, add entry without outbound interfaces
		 * nevertheless to avoid continuous cache misses from
		 * the kernel. Note that this still gets reported as an
		 * error (ENOENT) below.
		 */
		smclog(LOG_WARNING, "no match");
		memset(route->ttl, 0, NELEMS(route->ttl) * sizeof(route->ttl[0]));
	}

	ret = kern_add6(route, entry ? 1 : 0);
	if (ret)
		return ret;

	/* Add to list of dynamically added routes. Necessary if the user
	 * removes the (*,G) using the command line interface rather than
	 * updating the conf file and SIGHUP. Note: if we fail to alloc()
	 * memory we don't do anything, just add kernel route silently. */
	new_entry = malloc(sizeof(struct mroute6));
	if (new_entry) {
		memcpy(new_entry, route, sizeof(struct mroute6));
		LIST_INSERT_HEAD(&mroute6_dyn_list, new_entry, link);
	}

	/* Signal to cache handler we've added a stop filter */
	if (!entry) {
		errno = ENOENT;
		return -1;
	}

	return ret;
}

/**
 * mroute6_add - Add route to kernel, or save a wildcard route for later use
 * @route: Pointer to struct mroute6 IPv6 multicast route to add
 *
 * Adds the given multicast @route to the kernel multicast routing table.
 * unless the source IP is %INADDR_ANY, i.e., a (*,G) route.  Those we
 * save for and check against at runtime when the kernel signals us.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute6_add(struct mroute6 *route)
{
	struct mroute6 *entry;
	char origin[INET6_ADDRSTRLEN], group[INET6_ADDRSTRLEN];

	/* Exact match, then skip ... */
	if (mroute6_exists(route)) {
		errno = EEXIST;
		return 1;
	}

	/* ... (S,G) matches and inbound differs, then replace route */
	entry = mroute6_similar(route);

	if (entry) {
		kern_del6(entry, is_active6(entry));
		LIST_REMOVE(entry, link);
		free(entry);
	}

	entry = malloc(sizeof(struct mroute6));
	if (!entry) {
		smclog(LOG_WARNING, "Cannot add multicast route: %s", strerror(errno));
		return 1;
	}

	memcpy(entry, route, sizeof(struct mroute6));

	/*
	 * For (*,G) we save to a linked list to be added on-demand when
	 * the kernel sends IGMPMSG_NOCACHE.
	 */
	if (!is_mroute6_static(entry)) {
		struct mroute6 *dyn, *tmp;

		LIST_INSERT_HEAD(&mroute6_conf_list, entry, link);
		if (IN6_IS_ADDR_ANY(&entry->source.sin6_addr) &&
				IN6_IS_ADDR_ANY(&entry->group.sin6_addr))
		{
			smclog(LOG_INFO, "scope mask is %04X", entry->scope_mask);
			mif_list[route->inbound].scope_mask = entry->scope_mask;
		}

		/* Also, immediately expire any currently blocked traffic */
		LIST_FOREACH_SAFE(dyn, &mroute6_dyn_list, link, tmp) {
			if (!is_active6(dyn) && is_match6(entry, dyn)) {
				inet_ntop(AF_INET6, &dyn->group.sin6_addr,  group,  INET6_ADDRSTRLEN);
				inet_ntop(AF_INET6, &dyn->source.sin6_addr, origin, INET6_ADDRSTRLEN);
				smclog(LOG_DEBUG, "Flushing (%s,%s) on MIF %d, new matching (*,G) rule ...",
				       origin, group, dyn->inbound);

				kern_del6(dyn, 0);
				LIST_REMOVE(dyn, link);
				free(dyn);
			}
		}

		smclog(LOG_DEBUG, "Add conf %s -> %s from MIF %d",
				inet_ntop(AF_INET6, &entry->source.sin6_addr, origin, INET6_ADDRSTRLEN),
				inet_ntop(AF_INET6, &entry->group.sin6_addr, group, INET6_ADDRSTRLEN),
				entry->inbound);

		return 0;
	}

	LIST_INSERT_HEAD(&mroute6_static_list, entry, link);
	return kern_add6(route, 1);
}

/**
 * mroute6_del - Remove route from kernel, or all matching routes if wildcard
 * @route: Pointer to struct mroute6 IPv6 multicast route to remove
 *
 * Removes the given multicast @route from the kernel multicast routing
 * table.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute6_del(struct mroute6 *route)
{
	struct mroute6 *entry, *set, *tmp, *innertmp;
	
	if (is_mroute6_static(route)) {
		LIST_FOREACH_SAFE(entry, &mroute6_static_list, link, tmp) {
			if (!is_exact_match6(entry, route))
				continue;

			return do_mroute6_del(entry);
		}

		/* Not found in static list, check if spawned from a (*,G)/(*, *) rule. */
		LIST_FOREACH_SAFE(entry, &mroute6_dyn_list, link, tmp) {
			if (!is_exact_match6(entry, route))
				continue;

			return do_mroute6_del(entry);
		}

		smclog(LOG_NOTICE, "Cannot delete multicast route: not found");
		errno = ENOENT;
		return -1;
	}
	else {
		/* Find matching (*,G) ... and interface .. and prefix length. */
		LIST_FOREACH_SAFE(entry, &mroute6_conf_list, link, tmp) {
			int ret = 0;

			if (!is_match6(entry, route) || entry->len != route->len ||
					entry->src_len != route->src_len)
				continue;

			/* Remove all (S,G) routes spawned from the (*,G)/(*, *) as well ... */
			LIST_FOREACH_SAFE(set, &mroute6_dyn_list, link, innertmp) {
				if (is_match6(route, set))
				{
					ret += do_mroute6_del(set);
				}
			}

			if (!ret) {
				char origin[INET6_ADDRSTRLEN] = "", group[INET6_ADDRSTRLEN] = "";
				smclog(LOG_DEBUG, "Remove conf %s -> %s from MIF %d",
						inet_ntop(AF_INET6, &entry->source.sin6_addr, origin, INET6_ADDRSTRLEN),
						inet_ntop(AF_INET6, &entry->group.sin6_addr, group, INET6_ADDRSTRLEN),
						entry->inbound);
				LIST_REMOVE(entry, link);
				free(entry);
			}

			return ret;
		}

		smclog(LOG_NOTICE, "Cannot delete multicast route: not found");
		errno = ENOENT;
		return -1;
	}
}

#endif /* HAVE_IPV6_MULTICAST_ROUTING */

/* Used by file parser to add VIFs/MIFs after setup */
int mroute_add_vif(char *ifname, uint8_t mrdisc, uint8_t threshold)
{
	int ret = 0;
	struct iface *iface;
	struct ifmatch state;

	smclog(LOG_DEBUG, "Adding %s to list of multicast routing interfaces", ifname);
	iface_match_init(&state);
	while ((iface = iface_match_by_name(ifname, &state))) {
		iface->mrdisc    = mrdisc;
		iface->threshold = threshold;
		ret += mroute4_add_vif(iface);
#ifdef HAVE_IPV6_MULTICAST_ROUTING
		ret += mroute6_add_mif(iface);
#endif
	}

	if (!state.match_count)
		return 1;
	else
		return ret;
}

/* Used by file parser to remove VIFs/MIFs after setup */
int mroute_del_vif(char *ifname)
{
	int ret = 0;
	struct iface *iface;
	struct ifmatch state;

	smclog(LOG_DEBUG, "Pruning %s from list of multicast routing interfaces", ifname);
	iface_match_init(&state);
	while ((iface = iface_match_by_name(ifname, &state))) {
		ret += mroute4_del_vif(iface);
#ifdef HAVE_IPV6_MULTICAST_ROUTING
		ret += mroute6_del_mif(iface);
#endif
	}

	if (!state.match_count)
		return 1;
	else
		return ret;
}

#ifdef ENABLE_CLIENT
static int show_mroute(int sd, struct mroute4 *r, int detail)
{
	int vif;
	char src[INET_ADDRSTRLEN] = "*";
	char src_len[4] = "";
	char grp[INET_ADDRSTRLEN];
	char grp_len[4] = "";
	char sg[(INET_ADDRSTRLEN+3) * 2 + 5];
	char buf[MAX_MC_VIFS * 17 + 80];
	struct iface *i;

	if (r->source.s_addr != htonl(INADDR_ANY)) {
		inet_ntop(AF_INET, &r->source, src, sizeof(src));
		if (r->src_len)
			snprintf(src_len, sizeof(src_len), "/%u", r->src_len);
	}
	inet_ntop(AF_INET, &r->group, grp, sizeof(grp));
	if (r->len)
		snprintf(grp_len, sizeof(grp_len), "/%u", r->len);

	i = iface_find_by_vif(r->inbound);
	snprintf(sg, sizeof(sg), "(%s%s, %s%s)", src, src_len, grp, grp_len);
	snprintf(buf, sizeof(buf), "%-50s %-16s", sg, i->name);

	if (detail) {
		char stats[30];
		unsigned long p = 0, b = 0;

		get_stats4(r, &p, &b, NULL);
		snprintf(stats, sizeof(stats), " %10lu %10lu ", p, b);
		strlcat(buf, stats, sizeof(buf));
	}

	for (vif = 0; vif < MAX_MC_VIFS; vif++) {
		char tmp[22];

		if (r->ttl[vif] == 0)
			continue;

		i = iface_find_by_vif(vif);
		if (!i)
			continue;

		snprintf(tmp, sizeof(tmp), " %s", i->name);
		strlcat(buf, tmp, sizeof(buf));
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
	struct mroute4 *r;

	LIST_FOREACH(r, &mroute4_conf_list, link) {
		if (show_mroute(sd, r, detail) < 0)
			return 1;
	}

	LIST_FOREACH(r, &mroute4_dyn_list, link) {
		if (show_mroute(sd, r, detail) < 0)
			return 1;
	}

	LIST_FOREACH(r, &mroute4_static_list, link) {
		if (show_mroute(sd, r, detail) < 0)
			return 1;
	}

#ifdef HAVE_IPV6_MULTICAST_ROUTING
	struct mroute6 *r6;

	LIST_FOREACH(r6, &mroute6_conf_list, link) {
		if (show_mroute6(sd, r6, detail) < 0)
			return 1;
	}

	LIST_FOREACH(r6, &mroute6_dyn_list, link) {
		if (show_mroute6(sd, r6, detail) < 0)
			return 1;
	}

	LIST_FOREACH(r6, &mroute6_static_list, link) {
		if (show_mroute6(sd, r6, detail) < 0)
			return 1;
	}
#endif // HAVE_IPV6_MULTICAST_ROUTING

	return 0;
}
#endif

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
