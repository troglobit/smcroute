/* Generic kernel multicast routing API for Linux and *BSD
 *
 * Copyright (C) 2001-2005  Carsten Schill <carsten@cschill.de>
 * Copyright (C) 2006-2009  Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2009       Todd Hayton <todd.hayton@gmail.com>
 * Copyright (C) 2009-2011  Micha Lenk <micha@debian.org>
 * Copyright (C) 2011-2013  Joachim Nilsson <troglobit@gmail.com>
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
#include <unistd.h>
#include <arpa/inet.h>
#include "config.h"
#include "mclab.h"

#ifdef HAVE_NETINET6_IP6_MROUTE_H
#include <netinet6/ip6_mroute.h>
#endif

/* MAX_MC_VIFS from mclab.h must have same value as MAXVIFS from mroute.h */
#if MAX_MC_VIFS != MAXVIFS
#error "IPv4 constants don't match, mclab.h needs to be fixed!"
#endif

#ifdef HAVE_IPV6_MULTICAST_ROUTING
/* MAX_MC_MIFS from mclab.h must have same value as MAXVIFS from mroute6.h */
#if MAX_MC_MIFS != MAXMIFS
#error "IPv6 constants don't match, mclab.h needs to be fixed!"
#endif
#endif

/* Used for (*,G) matches */
#define mroute4_match(r1, r2) (!memcmp(&(r1)->group, &(r2)->group, sizeof((r1)->group)) && (r1)->inbound == (r2)->inbound)

/*
 * Need a raw IGMP socket as interface for the IPv4 mrouted API
 * Receives IGMP packets and kernel upcall messages.
 */
int mroute4_socket = -1;

/* All user added/configured (*,G) routes that are matched on-demand
 * at runtime. See the mroute4_dyn_list for the actual (S,G) routes
 * set from this "template". */
LIST_HEAD(, mroute4) mroute4_conf_list = LIST_HEAD_INITIALIZER();

/* For dynamically/on-demand set (S,G) routes that we must track
 * if the user removes the configured (*,G) route. */
LIST_HEAD(, mroute4) mroute4_dyn_list = LIST_HEAD_INITIALIZER();

#ifdef HAVE_IPV6_MULTICAST_ROUTING
/*
 * Need a raw ICMPv6 socket as interface for the IPv6 mrouted API
 * Receives MLD packets and kernel upcall messages.
 */
int mroute6_socket = -1;
#endif

/* IPv4 internal virtual interfaces (VIF) descriptor vector */
static struct {
	struct iface *iface;
} vif_list[MAXVIFS];

static int mroute4_add_vif(struct iface *iface);

#ifdef HAVE_IPV6_MULTICAST_ROUTING
/* IPv6 internal virtual interfaces (VIF) descriptor vector */
static struct mif {
	struct iface *iface;
} mif_list[MAXMIFS];

static int mroute6_add_mif(struct iface *iface);
#endif

/**
 * mroute4_enable - Initialise IPv4 multicast routing
 *
 * Setup the kernel IPv4 multicast routing API and lock the multicast
 * routing socket to this program (only!).
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute4_enable(void)
{
	int arg = 1;
	unsigned int i;
	struct iface *iface;

	mroute4_socket = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_IGMP);
	if (mroute4_socket < 0) {
		if (ENOPROTOOPT == errno)
			smclog(LOG_WARNING, "Kernel does not support IPv4 multicast routing, skipping ...");

		return -1;
	}

	if (setsockopt(mroute4_socket, IPPROTO_IP, MRT_INIT, (void *)&arg, sizeof(arg))) {
		switch (errno) {
		case EADDRINUSE:
			smclog(LOG_INIT, "IPv4 multicast routing API already in use: %m");
			break;

		default:
			smclog(LOG_INIT, "Failed initializing IPv4 multicast routing API: %m");
			break;
		}

		close(mroute4_socket);
		mroute4_socket = -1;

		return -1;
	}

	/* Initialize virtual interface table */
	memset(&vif_list, 0, sizeof(vif_list));

	/* Create virtual interfaces, VIFs, for all non-loopback interfaces
	 * that have a valid IPv4 address. */
	for (i = 0; (iface = iface_find_by_index(i)); i++) {
		if (iface->flags & IFF_LOOPBACK ||
		    iface->inaddr.s_addr == INADDR_ANY) {
			iface->vif = -1;
			continue;
		}

		/* No point in continuing the loop when out of VIF's */
		if (mroute4_add_vif(iface))
			break;
	}

	LIST_INIT(&mroute4_conf_list);
	LIST_INIT(&mroute4_dyn_list);

	return 0;
}

/**
 * mroute4_disable - Disable IPv4 multicast routing
 *
 * Disable IPv4 multicast routing and release kernel routing socket.
 */
void mroute4_disable(void)
{
	mroute4_t *entry;

	if (mroute4_socket < 0)
		return;

	/* Drop all kernel routes set by smcroute */
	if (setsockopt(mroute4_socket, IPPROTO_IP, MRT_DONE, NULL, 0))
		smclog(LOG_WARNING, "Failed shutting down IPv4 multicast routing socket: %m");

	close(mroute4_socket);
	mroute4_socket = -1;

	/* Free list of (*,G) routes on SIGHUP */
	while (!LIST_EMPTY(&mroute4_conf_list)) {
		entry = LIST_FIRST(&mroute4_conf_list);
		LIST_REMOVE(entry, link);
		free(entry);
	}
	while (!LIST_EMPTY(&mroute4_dyn_list)) {
		entry = LIST_FIRST(&mroute4_dyn_list);
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

	/* search free vif */
	for (i = 0; i < ARRAY_ELEMENTS(vif_list); i++) {
		if (!vif_list[i].iface) {
			vif = i;
			break;
		}
	}

	/* no more space */
	if (vif == -1) {
		errno = ENOMEM;
		smclog(LOG_WARNING, "Kernel MAXVIFS (%d) too small for number of interfaces: %m", MAXVIFS);
		return 1;
	}

	memset(&vc, 0, sizeof(vc));
	vc.vifc_vifi = vif;
	vc.vifc_flags = 0;      /* no tunnel, no source routing, register ? */
	vc.vifc_threshold = 1;  /* Packet TTL must be at least 1 to pass them */
	vc.vifc_rate_limit = 0;	/* hopefully no limit */
	vc.vifc_lcl_addr.s_addr = iface->inaddr.s_addr;
	vc.vifc_rmt_addr.s_addr = INADDR_ANY;

	smclog(LOG_DEBUG, "Iface %s => VIF %d index %d flags 0x%04x",
	       iface->name, vc.vifc_vifi, iface->ifindex, vc.vifc_flags);

	if (setsockopt(mroute4_socket, IPPROTO_IP, MRT_ADD_VIF, (void *)&vc, sizeof(vc))) {
		smclog(LOG_ERR, "Failed adding VIF for iface %s: %m", iface->name);
		exit(255);
	}

	iface->vif = vif;
	vif_list[vif].iface = iface;

	return 0;
}

/* Actually set in kernel - called by mroute4_add() and mroute4_check_add() */
static int __mroute4_add (mroute4_t *route)
{
	int result = 0;
	char origin[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];
	struct mfcctl mc;

	memset(&mc, 0, sizeof(mc));

	mc.mfcc_origin = route->sender;
	mc.mfcc_mcastgrp = route->group;
	mc.mfcc_parent = route->inbound;

	/* copy the TTL vector */
	if (sizeof(mc.mfcc_ttls[0]) != sizeof(route->ttl[0]) || ARRAY_ELEMENTS(mc.mfcc_ttls) != ARRAY_ELEMENTS(route->ttl)) {
		smclog(LOG_ERR, "Critical data type validation error in %s!", __FILE__);
		exit(255);
	}

	memcpy(mc.mfcc_ttls, route->ttl, ARRAY_ELEMENTS(mc.mfcc_ttls) * sizeof(mc.mfcc_ttls[0]));

	smclog(LOG_DEBUG, "Add %s -> %s from VIF %d",
	       inet_ntop(AF_INET, &mc.mfcc_origin,   origin, INET_ADDRSTRLEN),
	       inet_ntop(AF_INET, &mc.mfcc_mcastgrp, group,  INET_ADDRSTRLEN), mc.mfcc_parent);

	if (setsockopt(mroute4_socket, IPPROTO_IP, MRT_ADD_MFC, (void *)&mc, sizeof(mc))) {
		result = errno;
		smclog(LOG_WARNING, "Failed adding IPv4 multicast route: %m");
	}

	return result;
}

/* Actually remove from kernel - called by mroute4_del() */
static int __mroute4_del (mroute4_t *route)
{
	int result = 0;
	char origin[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];
	struct mfcctl mc;

	memset(&mc, 0, sizeof(mc));
	mc.mfcc_origin = route->sender;
	mc.mfcc_mcastgrp = route->group;

	smclog(LOG_DEBUG, "Del %s -> %s",
	       inet_ntop(AF_INET, &mc.mfcc_origin,  origin, INET_ADDRSTRLEN),
	       inet_ntop(AF_INET, &mc.mfcc_mcastgrp, group, INET_ADDRSTRLEN));

	if (setsockopt(mroute4_socket, IPPROTO_IP, MRT_DEL_MFC, (void *)&mc, sizeof(mc))) {
		result = errno;
		smclog(LOG_WARNING, "Failed removing IPv4 multicast route: %m");
	}

	return result;
}

/**
 * mroute4_dyn_add - Add route to kernel if it matches a known (*,G) route.
 * @route: Pointer to candidate &mroute4_t IPv4 multicast route
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute4_dyn_add(mroute4_t *route)
{
	mroute4_t *entry;

	LIST_FOREACH(entry, &mroute4_conf_list, link) {
		/* Find matching (*,G) ... and interface. */
		if (mroute4_match(entry, route)) {
			/* Use configured template (*,G) outbound interfaces. */
			memcpy(route->ttl, entry->ttl, ARRAY_ELEMENTS(route->ttl) * sizeof(route->ttl[0]));

			/* Add to list of dynamically added routes. Necessary if the user
			 * removes the (*,G) using the command line interface rather than
			 * updating the conf file and SIGHUP. Note: if we fail to alloc()
			 * memory we don't do anything, just add kernel route silently. */
			entry = malloc(sizeof(mroute4_t));
			if (entry) {
				memcpy(entry, route, sizeof(mroute4_t));
				LIST_INSERT_HEAD(&mroute4_dyn_list, entry, link);
			}

			return __mroute4_add(route);
		}
	}

	errno = ENOENT;
	return -1;
}

/**
 * mroute4_add - Add route to kernel, or save a wildcard route for later use
 * @route: Pointer to &mroute4_t IPv4 multicast route to add
 *
 * Adds the given multicast @route to the kernel multicast routing table
 * unless the source IP is %INADDR_ANY, i.e., a (*,G) route.  Those we
 * save for and check against at runtime when the kernel signals us.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute4_add(mroute4_t *route)
{
	/* For (*,G) we save to a linked list to be added on-demand
	 * when the kernel sends IGMPMSG_NOCACHE. */
	if (route->sender.s_addr == INADDR_ANY) {
		mroute4_t *entry = malloc(sizeof(mroute4_t));

		if (!entry) {
			smclog(LOG_WARNING, "Failed adding (*,G) multicast route: %m");
			return errno;
		}

		memcpy(entry, route, sizeof(mroute4_t));
		LIST_INSERT_HEAD(&mroute4_conf_list, entry, link);

		return 0;
	}

	return __mroute4_add (route);
}

/**
 * mroute4_del - Remove route from kernel
 * @route: Pointer to &mroute4_t IPv4 multicast route to remove
 *
 * Removes the given multicast @route from the kernel multicast routing
 * table.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute4_del(mroute4_t *route)
{
	mroute4_t *entry, *set;

	/* For (*,G) we have saved all dynamically added kernel routes
	 * to a linked list which we need to traverse again and remove
	 * all matches. From kernel dyn list before we remove the conf
	 * entry. */
	if (route->sender.s_addr != INADDR_ANY)
		return __mroute4_del(route);

	if (LIST_EMPTY(&mroute4_conf_list))
		return 0;

	entry = LIST_FIRST(&mroute4_conf_list);
	while (entry) {
		/* Find matching (*,G) ... and interface. */
		if (mroute4_match(entry, route)) {
			if (LIST_EMPTY(&mroute4_dyn_list)) {
				entry = LIST_NEXT(entry, link);
				continue;
			}

			set = LIST_FIRST(&mroute4_dyn_list);
			while (set) {
				if (mroute4_match(entry, set)) {
					__mroute4_del(set);
					LIST_REMOVE(set, link);
					free(set);

					set = LIST_FIRST(&mroute4_dyn_list);
					continue;
				}

				set = LIST_NEXT(set, link);
			}

			LIST_REMOVE(entry, link);
			free(entry);

			entry = LIST_FIRST(&mroute4_conf_list);
			continue;
		}

		entry = LIST_NEXT(entry, link);
	}

	return 0;
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
int mroute6_enable(void)
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
	return -1;
#else
	int arg = 1;
	unsigned int i;
	struct iface *iface;

	if ((mroute6_socket = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6)) < 0) {
		if (ENOPROTOOPT == errno)
			smclog(LOG_WARNING, "Kernel does not support IPv6 multicast routing, skipping ...");

		return -1;
	}
	if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_INIT, (void *)&arg, sizeof(arg))) {
		switch (errno) {
		case EADDRINUSE:
			smclog(LOG_INIT, "IPv6 multicast routing API already in use: %m");
			break;

		default:
			smclog(LOG_INIT, "Failed initializing IPv6 multicast routing API: %m");
			break;
		}

		close(mroute6_socket);
		mroute6_socket = -1;

		return -1;
	}

	/* Initialize virtual interface table */
	memset(&mif_list, 0, sizeof(mif_list));

#ifdef __linux__
	/* On Linux pre 2.6.29 kernels net.ipv6.conf.all.mc_forwarding
	 * is not set on MRT6_INIT so we have to do this manually */
	if (proc_set_val(IPV6_ALL_MC_FORWARD, 1)) {
		if (errno != EACCES) {
			smclog(LOG_ERR, "Failed enabling IPv6 multicast forwarding: %m");
			exit(255);
		}
	}
#endif
	/* Create virtual interfaces, IPv6 MIFs, for all non-loopback interfaces */
	for (i = 0; (iface = iface_find_by_index(i)); i++) {
		if (iface->flags & IFF_LOOPBACK) {
			iface->vif = -1;
			continue;
		}

		/* No point in continuing the loop when out of MIF's */
		if (mroute6_add_mif(iface))
			break;
	}

	return 0;
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
}

/**
 * mroute6_disable - Disable IPv6 multicast routing
 *
 * Disable IPv6 multicast routing and release kernel routing socket.
 */
void mroute6_disable(void)
{
#ifdef HAVE_IPV6_MULTICAST_ROUTING
	if (mroute6_socket < 0)
		return;

	if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_DONE, NULL, 0))
		smclog(LOG_WARNING, "Failed shutting down IPv6 multicast routing socket: %m");

	close(mroute6_socket);
	mroute6_socket = -1;
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
}

#ifdef HAVE_IPV6_MULTICAST_ROUTING
/* Create a virtual interface from @iface so it can be used for IPv6 multicast routing. */
static int mroute6_add_mif(struct iface *iface)
{
	struct mif6ctl mc;
	int mif = -1;
	size_t i;

	/* find a free mif */
	for (i = 0; i < ARRAY_ELEMENTS(mif_list); i++) {
		if (!mif_list[i].iface) {
			mif = i;
			break;
		}
	}

	/* no more space */
	if (mif == -1) {
		errno = ENOMEM;
		smclog(LOG_WARNING, "Kernel MAXMIFS (%d) too small for number of interfaces: %m", MAXMIFS);
		return 1;
	}

	memset(&mc, 0, sizeof(mc));
	mc.mif6c_mifi = mif;
	mc.mif6c_flags = 0;	/* no register */
#ifdef HAVE_MIF6CTL_VIFC_THRESHOLD
	mc.vifc_threshold = 1;	/* Packet TTL must be at least 1 to pass them */
#endif
	mc.mif6c_pifi = iface->ifindex;	/* physical interface index */
#ifdef HAVE_MIF6CTL_VIFC_RATE_LIMIT
	mc.vifc_rate_limit = 0;	/* hopefully no limit */
#endif

	smclog(LOG_DEBUG, "Iface %s => MIF %d index %d flags 0x%04x",
	       iface->name, mc.mif6c_mifi, mc.mif6c_pifi, mc.mif6c_flags);

	if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_ADD_MIF, (void *)&mc, sizeof(mc))) {
		smclog(LOG_ERR, "Failed adding MIF for iface %s: %m", iface->name);
		exit(255);
	}

	iface->mif = mif;
	mif_list[mif].iface = iface;

	return 0;
}

/**
 * mroute6_add - Add route to kernel, or save a wildcard route for later use
 * @route: Pointer to &mroute6_t IPv6 multicast route to add
 *
 * Adds the given multicast @route to the kernel multicast routing table.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute6_add(mroute6_t *route)
{
	int result = 0;
	size_t i;
	char origin[INET6_ADDRSTRLEN], group[INET6_ADDRSTRLEN];
	struct mf6cctl mc;

	memset(&mc, 0, sizeof(mc));
	mc.mf6cc_origin   = route->sender;
	mc.mf6cc_mcastgrp = route->group;
	mc.mf6cc_parent   = route->inbound;

	/* copy the outgoing MIFs */
	for (i = 0; i < ARRAY_ELEMENTS(route->ttl); i++) {
		if (route->ttl[i] > 0)
			IF_SET(i, &mc.mf6cc_ifset);
	}

	smclog(LOG_DEBUG, "Add %s -> %s from MIF %d",
	       inet_ntop(AF_INET6, &mc.mf6cc_origin.sin6_addr, origin, INET6_ADDRSTRLEN),
	       inet_ntop(AF_INET6, &mc.mf6cc_mcastgrp.sin6_addr, group, INET6_ADDRSTRLEN),
	       mc.mf6cc_parent);

	if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_ADD_MFC, (void *)&mc, sizeof(mc))) {
		result = errno;
		smclog(LOG_WARNING, "Failed adding IPv6 multicast route: %m");
	}

	return result;
}

/**
 * mroute6_del - Remove route from kernel
 * @route: Pointer to &mroute6_t IPv6 multicast route to remove
 *
 * Removes the given multicast @route from the kernel multicast routing
 * table.
 *
 * Returns:
 * POSIX OK(0) on success, non-zero on error with @errno set.
 */
int mroute6_del(mroute6_t *route)
{
	int result = 0;
	char origin[INET6_ADDRSTRLEN], group[INET6_ADDRSTRLEN];
	struct mf6cctl mc;

	memset(&mc, 0, sizeof(mc));
	mc.mf6cc_origin = route->sender;
	mc.mf6cc_mcastgrp = route->group;

	smclog(LOG_DEBUG, "Del %s -> %s",
	       inet_ntop(AF_INET6, &mc.mf6cc_origin.sin6_addr, origin, INET6_ADDRSTRLEN),
	       inet_ntop(AF_INET6, &mc.mf6cc_mcastgrp.sin6_addr, group, INET6_ADDRSTRLEN));

	if (setsockopt(mroute6_socket, IPPROTO_IPV6, MRT6_DEL_MFC, (void *)&mc, sizeof(mc))) {
		result = errno;
		smclog(LOG_WARNING, "Failed removing IPv6 multicast route: %m");
	}

	return result;
}
#endif /* HAVE_IPV6_MULTICAST_ROUTING */

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
