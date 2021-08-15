/* Physical and virtual interface API
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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <limits.h>
#include <unistd.h>
#include <netinet/in.h>

#include "log.h"
#include "ipc.h"
#include "iface.h"
#include "mcgroup.h"
#include "timer.h"
#include "util.h"

static LIST_HEAD(iflist, iface) iface_list = LIST_HEAD_INITIALIZER();

/**
 * iface_update - Check of new interfaces
 * @do_vifs: If set, then mark all interfaces found as "in use"
 */
void iface_update(int do_vifs)
{
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1) {
		smclog(LOG_ERR, "Failed retrieving interface addresses: %s", strerror(errno));
		exit(EX_OSERR);
	}

	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		struct iface *iface;

		/* Check if already added? */
		iface = iface_find_by_name(ifa->ifa_name);
		if (iface) {
			smclog(LOG_DEBUG, "Found %s, updating ...", ifa->ifa_name);
			if (!iface->inaddr.s_addr && ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
				iface->inaddr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			if (do_vifs)
				iface->unused = 0;

			continue;
		}

		smclog(LOG_DEBUG, "Found new interface %s, adding ...", ifa->ifa_name);
		iface = calloc(1, sizeof(struct iface));
		if (!iface) {
			smclog(LOG_ERR, "Failed allocating space for interface: %s", strerror(errno));
			exit(EX_OSERR);
		}

		/*
		 * Only copy interface address if inteface has one.  On
		 * Linux we can enumerate VIFs using ifindex, useful for
		 * DHCP interfaces w/o any address yet.  Other UNIX
		 * systems will fail on the MRT_ADD_VIF ioctl. if the
		 * kernel cannot find a matching interface.
		 */
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
			iface->inaddr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
		iface->flags = ifa->ifa_flags;
		strlcpy(iface->ifname, ifa->ifa_name, sizeof(iface->ifname));
		iface->ifindex = if_nametoindex(iface->ifname);
		iface->vif = ALL_VIFS;
		iface->mif = ALL_MIFS;
		iface->mrdisc = 0;
		iface->threshold = DEFAULT_THRESHOLD;

		LIST_INSERT_HEAD(&iface_list, iface, link);
	}

	freeifaddrs(ifaddr);
}

/**
 * iface_init - Probe for interaces at startup
 * @do_vifs: If set, then mark all interfaces found as "in use"
 *
 * Builds up a vector with active system interfaces.  Must be called
 * before any other interface functions in this module!
 */
void iface_init(int do_vifs)
{
	iface_update(do_vifs);
}

/**
 * iface_exit - Tear down interface list and clean up
 */
void iface_exit(void)
{
	struct iface *iface, *tmp;

	LIST_FOREACH_SAFE(iface, &iface_list, link, tmp) {
		LIST_REMOVE(iface, link);
		free(iface);
	}
}

/**
 * iface_find - Find an interface by ifindex
 * @ifindex: Interface index
 *
 * Returns:
 * Pointer to a @struct iface of the matching interface, or %NULL if no
 * interface exists, or is up.  If more than one interface exists, chose
 * the interface that corresponds to a virtual interface.
 */
struct iface *iface_find(int ifindex)
{
	struct iface *iface;

	LIST_FOREACH(iface, &iface_list, link) {
		if (iface->ifindex == ifindex)
			return iface;
	}

	return NULL;
}

/**
 * iface_find_by_name - Find an interface by name
 * @ifname: Interface name
 *
 * Returns:
 * Pointer to a @struct iface of the matching interface, or %NULL if no
 * interface exists, or is up.  If more than one interface exists, chose
 * the interface that corresponds to a virtual interface.
 */
struct iface *iface_find_by_name(const char *ifname)
{
	struct iface *candidate = NULL;
	struct iface *iface;
	char *nm, *ptr;

	if (!ifname)
		return NULL;

	nm = strdup(ifname);
	if (!nm)
		return NULL;

	/* Alias interfaces should use the same VIF/MIF as parent */
	ptr = strchr(nm, ':');
	if (ptr)
		*ptr = 0;

	LIST_FOREACH(iface, &iface_list, link) {
		if (!strcmp(nm, iface->ifname)) {
			if (iface->vif != NO_VIF) {
				free(nm);
				return iface;
			}

			candidate = iface;
		}
	}

	free(nm);

	return candidate;
}

static struct iface *find_by_vif(vifi_t vif)
{
	struct iface *iface;

	LIST_FOREACH(iface, &iface_list, link) {
		if (iface->vif != NO_VIF && iface->vif == vif)
			return iface;
	}

	return NULL;
}

static struct iface *find_by_mif(mifi_t mif)
{
	struct iface *iface;

	LIST_FOREACH(iface, &iface_list, link) {
		if (iface->mif != NO_VIF && iface->mif == mif)
			return iface;
	}

	return NULL;
}

/**
 * iface_find_by_inbound - Find iface by route's inbound VIF
 * @route: Route's inbound to use
 *
 * Returns:
 * Pointer to a @struct iface of the requested interface, or %NULL if no
 * interface matching @mif exists.
 */
struct iface *iface_find_by_inbound(struct mroute *route)
{
#ifdef  HAVE_IPV6_MULTICAST_HOST
	if (route->group.ss_family == AF_INET6)
		return find_by_mif(route->inbound);
#endif

	return find_by_vif(route->inbound);
}

/**
 * iface_match_init - Initialize interface matching iterator
 * @state: Iterator state to be initialized
 */
void iface_match_init(struct ifmatch *state)
{
	state->iface = LIST_FIRST(&iface_list);
	state->match_count = 0;
}

/**
 * ifname_is_wildcard - Check whether interface name is a wildcard
 *
 * Returns:
 * %TRUE(1) if wildcard, %FALSE(0) if normal interface name
 */
int ifname_is_wildcard(const char *ifname)
{
	return (ifname && ifname[0] && ifname[strlen(ifname) - 1] == '+');
}

/**
 * iface_match_by_name - Find matching interfaces by name pattern
 * @ifname: Interface name pattern
 * @state: Iterator state
 *
 * Interface name patterns use iptables- syntax, i.e. perform prefix
 * match with a trailing '+' matching anything.
 *
 * Returns:
 * Pointer to a @struct iface of the next matching interface, or %NULL if no
 * (more) interfaces exist (or are up).
 */
struct iface *iface_match_by_name(const char *ifname, struct ifmatch *state)
{
	unsigned int match_len = UINT_MAX;

	if (!ifname)
		return NULL;

	if (ifname_is_wildcard(ifname))
		match_len = strlen(ifname) - 1;

	while (state->iface != LIST_END(&iface_list)) {
		struct iface *iface = state->iface;

		if (!strncmp(ifname, iface->ifname, match_len)) {
			state->iface = LIST_NEXT(iface, link);
			state->match_count++;

			return iface;
		}

		state->iface = LIST_NEXT(iface, link);
	}

	return NULL;
}

/**
 * iface_iterator - Interface iterator
 * @first: Set to start from beginning
 *
 * Returns:
 * Pointer to a @struct iface, or %NULL when no more interfaces exist.
 */
struct iface *iface_iterator(int first)
{
	static struct iface *iface = NULL;

	if (first)
		iface = LIST_FIRST(&iface_list);
	else
		iface = LIST_NEXT(iface, link);

	return iface;
}

struct iface *iface_outbound_iterator(struct mroute *route, int first)
{
	struct iface *iface = NULL;
	static vifi_t i = 0;

	if (first)
		i = 0;

	while (i < MAX_MC_VIFS) {
		vifi_t vif = i++;

		if (route->ttl[vif] == 0)
			continue;

#ifdef HAVE_IPV6_MULTICAST_ROUTING
		if (route->group.ss_family == AF_INET6)
			iface = find_by_mif(vif);
		else
#endif
		iface = find_by_vif(vif);
		if (!iface)
			continue;

		return iface;
	}

	return NULL;
}

vifi_t iface_get_vif(int af_family, struct iface *iface)
{
#ifdef HAVE_IPV6_MULTICAST_HOST
	if (af_family == AF_INET6)
		return iface->mif;
#endif
	return iface->vif;
}

/**
 * iface_match_vif_by_name - Get matching virtual interface index by interface name pattern (IPv4)
 * @ifname: Interface name pattern
 * @state: Iterator state
 *
 * Returns:
 * The virtual interface index if the interface matches and is registered
 * with the kernel, or -1 if no (more) matching virtual interfaces are found.
 */
vifi_t iface_match_vif_by_name(const char *ifname, struct ifmatch *state, struct iface **found)
{
	struct iface *iface;

	while ((iface = iface_match_by_name(ifname, state))) {
		if (iface->vif != NO_VIF) {
			if (found)
				*found = iface;

//			smclog(LOG_DEBUG, "  %s has VIF %d", iface->ifname, iface->vif);
			return iface->vif;
		}

//		smclog(LOG_DEBUG, "  %s has NO VIF", iface->ifname);
		state->match_count--;
	}

	return NO_VIF;
}

/**
 * iface_match_mif_by_name - Get matching virtual interface index by interface name pattern (IPv6)
 * @ifname: Interface name pattern
 * @state: Iterator state
 *
 * Returns:
 * The virtual interface index if the interface matches and is registered
 * with the kernel, or -1 if no (more) matching virtual interfaces are found.
 */
mifi_t iface_match_mif_by_name(const char *ifname, struct ifmatch *state, struct iface **found)
{
	struct iface *iface;

	while ((iface = iface_match_by_name(ifname, state))) {
		if (iface->mif != NO_VIF) {
			if (found)
				*found = iface;

			smclog(LOG_DEBUG, "  %s has MIF %d", iface->ifname, iface->mif);
			return iface->mif;
		}

		state->match_count--;
	}

	return NO_VIF;
}

/* Return all currently known interfaces */
int iface_show(int sd, int detail)
{
	struct iface *iface;

	(void)detail;

	iface = iface_iterator(1);
	while (iface) {
		char buf[256];

		snprintf(buf, sizeof(buf), "%-16s  %6d  %3d  %3d\n",
			 iface->ifname, iface->ifindex, iface->vif, iface->mif);
		if (ipc_send(sd, buf, strlen(buf)) < 0) {
			smclog(LOG_ERR, "Failed sending reply to client: %s", strerror(errno));
			return -1;
		}

		iface = iface_iterator(0);
	}

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
