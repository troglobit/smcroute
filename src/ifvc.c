/* Physical and virtual interface API
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

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <limits.h>
#include <unistd.h>
#include <netinet/in.h>

#include "log.h"
#include "ifvc.h"
#include "util.h"

static unsigned int num_ifaces = 0, num_ifaces_alloc = 0;
static struct iface *iface_list = NULL;

/**
 * iface_init - Setup vector of active interfaces
 *
 * Builds up a vector with active system interfaces.  Must be called
 * before any other interface functions in this module!
 */
void iface_init(void)
{
	struct iface *iface;
	struct ifaddrs *ifaddr, *ifa;

	num_ifaces = 0;

	if (iface_list)
		free(iface_list);

	num_ifaces_alloc = 1;
	iface_list = calloc(num_ifaces_alloc, sizeof(struct iface));
	if (!iface_list) {
		smclog(LOG_ERR, "Failed allocating space for interfaces: %s", strerror(errno));
		exit(255);
	}

	if (getifaddrs(&ifaddr) == -1) {
		smclog(LOG_ERR, "Failed retrieving interface addresses: %s", strerror(errno));
		exit(255);
	}

	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		/* Check if already added? */
		if ((iface = iface_find_by_name(ifa->ifa_name))) {
			if (!iface->inaddr.s_addr && ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
				iface->inaddr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
			continue;
		}

		/* Allocate more space? */
		if (num_ifaces == num_ifaces_alloc) {
			num_ifaces_alloc *= 2;
			iface_list = realloc(iface_list, num_ifaces_alloc * sizeof(struct iface));
			if (!iface_list) {
				smclog(LOG_ERR, "Failed allocating space for interfaces: %s", strerror(errno));
				exit(255);
			}
			/* Initialize 2nd half of interface list */
			memset(&iface_list[num_ifaces], 0, num_ifaces * sizeof(struct iface));
		}

		/* Copy data from interface iterator 'ifa' */
		iface = &iface_list[num_ifaces++];
		strlcpy(iface->name, ifa->ifa_name, sizeof(iface->name));

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
		iface->ifindex = if_nametoindex(iface->name);
		iface->vif = -1;
		iface->mif = -1;
		iface->mrdisc = 0;
		iface->threshold = DEFAULT_THRESHOLD;
	}
	freeifaddrs(ifaddr);
}

/**
 * iface_exit - Tear down interface list and clean up
 */
void iface_exit(void)
{
	if (iface_list) {
		free(iface_list);
		iface_list = NULL;
	}
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
	unsigned int i;
	struct iface *iface;
	struct iface *candidate = NULL;

	if (!ifname)
		return NULL;

	for (i = 0; i < num_ifaces; i++) {
		iface = &iface_list[i];
		if (!strcmp(ifname, iface->name)) {
			if (iface->vif >= 0)
				return iface;
			candidate = iface;
		}
	}

	return candidate;
}

/**
 * iface_match_init - Initialize interface matching iterator
 * @state: Iterator state to be initialized
 */
void iface_match_init(struct ifmatch *state)
{
	state->iter = 0;
	state->match_count = 0;
}

/**
 * iface_match_by_name - Find matching interfaces by name pattern
 * @ifname: Interface name pattern
 * @state: Iterator state
 *
 * Returns:
 * Pointer to a @struct iface of the next matching interface, or %NULL if no
 * (more) interfaces exist (or are up). Interface name patterns use iptables-
 * syntax, i.e. perform prefix match with a trailing '+' matching anything.
 */
struct iface *iface_match_by_name(const char *ifname, struct ifmatch *state)
{
	struct iface *iface;
	unsigned int match_len = UINT_MAX;

	if (!ifname)
		return NULL;
	if (ifname_is_wildcard(ifname))
		match_len = strlen(ifname) - 1;

	for (; state->iter < num_ifaces; state->iter++) {
		iface = &iface_list[state->iter];
		if (!strncmp(ifname, iface->name, match_len)) {
			state->iter++;
			state->match_count++;
			return iface;
		}
	}

	return NULL;
}

/**
 * ifname_is_wildcard - Check whether interface name is a wildcard
 * Returns: 1 if wildcard, 0 if normal interface name
 */
int ifname_is_wildcard(const char *ifname)
{
	return (ifname && ifname[0] && ifname[strlen(ifname) - 1] == '+');
}

/**
 * iface_find_by_vif - Find by virtual interface index
 * @vif: Virtual multicast interface index
 *
 * Returns:
 * Pointer to a @struct iface of the requested interface, or %NULL if no
 * interface matching @vif exists.
 */
struct iface *iface_find_by_vif(int vif)
{
	size_t i;

	for (i = 0; i < num_ifaces; i++) {
		struct iface *iface = &iface_list[i];

		if (iface->vif >= 0 && iface->vif == vif)
			return iface;
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
	static size_t i = 0;

	if (first)
		i = 0;

	if (i >= num_ifaces)
		return NULL;

	return &iface_list[i++];
}


/**
 * iface_get_vif - Get virtual interface index for an interface (IPv4)
 * @iface: Pointer to a @struct iface interface
 *
 * Returns:
 * The virtual interface index if the interface is known and registered
 * with the kernel, or -1 if no virtual interface exists.
 */
int iface_get_vif(struct iface *iface)
{
	if (!iface)
		return -1;

	return iface->vif;
}

/**
 * iface_get_mif - Get virtual interface index for an interface (IPv6)
 * @iface: Pointer to a @struct iface interface
 *
 * Returns:
 * The virtual interface index if the interface is known and registered
 * with the kernel, or -1 if no virtual interface exists.
 */
int iface_get_mif(struct iface *iface __attribute__ ((unused)))
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
	return -1;
#else
	if (!iface)
		return -1;

	return iface->mif;
#endif				/* HAVE_IPV6_MULTICAST_ROUTING */
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
int iface_match_vif_by_name(const char *ifname, struct ifmatch *state, struct iface **found)
{
	int vif;
	struct iface *iface;

	while ((iface = iface_match_by_name(ifname, state))) {
		vif = iface_get_vif(iface);
		if (vif >= 0) {
			if (found)
				*found = iface;
			return vif;
		}
		state->match_count--;
	}
	return -1;
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
int iface_match_mif_by_name(const char *ifname, struct ifmatch *state, struct iface **found)
{
	int mif;
	struct iface *iface;

	while ((iface = iface_match_by_name(ifname, state))) {
		mif = iface_get_mif(iface);
		if (mif >= 0) {
			if (found)
				*found = iface;
			return mif;
		}
		state->match_count--;
	}
	return -1;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
