/* Physical and virtual interface API
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
#include <sys/types.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include "mclab.h"

static unsigned int num_ifaces = 0;
static struct iface *iface_list = NULL;

/**
 * iface_init - Setup vector of active interfaces
 *
 * Builds up a vector with active system interfaces.  Must be called
 * before any other interface functions in this module!
 */
void iface_init(void)
{
	int family;
	struct iface *iface;
	struct ifaddrs *ifaddr, *ifa;

	num_ifaces = 0;

	if (iface_list)
		free(iface_list);

	iface_list = calloc(MAX_IF, sizeof(struct iface));
	if (!iface_list) {
		smclog(LOG_ERR, "Failed allocating space for interfaces: %s", strerror(errno));
		exit(255);
	}

	if (getifaddrs(&ifaddr) == -1) {
		smclog(LOG_ERR, "Failed retrieving interface addresses: %s", strerror(errno));
		exit(255);
	}

	for (ifa = ifaddr; ifa && num_ifaces < MAX_IF; ifa = ifa->ifa_next) {
		/* Check if already added? */
		if (iface_find_by_name(ifa->ifa_name))
			continue;

		/* Copy data from interface iterator 'ifa' */
		iface = &iface_list[num_ifaces++];
		strncpy(iface->name, ifa->ifa_name, IFNAMSIZ);
		iface->name[IFNAMSIZ] = 0;

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
 * iface_find_by_index - Find by kernel interface index
 * @ifindex: Kernel interface index
 *
 * Returns:
 * Pointer to a @struct iface of the requested interface, or %NULL if no
 * interface @ifindex exists.
 */
struct iface *iface_find_by_index(unsigned int ifindex)
{
	if (ifindex >= num_ifaces)
		return NULL;

	return &iface_list[ifindex];
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
 * iface_get_vif_by_name - Get virtual interface index by interface name (IPv4)
 * @ifname: Interface name
 *
 * Returns:
 * The virtual interface index if the interface is known and registered
 * with the kernel, or -1 if no virtual interface by that name is found.
 */
int iface_get_vif_by_name(const char *ifname)
{
	int vif;
	struct iface *iface;

	iface = iface_find_by_name(ifname);
	if (!iface)
		return -1;

	vif = iface_get_vif(iface);
	if (vif < 0)
		return -1;

	return vif;
}

/**
 * iface_get_mif_by_name - Get virtual interface index by interface name (IPv6)
 * @ifname: Interface name
 *
 * Returns:
 * The virtual interface index if the interface is known and registered
 * with the kernel, or -1 if no virtual interface by that name is found.
 */
int iface_get_mif_by_name(const char *ifname)
{
	int vif;
	struct iface *iface;

	iface = iface_find_by_name(ifname);
	if (!iface)
		return -1;

	vif = iface_get_mif(iface);
	if (vif < 0)
		return -1;

	return vif;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
