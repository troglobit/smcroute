/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006-2009 Julien BLACHE <jb@jblache.org>
**  Copyright (C) 2009      Todd Hayton <todd.hayton@gmail.com>
**  Copyright (C) 2009-2011 Micha Lenk <micha@debian.org>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
**
**  $Id: ifvc.c 85 2011-08-08 16:47:53Z micha $	
**
**  This module manages an interface vector of the machine
**
*/

#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include "mclab.h"

static unsigned int num_ifaces = 0;
static struct iface iface_list[MAX_IF];

/*
** Builds up a vector with the interface of the machine. Calls to the other functions of 
** the module will fail if they are called before the vector is build.
**          
*/
void iface_init(void)
{
	int family;
	struct iface *iface;
	struct ifaddrs *ifaddr, *ifa;

	num_ifaces = 0;
	memset(iface_list, 0, sizeof(iface_list));

	if (getifaddrs(&ifaddr) == -1) {
		smclog(LOG_ERR, errno, "Failed to retrieve interface addresses");
		return;
	}

	for (ifa = ifaddr; ifa != NULL && num_ifaces < ARRAY_ELEMENTS(iface_list); ifa = ifa->ifa_next) {
		iface  = &iface_list[num_ifaces++];
		family = ifa->ifa_addr->sa_family;

		/* Skip non-IPv4 and non-IPv6 interfaces */
		if ((family != AF_INET) && (family != AF_INET6))
			continue;

		/* Skip interface without internet address */
		if (ifa->ifa_addr == NULL)
			continue;

		/* Copy data from interface iterator 'ifa' */
		strncpy(iface->name, ifa->ifa_name, sizeof(iface->name));
		if (family == AF_INET)
			iface->inaddr.s_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
		iface->flags = ifa->ifa_flags;
		iface->ifindex = if_nametoindex(iface->name);
		iface->vif = -1;
		iface->mif = -1;
	}
	freeifaddrs(ifaddr);
}

/*
** Returns a pointer to the iface of the interface 'ifname'
**
** returns: - pointer to the iface of the requested interface
**          - NULL if no interface 'ifname' exists
**          
**          - if more than one interface 'ifname' exists, chose the
**            an interface that corresponds to a virtual interface
*/
struct iface *iface_find_by_name(const char *ifname)
{
	unsigned int i;
	struct iface *iface;
	struct iface *candidate = NULL;

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

/*
** Returns a pointer to the iface of the interface 'ifindex'
**
** returns: - pointer to the iface of the requested interface
**          - NULL if no interface 'ifindex' exists
**          
*/
struct iface *iface_find_by_index(unsigned int ifindex)
{
	if (ifindex >= num_ifaces)
		return NULL;

	return &iface_list[ifindex];
}


/*
** Returns for the virtual interface index for '*iface'
**
** returns: - the virtual interface index if the interface is registered
**          - -1 if no virtual interface exists for the interface 
**          
*/
int iface_get_vif(struct iface *iface)
{
	if (iface == NULL)
		return -1;

	return iface->vif;
}

/*
** Returns for the virtual interface index for '*iface'
**
** returns: - the virtual interface index if the interface is registered
**          - -1 if no virtual interface exists for the interface 
**          
*/
int iface_get_mif(struct iface *iface __attribute__ ((unused)))
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
	return -1;
#else
	if (iface == NULL)
		return -1;

	return iface->mif;
#endif				/* HAVE_IPV6_MULTICAST_ROUTING */
}

/*
** Gets the VIF index for a given interface name
**
** returns: - index of the VIF
**          - -1 if no VIF can be found for the interface name
**          
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

/*
** Gets the MIF index for a given interface name
**
** returns: - index of the MIF
**          - -1 if no MIF can be found for the interface name
**          
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
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
