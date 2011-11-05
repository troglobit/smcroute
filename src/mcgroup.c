/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006-2009 Julien BLACHE <jb@jblache.org>
**  Copyright (C) 2009      Todd Hayton <todd.hayton@gmail.com>
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
**  $Id: mcgroup.c 85 2011-08-08 16:47:53Z micha $	
**
**  This module contains the remaining functions that where not placed in 
**  separate modules
**
*/

#include "mclab.h"

static int mcgroup4_socket = -1;

static void mcgroup4_init(void)
{
	if (mcgroup4_socket < 0) {
		mcgroup4_socket = udp_socket_open(INADDR_ANY, 0);
	}
}

static int mcgroup_join_leave_ipv4(int sd, int cmd, const char *ifname, struct in_addr group)
{
	int joinleave = cmd == 'j' ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
	char buf[INET_ADDRSTRLEN];
	const char *command = cmd == 'j' ? "Join" : "Leave";
	struct ip_mreq mreq;
	struct iface *iface = iface_find_by_name(ifname);

	if (!iface) {
		smclog(LOG_WARNING, 0, "%s multicast group, unknown interface %s", command, ifname);
		return 1;
	}

	smclog(LOG_NOTICE, 0, "%s multicast group: %s on %s", command,
	       inet_ntop(AF_INET, &group, buf, sizeof(buf)), iface ? iface->name : "<any>");

	mreq.imr_multiaddr.s_addr = group.s_addr;
	mreq.imr_interface.s_addr = iface->inaddr.s_addr;
	if (setsockopt(sd, IPPROTO_IP, joinleave, (void *)&mreq, sizeof(mreq))) {
		if (EADDRINUSE != errno)
			smclog(LOG_WARNING, errno, "%s MEMBERSHIP failed", cmd == 'j' ? "ADD" : "DROP");
		return 1;
	}

	return 0;
}

/*
** Joins the MC group with the address 'group' on the interface 'ifname'. 
** The join is bound to the UDP socket 'sd', so if this socket is 
** closed the membership is dropped.
**          
** returns: - 0 if the function succeeds
**          - 1 if parameters are wrong or the join fails
*/
int mcgroup4_join(const char *ifname, struct in_addr group)
{
	mcgroup4_init();

	return mcgroup_join_leave_ipv4(mcgroup4_socket, 'j', ifname, group);
}

/*
** Leaves the MC group with the address 'group' on the interface 'ifname'. 
**          
** returns: - 0 if the function succeeds
**          - 1 if parameters are wrong or the join fails
*/
int mcgroup4_leave(const char *ifname, struct in_addr group)
{
	mcgroup4_init();

	return mcgroup_join_leave_ipv4(mcgroup4_socket, 'l', ifname, group);
}

#ifdef HAVE_IPV6_MULTICAST_HOST
static int mcgroup6_socket = -1;

static void mcgroup6_init(void)
{
	if (mcgroup6_socket < 0) {
		mcgroup6_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (mcgroup6_socket < 0)
			smclog(LOG_WARNING, errno, "socket failed");
	}
}

static int mcgroup_join_leave_ipv6(int sd, int cmd, const char *ifname, struct in6_addr group)
{
	int joinleave = cmd == 'j' ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP;
	char buf[INET6_ADDRSTRLEN];
	const char *command = cmd == 'j' ? "Join" : "Leave";
	struct ipv6_mreq mreq;
	struct iface *iface = iface_find_by_name(ifname);

	if (!iface) {
		smclog(LOG_WARNING, 0, "%s multicast group, unknown interface %s", command, ifname);
		return 1;
	}

	smclog(LOG_NOTICE, 0, "%s multicast group: %s on %s", command,
	       inet_ntop(AF_INET6, &group, buf, sizeof(buf)), iface ? iface->name : "<any>");

	mreq.ipv6mr_multiaddr = group;
	mreq.ipv6mr_interface = iface->ifindex;
	if (setsockopt(sd, IPPROTO_IPV6, joinleave, (void *)&mreq, sizeof(mreq))) {
		if (EADDRINUSE != errno)
			smclog(LOG_WARNING, errno, "%s MEMBERSHIP failed", cmd == 'j' ? "ADD" : "DROP");
		return 1;
	}

	return 0;
}

/*
** Joins the MC group with the address 'group' on the interface 'ifname'.
** The join is bound to the UDP socket 'sd', so if this socket is
** closed the membership is dropped.
**
** returns: - 0 if the function succeeds
**          - 1 if parameters are wrong or the join fails
*/
int mcgroup6_join(const char *ifname, struct in6_addr group)
{
	mcgroup6_init();

	return mcgroup_join_leave_ipv6(mcgroup6_socket, 'j', ifname, group);
}

/*
** Leaves the MC group with the address 'group' on the interface 'ifname'.
**
** returns: - 0 if the function succeeds
**          - 1 if parameters are wrong or the join fails
*/
int mcgroup6_leave(const char *ifname, struct in6_addr group)
{
	mcgroup6_init();

	return mcgroup_join_leave_ipv6(mcgroup6_socket, 'l', ifname, group);
}
#endif				/* HAVE_IPV6_MULTICAST_HOST */

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
