/* Multicast group management (join/leave) API
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

#include "mclab.h"

static int mcgroup4_socket = -1;

#ifdef __linux__
/* Extremely simple "drop everything" filter for Linux so we do not get
 * a copy each packet of every routed group we join. */
static struct sock_filter filter[] = {
	{ 0x6, 0, 0, 0x00000000 },
};

static struct sock_fprog fprog = {
	sizeof(filter) / sizeof(filter[0]),
	filter
};
#endif

static struct iface *find_valid_iface(const char *ifname, int cmd)
{
	const char *command = cmd == 'j' ? "Join" : "Leave";
	struct iface *iface = iface_find_by_name(ifname);

	if (!iface) {
		smclog(LOG_WARNING, "%s multicast group, unknown interface %s", command, ifname);
		return NULL;
	}

	return iface;
}

static void mcgroup4_init(void)
{
	if (mcgroup4_socket < 0) {
		mcgroup4_socket = create_socket(AF_INET, SOCK_DGRAM, 0);
		if (mcgroup4_socket < 0) {
			smclog(LOG_ERR, "Failed creating socket for joining IPv4 multicast groups: %s", strerror(errno));
			exit(255);
		}

#ifdef __linux__
		if (setsockopt(mcgroup4_socket, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
			smclog(LOG_DEBUG, "Failed setting IPv4 socket filter, continuing anyway");
#endif
	}
}

static int mcgroup_join_leave_ipv4(int sd, int cmd, const char *ifname, struct in_addr group)
{
	int joinleave = cmd == 'j' ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP;
	struct ip_mreq mreq;
	struct iface *iface = find_valid_iface(ifname, cmd);

	if (!iface)
		return 1;

	mreq.imr_multiaddr.s_addr = group.s_addr;
	mreq.imr_interface.s_addr = iface->inaddr.s_addr;
	if (setsockopt(sd, IPPROTO_IP, joinleave, (void *)&mreq, sizeof(mreq))) {
		if (EADDRINUSE != errno)
			smclog(LOG_WARNING, "%s MEMBERSHIP failed: %s", cmd == 'j' ? "ADD" : "DROP", strerror(errno));
		return 1;
	}

	return 0;
}

static int mcgroup_join_leave_ssm_ipv4(int sd, int cmd, const char *ifname, struct in_addr source, struct in_addr group)
{
	int joinleave = cmd == 'j' ? IP_ADD_SOURCE_MEMBERSHIP : IP_DROP_SOURCE_MEMBERSHIP;
	struct ip_mreq_source mreqsrc;
	struct iface *iface = find_valid_iface(ifname, cmd);

	if (!iface)
		return 1;

	mreqsrc.imr_multiaddr.s_addr = group.s_addr;
	mreqsrc.imr_sourceaddr.s_addr = source.s_addr;
	mreqsrc.imr_interface.s_addr = iface->inaddr.s_addr;
	if (setsockopt(sd, IPPROTO_IP, joinleave, (void *)&mreqsrc, sizeof(mreqsrc))) {
		if (EADDRINUSE != errno)
			smclog(LOG_WARNING, "%s SOURCE_MEMBERSHIP failed: %s", cmd == 'j' ? "ADD" : "DROP", strerror(errno));
		return 1;
	}

	return 0;
}

/*
 * Joins the MC group with the address 'group' on the interface 'ifname'.
 * The join is bound to the UDP socket 'sd', so if this socket is
 * closed the membership is dropped.
 *
 * returns: - 0 if the function succeeds
 *          - 1 if parameters are wrong or the join fails
 */
int mcgroup4_join(const char *ifname, struct in_addr source, struct in_addr group)
{
	mcgroup4_init();

	if (!source.s_addr)
		return mcgroup_join_leave_ipv4(mcgroup4_socket, 'j', ifname, group);

	return mcgroup_join_leave_ssm_ipv4(mcgroup4_socket, 'j', ifname, source, group);
}

/*
 * Leaves the MC group with the address 'group' on the interface 'ifname'.
 *
 * returns: - 0 if the function succeeds
 *          - 1 if parameters are wrong or the join fails
 */
int mcgroup4_leave(const char *ifname, struct in_addr source, struct in_addr group)
{
	mcgroup4_init();

	if (!source.s_addr)
		return mcgroup_join_leave_ipv4(mcgroup4_socket, 'l', ifname, group);

	return mcgroup_join_leave_ssm_ipv4(mcgroup4_socket, 'l', ifname, source, group);
}

/*
 * Close IPv4 multicast socket to kernel to leave any joined groups
 */
void mcgroup4_disable(void)
{
	if (mcgroup4_socket != -1) {
		close(mcgroup4_socket);
		mcgroup4_socket = -1;
	}
}

#ifdef HAVE_IPV6_MULTICAST_HOST
static int mcgroup6_socket = -1;

static void mcgroup6_init(void)
{
	if (mcgroup6_socket < 0) {
		mcgroup6_socket = create_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (mcgroup6_socket < 0) {
			smclog(LOG_WARNING, "Failed creating socket for joining IPv6 multicast groups: %s", strerror(errno));
			return;
		}

#ifdef __linux__
		if (setsockopt(mcgroup6_socket, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
			smclog(LOG_DEBUG, "Failed setting IPv6 socket filter, continuing anyway");
#endif
	}
}

static int mcgroup_join_leave_ipv6(int sd, int cmd, const char *ifname, struct in6_addr group)
{
	int joinleave = cmd == 'j' ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP;
	struct ipv6_mreq mreq;
	struct iface *iface = find_valid_iface(ifname, cmd);

	if (!iface)
		return 1;

	mreq.ipv6mr_multiaddr = group;
	mreq.ipv6mr_interface = iface->ifindex;
	if (setsockopt(sd, IPPROTO_IPV6, joinleave, (void *)&mreq, sizeof(mreq))) {
		if (EADDRINUSE != errno)
			smclog(LOG_WARNING, "%s MEMBERSHIP failed: %s", cmd == 'j' ? "ADD" : "DROP", strerror(errno));
		return 1;
	}

	return 0;
}

/*
 * Joins the MC group with the address 'group' on the interface 'ifname'.
 * The join is bound to the UDP socket 'sd', so if this socket is
 * closed the membership is dropped.
 *
 * returns: - 0 if the function succeeds
 *          - 1 if parameters are wrong or the join fails
 */
int mcgroup6_join(const char *ifname, struct in6_addr group)
{
	mcgroup6_init();

	return mcgroup_join_leave_ipv6(mcgroup6_socket, 'j', ifname, group);
}

/*
 * Leaves the MC group with the address 'group' on the interface 'ifname'.
 *
 * returns: - 0 if the function succeeds
 *          - 1 if parameters are wrong or the join fails
 */
int mcgroup6_leave(const char *ifname, struct in6_addr group)
{
	mcgroup6_init();

	return mcgroup_join_leave_ipv6(mcgroup6_socket, 'l', ifname, group);
}
#endif /* HAVE_IPV6_MULTICAST_HOST */

/*
 * Close IPv6 multicast socket to kernel to leave any joined groups
 */
void mcgroup6_disable(void)
{
#ifdef HAVE_IPV6_MULTICAST_HOST
	if (mcgroup6_socket != -1) {
		close(mcgroup6_socket);
		mcgroup6_socket = -1;
	}
#endif /* HAVE_IPV6_MULTICAST_HOST */
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
