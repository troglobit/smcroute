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
#include "ifvc.h"
#include "socket.h"

static int mcgroup4_socket = -1;

#ifdef HAVE_LINUX_FILTER_H
/* Extremely simple "drop everything" filter for Linux so we do not get
 * a copy each packet of every routed group we join. */
static struct sock_filter filter[] = {
	{ 0x6, 0, 0, 0x00000000 },
};

static struct sock_fprog fprog = {
	sizeof(filter) / sizeof(filter[0]),
	filter
};
#endif /* HAVE_LINUX_FILTER_H */

static struct iface *find_valid_iface(const char *ifname)
{
	struct iface *iface;

	iface = iface_find_by_name(ifname);
	if (!iface) {
		smclog(LOG_DEBUG, "unknown interface %s", ifname);
		return NULL;
	}

	return iface;
}

static void mcgroup4_init(void)
{
	if (mcgroup4_socket < 0) {
		mcgroup4_socket = socket_create(AF_INET, SOCK_DGRAM, 0, NULL, NULL);
		if (mcgroup4_socket < 0) {
			smclog(LOG_ERR, "failed creating IPv4 mcgroup socket: %s", strerror(errno));
			exit(255);
		}

#ifdef HAVE_LINUX_FILTER_H
		if (setsockopt(mcgroup4_socket, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
			smclog(LOG_WARNING, "failed setting IPv4 socket filter, continuing anyway");
#endif
	}
}

static int mcgroup_join_leave_ipv4(int sd, int cmd, const char *ifname, struct in_addr group)
{
	struct ip_mreq mreq;
	struct iface *iface;

	iface = find_valid_iface(ifname);
	if (!iface)
		return 1;

	mreq.imr_multiaddr.s_addr = group.s_addr;
	mreq.imr_interface.s_addr = iface->inaddr.s_addr;
	if (setsockopt(sd, IPPROTO_IP, cmd == 'j' ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq))) {
		if (EADDRNOTAVAIL == errno && cmd == 'l')
			smclog(LOG_DEBUG, "failed leaving group, not a member of %s", inet_ntoa(group));
		else if (EADDRINUSE == errno && cmd == 'j')
			smclog(LOG_DEBUG, "failed joining group, already member of %s", inet_ntoa(group));
		else
			smclog(LOG_DEBUG, "failed group %s: %s", cmd == 'j' ? "join" : "leave", strerror(errno));
		return 1;
	}

	return 0;
}

static int mcgroup_join_leave_ssm_ipv4(int sd, int cmd, const char *ifname, struct in_addr source, struct in_addr group)
{
	int opt = cmd == 'j' ? IP_ADD_SOURCE_MEMBERSHIP : IP_DROP_SOURCE_MEMBERSHIP;
	struct iface *iface;
	struct ip_mreq_source mreqsrc;

	iface = find_valid_iface(ifname);
	if (!iface)
		return 1;

	mreqsrc.imr_multiaddr.s_addr  = group.s_addr;
	mreqsrc.imr_sourceaddr.s_addr = source.s_addr;
	mreqsrc.imr_interface.s_addr  = iface->inaddr.s_addr;
	if (setsockopt(sd, IPPROTO_IP, opt, &mreqsrc, sizeof(mreqsrc))) {
		if (EADDRNOTAVAIL == errno && cmd == 'j')
			smclog(LOG_DEBUG, "failed join, already member of %s", inet_ntoa(group));
		else if (EADDRNOTAVAIL == errno && cmd == 'l')
			smclog(LOG_DEBUG, "failed leave, not a member of %s from that source", inet_ntoa(group));
		else if (EINVAL == errno && cmd == 'l')
			smclog(LOG_DEBUG, "failed leave, not a member of %s", inet_ntoa(group));
		else
			smclog(LOG_WARNING, "failed %s: %s", cmd == 'j' ? "join" : "leave", strerror(errno));
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
		mcgroup6_socket = socket_create(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, NULL, NULL);
		if (mcgroup6_socket < 0) {
			smclog(LOG_WARNING, "failed creating IPv6 mcgroup socket: %s", strerror(errno));
			return;
		}

#ifdef HAVE_LINUX_FILTER_H
		if (setsockopt(mcgroup6_socket, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
			smclog(LOG_WARNING, "failed setting IPv6 socket filter, continuing anyway");
#endif
	}
}

static int mcgroup_join_leave_ipv6(int sd, int cmd, const char *ifname, struct in6_addr group)
{
	struct iface *iface;
	struct ipv6_mreq mreq;

	iface = find_valid_iface(ifname);
	if (!iface)
		return 1;

	mreq.ipv6mr_multiaddr = group;
	mreq.ipv6mr_interface = iface->ifindex;
	if (setsockopt(sd, IPPROTO_IPV6, cmd == 'j' ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, &mreq, sizeof(mreq))) {
		char buf[INET6_ADDRSTRLEN];

		if (EADDRNOTAVAIL == errno && cmd == 'l')
			smclog(LOG_DEBUG, "failed leaving group, not a member of %s",
			       inet_ntop(AF_INET6, &group, buf, sizeof(buf)));
		else if (EADDRINUSE == errno && cmd == 'j')
			smclog(LOG_DEBUG, "failed joining group, already member of %s",
			       inet_ntop(AF_INET6, &group, buf, sizeof(buf)));
		else
			smclog(LOG_DEBUG, "failed group %s: %s", cmd == 'j' ? "join" : "leave", strerror(errno));
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
