/* Kernel API for join/leave multicast groups and add/del routes
 *
 * Copyright (c) 2011-2020  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <string.h>

#include "log.h"
#include "ifvc.h"
#include "mcgroup.h"


/*
 * This function handles both ASM and SSM join/leave for IPv4 and IPv6
 * using the RFC 3678 API available on Linux, FreeBSD, and a few other
 * operating systems.
 *
 * On Linux this makes it possible to join a group on an interface that
 * is down and/or has no IP address assigned to it yet.  The latter is
 * one of the most common causes of malfunction on Linux and IPv4 with
 * the old struct ip_mreq API.
 */
#ifdef HAVE_STRUCT_GROUP_REQ	/* Prefer RFC 3678 */
static size_t group_req(int sd, int cmd, struct mcgroup *mcg)
{
	struct group_source_req gsr;
	struct sockaddr_in group;
	struct group_req gr;
	uint32_t addr = 0, addr_max = 0;
	size_t len;
	void *arg;
	int op, proto;
	int rc = 0;

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (mcg->group.ss_family == AF_INET6)
		proto = IPPROTO_IPV6;
	else
#endif
		proto = IPPROTO_IP;

	if (mcg->group.ss_family == AF_INET) {
		int mask;

		group = *(struct sockaddr_in *)&mcg->group;

		if (mcg->len > 0)
			mask = 0xFFFFFFFFu << (32 - mcg->len);
		else
			mask = 0xFFFFFFFFu;

		addr = ntohl(group.sin_addr.s_addr) & mask;
		addr_max = addr | ~mask;
	}

	while (addr <= addr_max) {
		if (addr) {
			struct sockaddr_in *sin;

			sin = (struct sockaddr_in *)&mcg->group;
			sin->sin_addr.s_addr = htonl(addr);
		}
		addr++;

		if (is_anyaddr(&mcg->source)) {
			if (cmd == 'j')	op = MCAST_JOIN_GROUP;
			else		op = MCAST_LEAVE_GROUP;

			gr.gr_interface    = mcg->iface->ifindex;;
			gr.gr_group        = mcg->group;

			arg                = &gr;
			len                = sizeof(gr);
		} else {
			if (cmd == 'j')	op = MCAST_JOIN_SOURCE_GROUP;
			else		op = MCAST_LEAVE_SOURCE_GROUP;

			gsr.gsr_interface  = mcg->iface->ifindex;;
			gsr.gsr_source     = mcg->source;
			gsr.gsr_group      = mcg->group;

			arg                = &gsr;
			len                = sizeof(gsr);
		}

		rc = setsockopt(sd, proto, op, arg, len);
		if (rc) {
			if (cmd == 'j' && errno == EADDRINUSE)
				continue; /* Already joined, ignore */
			break;
		}
	}

	if (addr) {
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *)&mcg->group;
		*sin = group;
	}

	return rc;
}

#else  /* Assume we have old style struct ip_mreq */

static size_t group_req(int sd, int cmd, struct mcgroup *mcg, void *arg)
{
	struct ip_mreq_source mreqsrc;
#ifdef HAVE_IPV6_MULTICAST_HOST
	struct ipv6_mreq ipv6mr;
#endif
	struct ip_mreq ipmr;
	size_t len;
	void *arg;
	int op, proto;

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (mcg->group.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)&mcg->group;
		ipv6mr.ipv6mr_multiaddr = sin6->sin6_addr;
		ipv6mr.ipv6mr_interface = mcg->iface->ifindex;
		proto = IPPROTO_IPV6;
	} else
#endif
	{
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *)&mcg->group;
		ipmr.imr_multiaddr = sin->sin_addr;
		ipmr.imr_interface = mcg->iface->inaddr;
		proto = IPPROTO_IP;
	}

	if (is_anyaddr(&mcg->source)) {
		if (cmd == 'j')	op = IP_ADD_MEMBERSHIP;
		else		op = IP_DROP_MEMBERSHIP;
	} else {
		if (cmd == 'j')	op = IP_ADD_SOURCE_MEMBERSHIP;
		else		op = IP_DROP_SOURCE_MEMBERSHIP;
	}

	return setsockopt(sd, proto, op, arg, len);
}
#endif

int kern_join_leave(int sd, int cmd, struct mcgroup *mcg)
{
	int err;

	if (!cmd)
		cmd = 'j';

	err = group_req(sd, cmd, mcg);
	if (err) {
		char source[INET_ADDRSTR_LEN] = "*";
		char group[INET_ADDRSTR_LEN];
		int len;

		if (!is_anyaddr(&mcg->source))
			convert_address(&mcg->source, source, sizeof(source));
		convert_address(&mcg->group, group, sizeof(group));
		len = mcg->len == 0 ? 32 : mcg->len;

		smclog(LOG_ERR, "Failed %s group (%s,%s/%d) on sd %d ... %d: %s",
		       cmd == 'j' ? "joining" : "leaving",
		       source, group, len, sd,
		       errno, strerror(errno));
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
