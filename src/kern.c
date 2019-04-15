/* Kernel API for join/leave multicast groups and add/del routes
 *
 * Copyright (c) 2011-2019  Joachim Nilsson <troglobit@gmail.com>
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

int kern_join_leave(int sd, int cmd, struct mcgroup *mcg)
{
#ifdef HAVE_STRUCT_GROUP_REQ	/* Prefer RFC 3678 */
	struct group_source_req gsr;
	struct group_req gr;
	size_t len;
	void *arg;
	int op, proto;

	if (!cmd)
		cmd = 'j';

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (mcg->group.ss_family == AF_INET6)
		proto = IPPROTO_IPV6;
	else
#endif
		proto = IPPROTO_IP;

	if (is_anyaddr(&mcg->source)) {
		if (cmd == 'j')	op = MCAST_JOIN_GROUP;
		else		op = MCAST_LEAVE_GROUP;

		gr.gr_interface    = mcg->ifindex;
		gr.gr_group        = mcg->group;

		arg                = &gr;
		len                = sizeof(gr);
	} else {
		if (cmd == 'j')	op = MCAST_JOIN_SOURCE_GROUP;
		else		op = MCAST_LEAVE_SOURCE_GROUP;

		gsr.gsr_interface  = mcg->ifindex;
		gsr.gsr_source     = mcg->source;
		gsr.gsr_group      = mcg->group;

		arg                = &gsr;
		len                = sizeof(gsr);
	}
#else  /* Assume we have old style struct ip_mreq */
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
		ipv6mr.ipv6mr_interface = mcg->ifindex;
		proto = IPPROTO_IPV6;
	} else
#endif
	{
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *)&mcg->group;
		ipmr.imr_multiaddr = sin->sin_addr;
		proto = IPPROTO_IP;
	}

	if (is_anyaddr(&mcg->source)) {
		if (cmd == 'j')	op = IP_ADD_MEMBERSHIP;
		else		op = IP_DROP_MEMBERSHIP;
	} else {
		if (cmd == 'j')	op = IP_ADD_SOURCE_MEMBERSHIP;
		else		op = IP_DROP_SOURCE_MEMBERSHIP;
	}
#endif
	if (setsockopt(sd, proto, op, arg, len)) {
		char source[INET_ADDRSTR_LEN] = "*";
		char group[INET_ADDRSTR_LEN];

		if (!is_anyaddr(&mcg->source))
			convert_address(&mcg->source, source, sizeof(source));
		convert_address(&mcg->group, group, sizeof(group));

		smclog(LOG_ERR, "Failed %s group (%s,%g) on sd %d ... %d: %s",
		       source, group,
		       cmd == 'j' ? "joining" : "leaving",
		       sd, errno, strerror(errno));
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
