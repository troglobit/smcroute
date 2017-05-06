/* IPC command parser and builder for daemon and client
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
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "msg.h"
#include "ifvc.h"
#include "mroute.h"
#include "mcgroup.h"

extern int running;
extern void reload(int signo);


static int do_mgroup4(struct ipc_msg *msg)
{
	int ret = 0;
	char *ifname = msg->argv[0];
	struct in_addr src, grp;

	if (msg->count == 3) {
		ret += inet_pton(AF_INET, msg->argv[1], &src);
		ret += inet_pton(AF_INET, msg->argv[2], &grp);
	} else {
		src.s_addr = htonl(INADDR_ANY);
		ret  = 1;
		ret += inet_pton(AF_INET, msg->argv[1], &grp);
	}

	if (ret < 2 || !IN_MULTICAST(ntohl(grp.s_addr))) {
		smclog(LOG_DEBUG, "Invalid IPv4 source or group address.");
		return 1;
	}

	if (msg->cmd == 'j')
		return mcgroup4_join(ifname, src, grp);

	return mcgroup4_leave(ifname, src, grp);
}

static int do_mgroup6(struct ipc_msg *msg)
{
#ifndef HAVE_IPV6_MULTICAST_HOST
	(void)msg;
	smclog(LOG_WARNING, "IPv6 multicast support disabled.");
	return 1;
#else
	int ret = 0;
	char *ifname = msg->argv[0];
	struct in6_addr src, grp;

	if (msg->count == 3) {
		ret += inet_pton(AF_INET6, msg->argv[1], &src);
		ret += inet_pton(AF_INET6, msg->argv[2], &grp);
	} else {
		memset(&src, 0, sizeof(src));
		ret = 1;
		ret += inet_pton(AF_INET6, msg->argv[1], &grp);
	}

	if (ret < 2 || !IN6_IS_ADDR_MULTICAST(&grp)) {
		smclog(LOG_DEBUG, "Invalid IPv6 source or group address.");
		return 1;
	}

	if (msg->cmd == 'j')
		return mcgroup6_join(ifname, grp);

	return mcgroup6_leave(ifname, grp);
#endif
}

/*
 * Check for prefix length, only applicable for (*,G) routes
 */
static int is_range(char *arg)
{
	char *ptr;

	ptr = strchr(arg, '/');
	if (ptr) {
		*ptr++ = 0;
		return atoi(ptr);
	}

	return 0;
}

static int do_mroute4(struct ipc_msg *msg)
{
	int len, pos = 0;
	struct mroute4 mroute;
	struct in_addr src, grp;

	memset(&mroute, 0, sizeof(mroute));
	mroute.inbound = iface_get_vif_by_name(msg->argv[pos++]);
	if (mroute.inbound < 0) {
		smclog(LOG_DEBUG, "Invalid input interface");
		return 1;
	}

	len = is_range(msg->argv[pos]);
	if (inet_pton(AF_INET, msg->argv[pos++], &src) <= 0) {
		smclog(LOG_DEBUG, "Invalid IPv4 source or group address");
		return 1;
	}

	if (!IN_MULTICAST(ntohl(src.s_addr))) {
		len = is_range(msg->argv[pos]);
		if (inet_pton(AF_INET, msg->argv[pos++], &grp) <= 0 || !IN_MULTICAST(ntohl(grp.s_addr))) {
			smclog(LOG_DEBUG, "Invalid IPv4 group address");
			return 1;
		}

		if (len && (len < 0 || len > 32)) {
			smclog(LOG_DEBUG, "Invalid prefix length (/LEN), must be 0-32");
			return 1;
		}
	} else {
		grp = src;
		src.s_addr = htonl(INADDR_ANY);
	}

	mroute.sender  = src;
	mroute.len     = len;
	mroute.group   = grp;

	if (len && mroute.sender.s_addr != htonl(INADDR_ANY)) {
		smclog(LOG_DEBUG, "GROUP/LEN not yet supported for source specific multicast routes.");
		return 1;
	}

	/*
	 * Scan output interfaces for the 'add' command only, just
	 * ignore it for the 'remove' command.
	 */
	if (msg->cmd == 'a') {
		if (pos >= msg->count) {
			smclog(LOG_DEBUG, "Missing outbound interface");
			return 1;
		}

		while (pos < msg->count) {
			int vif;
			char *ifname = msg->argv[pos++];

			vif = iface_get_vif_by_name(ifname);
			if (vif < 0) {
				smclog(LOG_DEBUG, "Invalid output interface");
				return 1;
			}

			if (vif == mroute.inbound)
				smclog(LOG_WARNING, "Same outbound interface as inbound %s?", ifname);

			mroute.ttl[vif] = 1;	/* Use a TTL threshold */
		}

		return mroute4_add(&mroute);
	}

	return mroute4_del(&mroute);
}

static int do_mroute6(struct ipc_msg *msg)
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
	(void)msg;
	smclog(LOG_WARNING, "IPv6 multicast support disabled.");
	return 1;
#else
	int pos = 0;
	struct mroute6 mroute;

	memset(&mroute, 0, sizeof(mroute));
	mroute.inbound = iface_get_mif_by_name(msg->argv[pos++]);
	if (mroute.inbound < 0) {
		smclog(LOG_DEBUG, "Invalid input interface");
		return 1;
	}

	if (inet_pton(AF_INET6, msg->argv[pos++], &mroute.sender.sin6_addr) <= 0) {
		smclog(LOG_DEBUG, "Invalid IPv6 source address");
		return 1;
	}

	if (inet_pton(AF_INET6, msg->argv[pos++], &mroute.group.sin6_addr) <= 0 ||
	    !IN6_IS_ADDR_MULTICAST(&mroute.group.sin6_addr)) {
		smclog(LOG_DEBUG, "Invalid IPv6 group address");
		return 1;
	}

	/*
	 * Scan output interfaces for the 'add' command only, just ignore it
	 * for the 'remove' command to be compatible to the first release.
	 */
	if (msg->cmd == 'a') {
		if (pos >= msg->count) {
			smclog(LOG_DEBUG, "Missing outbound interface");
			return 1;
		}

		while (pos < msg->count) {
			int mif;
			char *ifname = msg->argv[pos++];

			mif = iface_get_mif_by_name(ifname);
			if (mif < 0) {
				smclog(LOG_DEBUG, "Invalid output interface");
				return 1;
			}

			if (mif == mroute.inbound)
				smclog(LOG_DEBUG, "Same outbound interface as inbound %s?", ifname);

			mroute.ttl[mif] = 1;	/* Use a TTL threshold */
		}

		return mroute6_add(&mroute);
	}

	return mroute6_del(&mroute);
#endif
}

static int do_mroute(struct ipc_msg *msg)
{
	if (msg->count < 2) {
		errno = EINVAL;
		return -1;
	}

	if (strchr(msg->argv[1], ':'))
		return do_mroute6(msg);

	return do_mroute4(msg);
}

static int do_mgroup(struct ipc_msg *msg)
{
	if (msg->count < 2) {
		errno = EINVAL;
		return -1;
	}

	if (strchr(msg->argv[1], ':'))
		return do_mgroup6(msg);

	return do_mgroup4(msg);
}

/*
 * Convert IPC command from client to a mulicast route or group join/leave
 */
int msg_do(int sd, struct ipc_msg *msg)
{
	int result = 0;

	switch (msg->cmd) {
	case 'a':
	case 'r':
		result = do_mroute(msg);
		break;

	case 'j':
	case 'l':
		result = do_mgroup(msg);
		break;

	case 'F':
		mroute4_dyn_expire(0);
		break;

	case 'H':		/* HUP */
		reload(0);
		break;

	case 'k':
		running = 0;
		break;

	case 's':
		result = mroute_show(sd);
		break;

	default:
		errno = EINVAL;
		result = -1;
	}

	return result;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
