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

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "msg.h"
#include "ifvc.h"


/* -j/-l eth0 [1.1.1.1] 239.1.1.1
 *
 *  +----+-----+---+--------------------------------------------+
 *  | 32 | 'j' | 3 | "eth0\01.1.1.1\0239.1.1.1\0\0"             |
 *  +----+-----+---+--------------------------------------------+
 */
char *msg_to_mgroup4(struct ipc_msg *msg, struct in_addr *src, struct in_addr *grp)
{
	int ret = 0;

	if (msg->count == 3) {
		ret += inet_pton(AF_INET, msg->argv[1], src);
		ret += inet_pton(AF_INET, msg->argv[2], grp);
	} else {
		src->s_addr = 0;
		ret  = 1;
		ret += inet_pton(AF_INET, msg->argv[1], grp);
	}

	if (ret < 2)
		return NULL;

	return msg->argv[0];
}

char *msg_to_mgroup6(struct ipc_msg *msg, struct in6_addr *src, struct in6_addr *grp)
{
	int ret = 0;

	if (msg->count == 3) {
		ret += inet_pton(AF_INET6, msg->argv[1], src);
		ret += inet_pton(AF_INET6, msg->argv[2], grp);
	} else {
		memset(src, 0, sizeof(*src));
		ret = 1;
		ret += inet_pton(AF_INET6, msg->argv[1], grp);
	}

	if (ret < 2)
		return NULL;

	return msg->argv[0];
}

/**
 * msg_to_mroute - Convert IPC command from client to desired mulicast route
 * @mroute: Pointer to &struct mroute to convert to
 * @msg: Pointer to &struct ipc_msg IPC command
 *
 * Converts a @msg to an @mroute for the 'add' and 'remove' commands.
 * The IP version is determined by searching for ':' in the address
 * strings to indicate IPv6 addresses.
 *
 * Returns:
 * %NULL on success, or an error string with a hint why the operation failed.
 */
const char *msg_to_mroute(struct mroute *mroute, const struct ipc_msg *msg)
{
	if (msg->count < 2)
		return NULL;

	memset(mroute, 0, sizeof(*mroute));

	if (strchr(msg->argv[1], ':')) {
		mroute->version = 6;
		return msg_to_mroute6(&mroute->u.mroute6, msg);
	}

	mroute->version = 4;
	return msg_to_mroute4(&mroute->u.mroute4, msg);
}

/* check for prefix length, only applicable for (*,G) routes */
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

/* -a eth0 [1.1.1.1] 239.1.1.1 eth1 eth2
 *
 *  +----+-----+---+--------------------------------------------+
 *  | 42 | 'a' | 5 | "eth0\01.1.1.1\0239.1.1.1\0eth1\0eth2\0\0" |
 *  +----+-----+---+--------------------------------------------+
 *  ^              ^
 *  |              |
 *  |              |
 *  +-----cmd------+
 */
const char *msg_to_mroute4(struct mroute4 *mroute, const struct ipc_msg *msg)
{
	int len, pos = 0;
	struct in_addr src, grp;

	memset(mroute, 0, sizeof(*mroute));
	mroute->inbound = iface_get_vif_by_name(msg->argv[pos++]);
	if (mroute->inbound < 0)
		return "Invalid input interface";

	len = is_range(msg->argv[pos]);
	if (inet_pton(AF_INET, msg->argv[pos++], &src) <= 0)
		return "Invalid IPv4 source or group address";

	if (!IN_MULTICAST(ntohl(src.s_addr))) {
		len = is_range(msg->argv[pos]);
		if (inet_pton(AF_INET, msg->argv[pos++], &grp) <= 0 || !IN_MULTICAST(ntohl(grp.s_addr)))
			return "Invalid IPv4 group address";

		if (len && (len < 0 || len > 32))
			return "Invalid prefix length (/LEN), must be 0-32";
	} else {
		grp = src;
		src.s_addr = htonl(INADDR_ANY);
	}

	mroute->sender = src;
	mroute->len    = len;
	mroute->group  = grp;

	if (len && mroute->sender.s_addr != htonl(INADDR_ANY))
		return "GROUP/LEN not yet supported for source specific multicast.";

	/*
	 * Scan output interfaces for the 'add' command only, just
	 * ignore it for the 'remove' command.
	 */
	if (msg->cmd == 'a') {
		while (pos < msg->count) {
			int vif;
			char *ifname = msg->argv[pos++];

			vif = iface_get_vif_by_name(ifname);
			if (vif < 0)
				return "Invalid output interface";

			if (vif == mroute->inbound)
				smclog(LOG_WARNING, 0, "Same outbound interface as inbound %s?", ifname);

			mroute->ttl[vif] = 1;	/* Use a TTL threshold */
		}
	}

	return NULL;
}

const char *msg_to_mroute6(struct mroute6 *mroute, const struct ipc_msg *msg)
{
	int pos = 0;

	memset(mroute, 0, sizeof(*mroute));
	mroute->inbound = iface_get_mif_by_name(msg->argv[pos++]);
	if (mroute->inbound < 0)
		return "Invalid input interface";

	if (inet_pton(AF_INET6, msg->argv[pos++], &mroute->sender.sin6_addr) <= 0)
		return "Invalid IPv6 source address";

	if (inet_pton(AF_INET6, msg->argv[pos++], &mroute->group.sin6_addr) <= 0 ||
	    !IN6_IS_ADDR_MULTICAST(&mroute->group.sin6_addr))
		return "Invalid IPv4 group address";

	/*
	 * Scan output interfaces for the 'add' command only, just ignore it
	 * for the 'remove' command to be compatible to the first release.
	 */
	if (msg->cmd == 'a') {
		while (pos < msg->count) {
			int mif;
			char *ifname = msg->argv[pos++];

			mif = iface_get_mif_by_name(ifname);
			if (mif < 0)
				return "Invalid output interface";

			if (mif == mroute->inbound)
				smclog(LOG_WARNING, 0, "Same outbound interface as inbound %s?", ifname);

			mroute->ttl[mif] = 1;	/* Use a TTL threashold */
		}
	}

	return NULL;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
