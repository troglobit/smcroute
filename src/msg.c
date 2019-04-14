/* IPC command parser and builder for daemon and client
 *
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
#include <signal.h>		/* sig_atomic_t */
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "msg.h"
#include "ifvc.h"
#include "util.h"
#include "mroute.h"
#include "mcgroup.h"

extern volatile sig_atomic_t running;
extern volatile sig_atomic_t reloading;

/*
 * Check for prefix length, only applicable for (*,G) routes
 */
int is_range(char *arg)
{
	char *ptr;

	ptr = strchr(arg, '/');
	if (ptr) {
		*ptr++ = 0;
		return atoi(ptr);
	}

	return 0;
}

static int do_mgroup4(struct ipc_msg *msg)
{
	struct in_addr src, grp;
	char *ifname = msg->argv[0];
	char group[20];
	int len, ret = 0;

	if (msg->count == 3) {
		strlcpy(group, msg->argv[2], sizeof(group));
		ret += inet_pton(AF_INET, msg->argv[1], &src);
	} else {
		strlcpy(group, msg->argv[1], sizeof(group));
		src.s_addr = htonl(INADDR_ANY);
		ret = 1;
	}

	len = is_range(group);
	if (len < 0 || len > 32) {
		smclog(LOG_DEBUG, "Invalid IPv4 group prefix length (0-32): %d", len);
		return 1;
	}

	ret += inet_pton(AF_INET, group, &grp);
	if (ret < 2 || !IN_MULTICAST(ntohl(grp.s_addr))) {
		smclog(LOG_DEBUG, "Invalid IPv4 source or group address.");
		return 1;
	}

	if (msg->cmd == 'j')
		return mcgroup4_join(ifname, src, grp, len);

	return mcgroup4_leave(ifname, src, grp, len);
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

static int do_mroute4(struct ipc_msg *msg)
{
	struct ifmatch state_in;
	int result = 0;
	/* Only emit first non-fatal error message as that's the most relevant */
	int errmsg = 0;

	iface_match_init(&state_in);
	while (1) {
		int len, src_len, pos = 0, vif;
		struct mroute4 mroute;
		struct ifmatch state_out;
		struct in_addr src, grp;
		char *ifname_in = msg->argv[pos++];

		vif = iface_match_vif_by_name(ifname_in, &state_in, NULL);
		if (vif < 0)
			break;
		memset(&mroute, 0, sizeof(mroute));
		mroute.inbound = vif;

		src_len = is_range(msg->argv[pos]);
		if (src_len && (src_len < 0 || src_len > 32)) {
			smclog(LOG_DEBUG, "Invalid prefix length (/LEN), must be 0-32");
			return 1;
		}

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
			len = src_len;
			src_len = 0;
			src.s_addr = htonl(INADDR_ANY);
		}

		mroute.src_len = src_len;
		mroute.source  = src;
		mroute.len     = len;
		mroute.group   = grp;

		/*
		 * Scan output interfaces for the 'add' command only, just
		 * ignore it for the 'remove' command.
		 */
		if (msg->cmd == 'a') {
			if (pos >= msg->count) {
				smclog(LOG_DEBUG, "Missing outbound interface");
				return 1;
			}

			int total = 0;
			while (pos < msg->count) {
				char *ifname_out = msg->argv[pos++];

				iface_match_init(&state_out);
				while ((vif = iface_match_vif_by_name(ifname_out, &state_out, NULL)) >= 0) {
					if (vif == mroute.inbound) {
						/* In case of wildcard match in==out is normal, so don't complain */
						if (!ifname_is_wildcard(ifname_in) && !ifname_is_wildcard(ifname_out) && !errmsg++)
							smclog(LOG_WARNING, "Same outbound interface (%s) as inbound (%s) may cause routing loops.", ifname_out, ifname_in);
					}
					mroute.ttl[vif] = 1;	/* Use a TTL threshold */
					total++;
				}

				if (!state_out.match_count && !errmsg++)
					smclog(LOG_DEBUG, "Invalid output interface");
			}

			if (!total) {
				if (!errmsg++)
					smclog(LOG_DEBUG, "No valid output interfaces");
				result += 1;
			} else {
				result += mroute4_add(&mroute);
			}
		} else {
			result += mroute4_del(&mroute);
		}
	}

	if (!state_in.match_count) {
		smclog(LOG_DEBUG, "Invalid input interface");
		return 1;
	}
	return result;
}

static int do_mroute6(struct ipc_msg *msg)
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
	(void)msg;
	smclog(LOG_WARNING, "IPv6 multicast support disabled.");
	return 1;
#else
	struct ifmatch state_in;
	int result = 0;
	/* Only emit first non-fatal error message as that's the most relevant */
	int errmsg = 0;

	iface_match_init(&state_in);
	while (1) {
		int len = 0, pos = 0, mif;
		struct mroute6 mroute;
		struct ifmatch state_out;
		char *ifname_in = msg->argv[pos++];

		mif = iface_match_mif_by_name(ifname_in, &state_in, NULL);
		if (mif < 0)
			break;

		memset(&mroute, 0, sizeof(mroute));
		mroute.inbound = mif;
		mroute.src_len = 128;
		mroute.len = 128;

		if ((len = is_range(msg->argv[pos])) != 0)
		{
			mroute.src_len = len;
		}

		if (inet_pton(AF_INET6, msg->argv[pos++], &mroute.source.sin6_addr) <= 0) {
			smclog(LOG_DEBUG, "Invalid IPv6 source or group address %s", msg->argv[pos-1]);
			return 1;
		}

		if (IN6_IS_ADDR_ANY(&mroute.source.sin6_addr))
		{
			mroute.src_len = 0;
		}

		if (mroute.src_len < 0 || mroute.src_len > 128) {
			smclog(LOG_DEBUG, "Invalid prefix length (/LEN), must be 0-128");
			return 1;
		}

		if (!IN6_IS_ADDR_MULTICAST(&mroute.source.sin6_addr))
		{
			if ((len = is_range(msg->argv[pos])) != 0)
			{
				mroute.len = len;
			}

			if (inet_pton(AF_INET6, msg->argv[pos++], &mroute.group.sin6_addr) <= 0 ||
					(!IN6_IS_ADDR_MULTICAST(&mroute.group.sin6_addr) &&
					 !IN6_IS_ADDR_ANY(&mroute.group.sin6_addr))) {
				smclog(LOG_DEBUG, "Invalid IPv6 group address");
				return 1;
			}

			if (IN6_IS_ADDR_ANY(&mroute.group.sin6_addr))
			{
				mroute.len = 0;
			}

			if (mroute.len < 0 || mroute.len > 128) {
				smclog(LOG_DEBUG, "Invalid prefix length (/LEN), must be 0-128");
				return 1;
			}
		}
		else
		{
			mroute.group = mroute.source;
			mroute.len = mroute.src_len;
			mroute.src_len = 0;
			mroute.source.sin6_addr = in6addr_any;
		}

		if (mroute.len > 0 && mroute.len < 128)
		{
		    smclog(LOG_WARNING, "GROUP/LEN not supported yet");
		}

		/*
		 * Scan output interfaces for the 'add' command only, just ignore it
		 * for the 'remove' command to be compatible to the first release.
		 */
		if (msg->cmd == 'a') {
			if (IN6_IS_ADDR_ANY(&mroute.group.sin6_addr) && IN6_IS_ADDR_ANY(&mroute.group.sin6_addr))
			{
				if (pos >= msg->count) {
					smclog(LOG_DEBUG, "Missing scope specification");
					return 1;
				}

				mroute.scope_mask = (uint16_t)atoi(msg->argv[pos++]);
				smclog(LOG_DEBUG, "Multicast scope mask %4x", mroute.scope_mask);
			}

			if (pos >= msg->count) {
				smclog(LOG_DEBUG, "Missing outbound interface");
				return 1;
			}

			int total = 0;
			while (pos < msg->count) {
				char *ifname_out = msg->argv[pos++];

				iface_match_init(&state_out);
				while ((mif = iface_match_mif_by_name(ifname_out, &state_out, NULL)) >= 0) {
					if (mif == mroute.inbound) {
						/* In case of wildcard match in==out is normal, so don't complain */
						if (!ifname_is_wildcard(ifname_in) && !ifname_is_wildcard(ifname_out) && !errmsg++)
							smclog(LOG_INFO, "Same outbound interface (%s) as inbound (%s) may cause routing loops.", ifname_out, ifname_in);
					}
					mroute.ttl[mif] = 1;	/* Use a TTL threshold */
					total++;
				}

				if (!state_out.match_count && !errmsg++)
					smclog(LOG_DEBUG, "Invalid output interface");
			}

			if (!total) {
				if (!errmsg++)
					smclog(LOG_DEBUG, "No valid output interfaces");
				result += 1;
			} else {
				result += mroute6_add(&mroute);
			}
		} else {
			result += mroute6_del(&mroute);
		}
	}

	if (!state_in.match_count) {
		smclog(LOG_DEBUG, "Invalid input interface");
		return 1;
	}
	return result;
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
	else
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

static int do_show(struct ipc_msg *msg, int sd, int detail)
{
	if (msg->count == 0)
		return mroute_show(sd, detail);

	if (msg->argv[0][0] == 'g')
		return mcgroup_show(sd, detail);

	return mroute_show(sd, detail);
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
#if HAVE_IPV6_MULTICAST_ROUTING
		mroute6_dyn_expire(0);
#endif
		break;

	case 'H':		/* HUP */
		reloading = 1;
		break;

	case 'k':
		running = 0;
		break;

	case 'S':
		result = do_show(msg, sd, 1);
		break;

	case 's':
		result = do_show(msg, sd, 0);
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
