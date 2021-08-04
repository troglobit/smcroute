/* IPC command parser and builder for daemon and client
 *
 * Copyright (C) 2011-2020  Joachim Wiberg <troglobit@gmail.com>
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
#include "iface.h"
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
	char group[INET_ADDRSTR_LEN];
	char *ifname = msg->argv[0];
	inet_addr_t src;
	inet_addr_t grp;
	int rc = 0;
	int len;

	memset(&src, 0, sizeof(src));
	memset(&grp, 0, sizeof(grp));

	if (msg->count == 3) {
		rc += inet_str2addr(msg->argv[1], &src);
		strlcpy(group, msg->argv[2], sizeof(group));
	} else {
		inet_anyaddr(AF_INET, &src);
		strlcpy(group, msg->argv[1], sizeof(group));
	}

	len = is_range(group);
	if (len < 0 || len > 32) {
		smclog(LOG_DEBUG, "Invalid IPv4 group prefix length (0-32): %d", len);
		return 1;
	}
	if (!len)
		len = 32;

	rc += inet_str2addr(group, &grp);
	if (rc != 0 || !is_multicast(&grp)) {
		smclog(LOG_DEBUG, "Invalid IPv4 source or group address.");
		return 1;
	}

	return mcgroup_action(msg->cmd, ifname, &src, &grp, len);
}

static int do_mgroup6(struct ipc_msg *msg)
{
#ifndef HAVE_IPV6_MULTICAST_HOST
	(void)msg;
	smclog(LOG_WARNING, "IPv6 multicast support disabled.");
	return 1;
#else
	char group[INET_ADDRSTR_LEN];
	char *ifname = msg->argv[0];
	inet_addr_t src;
	inet_addr_t grp;
	int rc = 0;
	int len;

	memset(&src, 0, sizeof(src));
	memset(&grp, 0, sizeof(grp));

	if (msg->count == 3) {
		rc += inet_str2addr(msg->argv[1], &src);
		strlcpy(group, msg->argv[2], sizeof(group));
	} else {
		inet_anyaddr(AF_INET6, &src);
		strlcpy(group, msg->argv[1], sizeof(group));
	}

	len = is_range(group);
	if (len < 0 || len > 128) {
		smclog(LOG_DEBUG, "Invalid IPv6 group prefix length (0-128): %d", len);
		return 1;
	}
	if (!len)
		len = 128;

	rc += inet_str2addr(group, &grp);
	if (rc != 0 || !is_multicast(&grp)) {
		smclog(LOG_DEBUG, "Invalid IPv6 source or group address.");
		return 1;
	}

	return mcgroup_action(msg->cmd, ifname, &src, &grp, len);
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
		char src[INET_ADDRSTR_LEN], grp[INET_ADDRSTR_LEN];
		struct mroute mroute = { 0 };
		struct ifmatch state_out;
		char *ifname_in;
		int len, src_len, pos = 0, vif;

		ifname_in = msg->argv[pos++];
		vif = iface_match_vif_by_name(ifname_in, &state_in, NULL);
		if (vif == NO_VIF)
			break;

		src_len = is_range(msg->argv[pos]);
		if (src_len && (src_len < 0 || src_len > 32)) {
			smclog(LOG_DEBUG, "Invalid prefix length (/LEN), must be 0-32");
			return 1;
		}

		if (inet_str2addr(msg->argv[pos++], &mroute.source)) {
			smclog(LOG_DEBUG, "Invalid IPv4 source address");
			return 1;
		}

		if (!is_multicast(&mroute.source)) {
			len = is_range(msg->argv[pos]);
			if (inet_str2addr(msg->argv[pos++], &mroute.group) || !is_multicast(&mroute.group)) {
				smclog(LOG_DEBUG, "Invalid IPv4 group address");
				return 1;
			}

			if (len && (len < 0 || len > 32)) {
				smclog(LOG_DEBUG, "Invalid prefix length (/LEN), must be 0-32");
				return 1;
			}
		} else {
			/* missing source arg, was actually the group, swaparoo */
			mroute.group = mroute.source;
			inet_anyaddr(AF_INET, &mroute.source);
			len = src_len;
			src_len = 0;
		}

		mroute.inbound = vif;
		mroute.src_len = src_len;
		mroute.len     = len;

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
				while ((vif = iface_match_vif_by_name(ifname_out, &state_out, NULL)) != NO_VIF) {
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
				smclog(LOG_DEBUG, "Adding IPv4 multicast route (%s/%u,%s/%u)",
				       inet_addr2str(&mroute.source, src, sizeof(src)), mroute.src_len,
				       inet_addr2str(&mroute.group, grp, sizeof(grp)), mroute.len);
				result += mroute4_add(&mroute);
			}
		} else {
			smclog(LOG_DEBUG, "Deleting IPv4 multicast route (%s/%u,%s/%u)",
			       inet_addr2str(&mroute.source, src, sizeof(src)), mroute.src_len,
			       inet_addr2str(&mroute.group, grp, sizeof(grp)), mroute.len);
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
		char src[INET_ADDRSTR_LEN], grp[INET_ADDRSTR_LEN];
		struct mroute mroute = { 0 };
		struct ifmatch state_out;
		char *ifname_in;
		int pos = 0, mif;

		ifname_in = msg->argv[pos++];
		mif = iface_match_mif_by_name(ifname_in, &state_in, NULL);
		if (mif == NO_VIF)
			break;

		if (inet_str2addr(msg->argv[pos++], &mroute.source)) {
			smclog(LOG_DEBUG, "Invalid IPv6 source address");
			return 1;
		}

		if (!is_multicast(&mroute.source)) {
			if (inet_str2addr(msg->argv[pos++], &mroute.group) || !is_multicast(&mroute.group)) {
				smclog(LOG_DEBUG, "Invalid IPv6 group address");
				return 1;
			}
			mroute.src_len = 128;
		} else {
			/* missing source arg, was actually the group, swaparoo */
			mroute.group = mroute.source;
			inet_anyaddr(AF_INET6, &mroute.source);
			mroute.src_len = 0;
		}

		mroute.inbound = mif;
		mroute.len = 128;

		/*
		 * Scan output interfaces for the 'add' command only, just ignore it
		 * for the 'remove' command to be compatible to the first release.
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
				while ((mif = iface_match_mif_by_name(ifname_out, &state_out, NULL)) != NO_VIF) {
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
				smclog(LOG_DEBUG, "Adding IPv6 multicast route (%s/%u,%s/%u)",
				       inet_addr2str(&mroute.source, src, sizeof(src)), mroute.src_len,
				       inet_addr2str(&mroute.group, grp, sizeof(grp)), mroute.len);
				result += mroute6_add(&mroute);
			}
		} else {
			smclog(LOG_DEBUG, "Deleting IPv6 multicast route (%s/%u,%s/%u)",
			       inet_addr2str(&mroute.source, src, sizeof(src)), mroute.src_len,
			       inet_addr2str(&mroute.group, grp, sizeof(grp)), mroute.len);
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
	if (msg->count > 0) {
		char cmd = msg->argv[0][0];

		switch (cmd) {
		case 'g':
			return mcgroup_show(sd, detail);

		case 'i':
			return iface_show(sd, detail);

		default:
			break;
		}
	}

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
