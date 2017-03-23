/* IPC command parser and builder for daemon and client
 *
 * Copyright (C) 2001-2005  Carsten Schill <carsten@cschill.de>
 * Copyright (C) 2006-2009  Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2009       Todd Hayton <todd.hayton@gmail.com>
 * Copyright (C) 2009-2011  Micha Lenk <micha@debian.org>
 * Copyright (C) 2011-2013  Joachim Nilsson <troglobit@gmail.com>
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mclab.h"


/**
 * cmd_build - Create IPC command to send to daemon
 * @cmd:   Command, one of 'a', 'r', 'j' or 'l'
 * @argv:  Vector of arguments for @cmd
 * @count: Number of arguments in @argv
 *
 * Builds an command packet with the command @cmd and @count number of
 * arguments from @argv.
 *
 * Returns:
 * Pointer to a dynamically allocated command packet, or %NULL on failure
 * to allocate enought memory.
 */
void *cmd_build(char cmd, const char *argv[], int count)
{
	int i;
	char *ptr;
	size_t arg_len = 0, packet_len;
	struct cmd *packet;

	/* Summarize length of all arguments/commands */
	for (i = 0; i < count; i++)
		arg_len += strlen(argv[i]) + 1;

	/* resulting packet size */
	packet_len = sizeof(struct cmd) + arg_len + 1;
	if (packet_len > MX_CMDPKT_SZ) {
		errno = EMSGSIZE;
		return NULL;
	}

	/* build packet */
	packet = malloc(packet_len);
	if (!packet)
		return NULL;

	packet->len   = packet_len;
	packet->cmd   = cmd;
	packet->count = count;

	/* copy args */
	ptr = (char *)(packet->argv);
	for (i = 0; i < count; i++) {
		arg_len = strlen(argv[i]) + 1;
		memcpy(ptr, argv[i], arg_len);
		ptr += arg_len;
	}
	*ptr = '\0';	/* '\0' behind last string */

	return packet;
}

/**
 * cmd_convert_to_mroute - Convert IPC command from client to desired mulicast route
 * @mroute: Pointer to &struct mroute to convert to
 * @packet: Pointer to &struct cmd IPC command
 *
 * Converts a command @packet to an @mroute for the 'add' and 'remove'
 * commands.  The IP version is determined by searching for ':' in the
 * address strings to indicate IPv6 addresses.
 *
 * Returns:
 * %NULL on success, or an error string with a hint why the operation failed.
 */
const char *cmd_convert_to_mroute(struct mroute *mroute, const struct cmd *packet)
{
	char *arg = (char *)packet->argv;

	memset(mroute, 0, sizeof(*mroute));

	switch (packet->cmd) {
	case 'a':
	case 'r':
		/* -a eth0 1.1.1.1 239.1.1.1 eth1 eth2
		 *
		 *  +----+-----+---+--------------------------------------------+
		 *  | 42 | 'a' | 5 | "eth0\01.1.1.1\0239.1.1.1\0eth1\0eth2\0\0" |
		 *  +----+-----+---+--------------------------------------------+
		 *  ^              ^
		 *  |              |
		 *  |              |
		 *  +-----cmd------+
		 *
		 * -r 1.1.1.1 239.1.1.1
		 *
		 *  +----+-----+---+--------------------------+
		 *  | 27 | 'r' | 2 | "1.1.1.1\0239.1.1.1\0\0" |
		 *  +----+-----+---+--------------------------+
		 *  ^              ^
		 *  |              |
		 *  |              |
		 *  +-----cmd------+
		 */
		if (packet->cmd == 'a' || packet->count > 2)
			arg += strlen(arg) + 1;

		if (strchr(arg, ':')) {
			mroute->version = 6;
			return cmd_convert_to_mroute6(&mroute->u.mroute6, packet);
		}

		mroute->version = 4;
		return cmd_convert_to_mroute4(&mroute->u.mroute4, packet);

	default:
		return "Invalid command";
	}

	return NULL;
}

const char *cmd_convert_to_mroute4(struct mroute4 *mroute, const struct cmd *packet)
{
	char *arg = (char *)packet->argv;

	memset(mroute, 0, sizeof(*mroute));

	/* -a eth0 1.1.1.1 239.1.1.1 eth1 eth2
	 *
	 *  +----+-----+---+--------------------------------------------+
	 *  | 42 | 'a' | 5 | "eth0\01.1.1.1\0239.1.1.1\0eth1\0eth2\0\0" |
	 *  +----+-----+---+--------------------------------------------+
	 *  ^              ^
	 *  |              |
	 *  |              |
	 *  +-----cmd------+
	 */

	/* get input interface index */
	if (!*arg || (mroute->inbound = iface_get_vif_by_name(arg)) < 0)
		return "Invalid input interface";

	/* get origin */
	arg += strlen(arg) + 1;
	if (!*arg || (inet_pton(AF_INET, arg, &mroute->sender) <= 0))
		return "Invalid origin IPv4 address";

	/* get multicast group */
	arg += strlen(arg) + 1;
	if (!*arg || (inet_pton(AF_INET, arg, &mroute->group) <= 0) || !IN_MULTICAST(ntohl(mroute->group.s_addr)))
		return "Invalid multicast group";

	/*
	 * Scan output interfaces for the 'add' command only, just ignore it
	 * for the 'remove' command to be compatible to the first release.
	 */
	if (packet->cmd == 'a') {
		for (arg += strlen(arg) + 1; *arg; arg += strlen(arg) + 1) {
			int vif;

			if ((vif = iface_get_vif_by_name(arg)) < 0)
				return "Invalid output interface";

			if (vif == mroute->inbound)
				smclog(LOG_WARNING, 0, "Same outbound interface as inbound %s?", arg);

			mroute->ttl[vif] = 1;	/* Use a TTL threashold */
		}
	}

	return NULL;
}

const char *cmd_convert_to_mroute6(struct mroute6 *mroute, const struct cmd *packet)
{
	const char *arg = (const char *)(packet + 1);

	memset(mroute, 0, sizeof(*mroute));

	/* get input interface index */
	if (!*arg || (mroute->inbound = iface_get_mif_by_name(arg)) < 0)
		return "Invalid input interface";

	/* get origin */
	arg += strlen(arg) + 1;
	if (!*arg || (inet_pton(AF_INET6, arg, &mroute->sender.sin6_addr) <= 0))
		return "Invalid origin IPv6 address";

	/* get multicast group */
	arg += strlen(arg) + 1;

	if (!*arg || (inet_pton(AF_INET6, arg, &mroute->group.sin6_addr) <= 0)
	    || !IN6_IS_ADDR_MULTICAST(&mroute->group.sin6_addr))
		return "Invalid multicast group";

	/*
	 * Scan output interfaces for the 'add' command only, just ignore it
	 * for the 'remove' command to be compatible to the first release.
	 */
	if (packet->cmd == 'a') {
		for (arg += strlen(arg) + 1; *arg; arg += strlen(arg) + 1) {
			int mif;

			if ((mif = iface_get_mif_by_name(arg)) < 0)
				return "Invalid output interface";

			if (mif == mroute->inbound)
				smclog(LOG_WARNING, 0, "Same outbound interface as inbound %s?", arg);

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
