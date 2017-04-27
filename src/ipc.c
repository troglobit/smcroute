/* Daemon IPC API
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

#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "ipc.h"
#include "log.h"
#include "msg.h"
#include "mcgroup.h"
#include "socket.h"

extern int running;
extern void reload(int signo);

/* Receive command from the smcroutectl */
static void read_ipc_command(int sd)
{
	const char *str;
	struct ipc_msg *msg;
	struct mroute mroute;
	char buf[MX_CMDPKT_SZ];

	memset(buf, 0, sizeof(buf));
	msg = (struct ipc_msg *)ipc_receive(sd, buf, sizeof(buf));
	if (!msg) {
		/* Skip logging client disconnects */
		if (errno != ECONNRESET)
			smclog(LOG_WARNING, "Failed receving IPC message from client: %s", strerror(errno));
		return;
	}

	switch (msg->cmd) {
	case 'a':
	case 'r':
		if ((str = msg_to_mroute(&mroute, msg))) {
			smclog(LOG_WARNING, "%s", str);
			ipc_send(sd, log_message, strlen(log_message) + 1);
			goto error;
		}

		if (mroute.version == 4) {
			if ((msg->cmd == 'a' && mroute4_add(&mroute.u.mroute4))
			    || (msg->cmd == 'r' && mroute4_del(&mroute.u.mroute4))) {
				ipc_send(sd, log_message, strlen(log_message) + 1);
				goto error;
			}
		} else {
#ifndef HAVE_IPV6_MULTICAST_ROUTING
			smclog(LOG_WARNING, "IPv6 multicast routing support disabled.");
#else
			if ((msg->cmd == 'a' && mroute6_add(&mroute.u.mroute6))
			    || (msg->cmd == 'r' && mroute6_del(&mroute.u.mroute6))) {
				ipc_send(sd, log_message, strlen(log_message) + 1);
				goto error;
			}
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
		}
		break;

	case 'j':
	case 'l':
	{
		int result = -1;

		str = msg->cmd == 'j' ? "join" : "leave";
		if (strchr(msg->argv[1], ':')) {
#ifndef HAVE_IPV6_MULTICAST_HOST
			smclog(LOG_WARNING, "IPv6 multicast support disabled.");
#else
			char *ifname;
			struct in6_addr source, group;

			ifname = msg_to_mgroup6(msg, &source, &group);
			if (!ifname || !IN6_IS_ADDR_MULTICAST(&group)) {
				smclog(LOG_WARNING, "%s: Invalid IPv6 source our group address.", str);
			} else {
				if (msg->cmd == 'j')
					result = mcgroup6_join(ifname, group);
				else
					result = mcgroup6_leave(ifname, group);
			}
#endif /* HAVE_IPV6_MULTICAST_HOST */
		} else {
			char *ifname;
			struct in_addr source, group;

			ifname = msg_to_mgroup4(msg, &source, &group);
			if (!ifname || !IN_MULTICAST(ntohl(group.s_addr))) {
				smclog(LOG_WARNING, "%s: Invalid IPv4 source our group address.", str);
			} else {
				if (msg->cmd == 'j')
					result = mcgroup4_join(ifname, source, group);
				else
					result = mcgroup4_leave(ifname, source, group);
			}
		}

		if (result) {
			ipc_send(sd, log_message, strlen(log_message) + 1);
			goto error;
		}
		break;
	}

	case 'H':		/* HUP */
		reload(0);
		break;

	case 'F':
		mroute4_dyn_flush();
		break;

	case 'k':
		running = 0;
		break;
	}

	ipc_send(sd, "", 1);
error:
	free(msg);
}

static void ipc_accept(int sd, void *arg)
{
	int client;
	socklen_t socklen = 0;

	(void)arg;
	client = accept(sd, NULL, &socklen);
	if (client < 0)
		return;

	read_ipc_command(client);
	close(client);
}

/**
 * ipc_server_init - Initialise an IPC server socket
 *
 * Returns:
 * The socket descriptor, or -1 on error with @errno set.
 */
int ipc_init(void)
{
	int sd;
	socklen_t len;
	struct sockaddr_un sa;

	sd = socket_create(AF_UNIX, SOCK_STREAM, 0, ipc_accept, NULL);
	if (sd < 0)
		return -1;

#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sa.sun_len = 0;	/* <- correct length is set by the OS */
#endif
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, SOCKET_PATH);

	unlink(SOCKET_PATH);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(SOCKET_PATH);
	if (bind(sd, (struct sockaddr *)&sa, len) < 0 || listen(sd, 1)) {
		int err = errno;

		close(sd);
		errno = err;
	}

	return sd;
}

/**
 * ipc_exit - Tear down and cleanup IPC communication.
 */
void ipc_exit(void)
{
	unlink(SOCKET_PATH);
}

/**
 * ipc_send - Send message to peer
 * @sd:  Client socket from ipc_accept()
 * @buf: Message to send
 * @len: Message length in bytes of @buf
 *
 * Sends the IPC message in @buf of the size @len to the peer.
 *
 * Returns:
 * Number of bytes successfully sent, or -1 with @errno on failure.
 */
int ipc_send(int sd, char *buf, size_t len)
{
	if (write(sd, buf, len) != (ssize_t)len)
		return -1;

	return len;
}

/**
 * ipc_server_read - Read IPC message from client
 * @sd:  Client socket from ipc_accept()
 * @buf: Buffer for message
 * @len: Size of @buf in bytes
 *
 * Reads a message from the IPC socket and stores in @buf, respecting
 * the size @len.  Connects and resets connection as necessary.
 *
 * Returns:
 * Pointer to a successfuly read command packet in @buf, or %NULL on error.
 */
void *ipc_receive(int sd, char *buf, size_t len)
{
	size_t sz;

	sz = recv(sd, buf, len, 0);
	if (!sz) {
		errno = ECONNRESET;
		return NULL;
	}

	/* successful read */
	if (sz >= sizeof(struct ipc_msg)) {
		struct ipc_msg *msg = (struct ipc_msg *)buf;

		if (sz == msg->len)
			return msg;
	}

	errno = EAGAIN;
	return NULL;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
