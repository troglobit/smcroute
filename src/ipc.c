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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "ipc.h"
#include "log.h"
#include "msg.h"
#include "socket.h"
#include "mroute.h"

extern char *ident;
static struct sockaddr_un sun;


/* Receive command from the smcroutectl */
static void ipc_read(int sd)
{
	char buf[MX_CMDPKT_SZ];
	struct ipc_msg *msg;

	memset(buf, 0, sizeof(buf));
	msg = (struct ipc_msg *)ipc_receive(sd, buf, sizeof(buf));
	if (!msg) {
		/* Skip logging client disconnects */
		if (errno != ECONNRESET)
			smclog(LOG_WARNING, "Failed receving IPC message from client: %s", strerror(errno));
		return;
	}

	if (msg_do(sd, msg)) {
		if (EINVAL == errno)
			smclog(LOG_WARNING, "Unkown or malformed IPC message '%c' from client.", msg->cmd);
		errno = 0;
		ipc_send(sd, log_message, strlen(log_message) + 1);
	} else {
		ipc_send(sd, "", 1);
	}

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

	ipc_read(client);
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

	if (strlen(LOCALSTATEDIR) + strlen(ident) + 11 >= sizeof(sun.sun_path)) {
		smclog(LOG_ERR, "Too long socket path, max %zd chars", sizeof(sun.sun_path));
		return -1;
	}

	sd = socket_create(AF_UNIX, SOCK_STREAM, 0, ipc_accept, NULL);
	if (sd < 0) {
		smclog(LOG_WARNING, "Failed creating IPC socket, client disabled: %s", strerror(errno));
		return -1;
	}

#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sun.sun_len = 0;	/* <- correct length is set by the OS */
#endif
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof(sun.sun_path), "%s/run/%s.sock", LOCALSTATEDIR, ident);

	unlink(sun.sun_path);
	smclog(LOG_DEBUG, "Binding IPC socket to %s", sun.sun_path);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(sun.sun_path);
	if (bind(sd, (struct sockaddr *)&sun, len) < 0 || listen(sd, 1)) {
		smclog(LOG_WARNING, "Failed binding IPC socket, client disabled: %s", strerror(errno));
		socket_close(sd);
		return -1;
	}

	return sd;
}

/**
 * ipc_exit - Tear down and cleanup IPC communication.
 */
void ipc_exit(void)
{
	unlink(sun.sun_path);
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

		/* Make sure to always have at least one NUL, for strlen() */
		buf[sz] = 0;

		if (sz == msg->len) {
			char *ptr;
			size_t i, count;

			/* Upper bound: smcroutectl add in1 source group out1 out2 .. out32 */
			count = msg->count;
			if (count > (MAXVIFS + 3)) {
				errno = EINVAL;
				return NULL;
			}

			msg = malloc(sizeof(struct ipc_msg) + msg->count * sizeof(char *));
			if (!msg)
				return NULL;

			memcpy(msg, buf, sizeof(struct ipc_msg));

			ptr = buf + offsetof(struct ipc_msg, argv);
			for (i = 0; i < count; i++) {
				/* Verify ptr, attacker may set too large msg->count */
				if (ptr >= (buf + len)) {
					free(msg);
					errno = EBADMSG;
					return NULL;
				}

				msg->argv[i] = ptr;
				ptr += strlen(ptr) + 1;
			}
			msg->count = count;

			return msg;
		}
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
