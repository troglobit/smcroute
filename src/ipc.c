/* Daemon and client IPC API
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

#include "msg.h"
#include "socket.h"

/* server's listen socket */
static int server_sd = -1;

/* connected server or client socket */
static int client_sd = -1;

/**
 * ipc_server_init - Initialise an IPC server socket
 *
 * Returns:
 * The socket descriptor, or -1 on error with @errno set.
 */
int ipc_server_init(void)
{
	struct sockaddr_un sa;
	socklen_t len;

	if (server_sd >= 0)
		close(server_sd);

	server_sd = create_socket(AF_UNIX, SOCK_STREAM, 0);
	if (server_sd < 0)
		return -1;

#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sa.sun_len = 0;	/* <- correct length is set by the OS */
#endif
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, SOCKET_PATH);

	unlink(SOCKET_PATH);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(SOCKET_PATH);
	if (bind(server_sd, (struct sockaddr *)&sa, len) < 0 || listen(server_sd, 1)) {
		int err = errno;

		close(server_sd);
		server_sd = -1;
		errno = err;
	}

	return server_sd;
}

/**
 * ipc_exit - Tear down and cleanup IPC communication.
 */
void ipc_exit(void)
{
	if (server_sd >= 0) {
		close(server_sd);
		unlink(SOCKET_PATH);
	}

	if (client_sd >= 0)
		close(client_sd);
}

/**
 * ipc_server_read - Read IPC message from client
 * @buf: Buffer for message
 * @len: Size of @buf in bytes
 *
 * Reads a message from the IPC socket and stores in @buf, respecting
 * the size @len.  Connects and resets connection as necessary.
 *
 * Returns:
 * Pointer to a successfuly read command packet in @buf, or %NULL on error.
 */
void *ipc_server_read(char *buf, size_t len)
{
	size_t sz;
	socklen_t socklen = 0;

	/* sanity check */
	if (server_sd < 0) {
		errno = EBADF;
		return NULL;
	}

	/* wait for connections */
	if (client_sd < 0) {
		client_sd = accept(server_sd, NULL, &socklen);
		if (client_sd < 0)
			return NULL;
	}

	sz = recv(client_sd, buf, len, 0);
	if (!sz) {
		close(client_sd);
		client_sd = -1;
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
 * ipc_send - Send message to peer
 * @buf: Message to send
 * @len: Message length in bytes of @buf
 *
 * Sends the IPC message in @buf of the size @len to the peer.
 *
 * Returns:
 * Number of bytes successfully sent, or -1 with @errno on failure.
 */
int ipc_send(char *buf, size_t len)
{
	/* sanity check */
	if (client_sd < 0) {
		errno = EBADF;
		return -1;
	}

	if (write(client_sd, buf, len) != (ssize_t)len)
		return -1;

	return len;
}

/**
 * ipc_receive - Receive message from peer
 * @buf: Buffer to receive message in
 * @len: Buffer size in bytes
 *
 * Waits to receive an IPC message in @buf of max @len bytes from the peer.
 *
 * Returns:
 * Number of bytes successfully received, or -1 with @errno on failure.
 */
int ipc_receive(char *buf, size_t len)
{
	/* sanity check */
	if (client_sd < 0) {
		errno = EBADF;
		return -1;
	}

	return read(client_sd, buf, len);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
