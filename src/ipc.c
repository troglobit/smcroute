/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006-2009 Julien BLACHE <jb@jblache.org>
**  Copyright (C) 2009      Todd Hayton <todd.hayton@gmail.com>
**  Copyright (C) 2009-2011 Micha Lenk <micha@debian.org>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
**
**  $Id: ipc.c 85 2011-08-08 16:47:53Z micha $	
**
**  This module contains the IPC functions for client and server
**
*/

#include <stddef.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "mclab.h"

#define SOCKET_PATH "/var/run/smcroute"

/* server's listen socket */
static int server_sd;

/* connected server or client socket */
static int client_sd = -1;

/*
** Inits an IPC listen socket 
**
** returns: - the socket descriptor
*/
int ipc_server_init(void)
{
	struct sockaddr_un sa;
	socklen_t len;

	if ((server_sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
           smclog(LOG_INIT, errno, "%s: socket() failed", __FUNCTION__);
		return -1;
	}
#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sa.sun_len = 0;	/* <- correct length is set by the OS */
#endif
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, SOCKET_PATH);

	unlink(SOCKET_PATH);

	len = offsetof(struct sockaddr_un, sun_path)+strlen(SOCKET_PATH);
	if (bind(server_sd, (struct sockaddr *)&sa, len) < 0 || listen(server_sd, 1)) {
           smclog(LOG_INIT, errno, "%s: bind()/listen() failed", __FUNCTION__);
           close(server_sd);
           return -1;
	}

	return server_sd;
}

/*
** Connects to the IPC socket of the server
**
** returns: - 0, if function succeeds
**          - errno value, of connection attempt. Typically: 
**            - EACCES - Permission denied
**            - ENOENT - No such file or directory
**            - ECONREFUSED - Connection refused
*/
int ipc_client_init(void)
{
	int err;
	struct sockaddr_un sa;
	socklen_t len;

	if ((client_sd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		smclog(LOG_ERR, errno, "%s: socket() failed", __FUNCTION__);

#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sa.sun_len = 0;	/* <- correct length is set by the OS */
#endif
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, SOCKET_PATH);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(SOCKET_PATH);
	if (connect(client_sd, (struct sockaddr *)&sa, len) < 0) {
		err = errno;

		close(client_sd);
		client_sd = -1;

		return err;
	}

	smclog(LOG_DEBUG, 0, "%s: client connected, sd %d", __FUNCTION__, client_sd);

	return 0;
}

/*
** Reads a message from the IPC socket and stores in 'buf' with a max. size of 'len'. 
** Connects and resets connection as necessary.
**
** returns: Pointer to a successfuly read command packet in 'buf' 
*/
struct cmd *ipc_server_read(uint8 buf[], int len)
{
	while (1) {
		size_t size;
		socklen_t socklen = 0;

		/* wait for connections */
		if (client_sd < 0) {
			smclog(LOG_DEBUG, 0, "%s: waiting for connection...", __FUNCTION__);

			if ((client_sd = accept(server_sd, NULL, &socklen)) < 0)
				smclog(LOG_ERR, errno, "%s: accept() failed", __FUNCTION__);

			smclog(LOG_DEBUG, 0, "%s: accepted connection", __FUNCTION__);
		}

		/* read */
		memset(buf, 0, len);	/* had some problems with buffer garbage */
		size = read(client_sd, buf, len);
		smclog(LOG_DEBUG, 0, "%s: command read (%zu)", __FUNCTION__, size);

		/* successfull read */
		if (size >= sizeof(struct cmd) && size == ((struct cmd *)buf)->len)
			return (struct cmd *)buf;

		/* connection lost ? -> reset connection */
		if (!size) {
			smclog(LOG_DEBUG, 0, "%s: connection lost", __FUNCTION__);
			close(client_sd);
			client_sd = -1;
			continue;
		}

		/* error */
		smclog(LOG_WARNING, errno, "%s: read() failed", __FUNCTION__);
	}
}

/*
** Sends the IPC message in 'buf' with the size 'Sz' to the peer.
**
** returns: - number of bytes written (Sz)
**          - -1 if write failed
*/
int ipc_send(const void *buf, int len)
{
	if (write(client_sd, buf, len) != len) {
		smclog(LOG_ERR, errno, "%s: write failed (%d)", __FUNCTION__, len);
		return -1;
	}

	return len;
}

/*
** Reads the next IPC message in 'buf' with the max. size 'len' from the peer.
**
** returns: - number of bytes read (0..len)
**          - -1 if read failed
** 
*/
int ipc_receive(uint8 buf[], int len)
{
	int size = read(client_sd, buf, len);

	smclog(LOG_DEBUG, 0, "%s: read (%d)", __FUNCTION__, size);

	if (size < 1)
		smclog(LOG_WARNING, errno, "%s: read() failed", __FUNCTION__);

	return size;
}

/*
** Clean up IPC.
** 
*/
void ipc_exit(void)
{
	if (server_sd) {
		close(server_sd);
		unlink(SOCKET_PATH);
	}

	if (client_sd >= 0)
		close(client_sd);
}

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
