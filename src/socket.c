/* Socket helper functions
 *
 * Copyright (C) 2017  Joachim Nilsson <troglobit@gmail.com>
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
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "log.h"
#include "queue.h"

struct sock {
	LIST_ENTRY(sock) link;

	int sd;

	void (*cb)(int, void *arg);
	void *arg;
};

static int max_fdnum = -1;
LIST_HEAD(, sock) sl = LIST_HEAD_INITIALIZER();


int nfds(void)
{
	return max_fdnum + 1;
}

/*
 * register socket/fd/pipe created elsewhere, optional callback
 */
int socket_register(int sd, void (*cb)(int, void *), void *arg)
{
	struct sock *entry;

	entry = malloc(sizeof(*entry));
	if (!entry)
		return -1;

	entry->sd  = sd;
	entry->cb  = cb;
	entry->arg = arg;
	LIST_INSERT_HEAD(&sl, entry, link);

#if !defined(HAVE_SOCK_CLOEXEC) && defined(HAVE_FCNTL_H)
	fcntl(sd, F_SETFD, fcntl(sd, F_GETFD) | FD_CLOEXEC);
#endif

	/* Keep track for select() */
	if (sd > max_fdnum)
		max_fdnum = sd;

	return sd;
}

/*
 * create socket, with optional callback for reading inbound data
 */
int socket_create(int domain, int type, int proto, void (*cb)(int, void *), void *arg)
{
	int sd;

#ifdef HAVE_SOCK_CLOEXEC
	type |= SOCK_CLOEXEC;
#endif
	sd = socket(domain, type, proto);
	if (sd < 0)
		return -1;

	if (socket_register(sd, cb, arg) < 0) {
		close(sd);
		return -1;
	}

	return sd;
}

int socket_close(int sd)
{
	struct sock *entry, *tmp;

	LIST_FOREACH_SAFE(entry, &sl, link, tmp) {
		if (entry->sd == sd) {
			LIST_REMOVE(entry, link);
			close(entry->sd);
			free(entry);

			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

int socket_poll(struct timeval *timeout)
{
	int num;
	fd_set fds;
	struct sock *entry;

	FD_ZERO(&fds);
	LIST_FOREACH(entry, &sl, link)
		FD_SET(entry->sd, &fds);

	num = select(nfds(), &fds, NULL, NULL, timeout);
	if (num <= 0) {
		/* Log all errors, except when signalled, ignore failures. */
		if (num < 0 && EINTR != errno)
			smclog(LOG_WARNING, "Failed select(): %s", strerror(errno));

		return num;
	}

	LIST_FOREACH(entry, &sl, link) {
		if (!FD_ISSET(entry->sd, &fds))
			continue;

		if (entry->cb)
			entry->cb(entry->sd, entry->arg);
	}

	return num;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
