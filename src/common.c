/* Helper functions
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

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <string.h>
#include <sys/socket.h>

static int max_fdnum = -1;

int nfds(void)
{
	return max_fdnum + 1;
}

char *progname(const char *arg0)
{
	char *nm;

	nm = strrchr(arg0, '/');
	if (nm)
		nm++;
	else
		nm = (char *)arg0;

	return nm;
}

int create_socket(int domain, int type, int proto)
{
	int sd;

#ifdef HAVE_SOCK_CLOEXEC
	type |= SOCK_CLOEXEC;
#endif
	sd = socket(domain, type, proto);
#if !defined(HAVE_SOCK_CLOEXEC) && defined(HAVE_FCNTL_H)
	if (sd >= 0)
		fcntl(sd, F_SETFD, fcntl(sd, F_GETFD) | FD_CLOEXEC);
#endif

	/* Keep track for select() */
	if (sd > max_fdnum)
		max_fdnum = sd;

	return sd;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
