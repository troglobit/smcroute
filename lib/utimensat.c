/* Replacement in case utimensat(2) is missing
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
#include <sys/time.h>		/* lutimes(), utimes(), utimensat() */

int utimensat(int dirfd, const char *pathname, const struct timespec ts[2], int flags)
{
	int ret = -1;
	struct timeval tv[2];

	if (dirfd != 0) {
		errno = ENOTSUP;
		return -1;
	}

	TIMESPEC_TO_TIMEVAL(&tv[0], &ts[0]);
	TIMESPEC_TO_TIMEVAL(&tv[1], &ts[1]);

	if ((flags & AT_SYMLINK_NOFOLLOW) == AT_SYMLINK_NOFOLLOW)
		ret = lutimes(pathname, tv);
	else
		ret = utimes(pathname, tv);

	return ret;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
