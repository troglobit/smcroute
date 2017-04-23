/* Replacement in case utimensat(2) is missing */

#include <sys/time.h>		/* lutimes(), utimes(), utimensat() */
#include "config.h"

#ifndef HAVE_UTIMENSAT
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
#endif /* HAVE_UTIMENSAT */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
