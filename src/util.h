/* Utilitity and replacement functions */
#ifndef SMCROUTE_UTIL_H_
#define SMCROUTE_UTIL_H_

#include "config.h"
#include <string.h>
#include "mroute.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#endif

/* From The Practice of Programming, by Kernighan and Pike */
#ifndef NELEMS
#define NELEMS(array) (sizeof(array) / sizeof(array[0]))
#endif

int pidfile(const char *basename, uid_t uid, gid_t gid);
#ifndef HAVE_UTIMENSAT
int utimensat(int dirfd, const char *pathname, const struct timespec ts[2], int flags);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t len);
#endif

#endif /* SMCROUTE_UTIL_H_ */
