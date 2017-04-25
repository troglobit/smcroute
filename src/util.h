/* Utilitity functions */
#ifndef SMCROUTE_UTIL_H_
#define SMCROUTE_UTIL_H_

#include "mroute.h"

extern char *script_exec;

int run_script(struct mroute *mroute);
int pidfile(const char *basename, uid_t uid, gid_t gid);
int utimensat(int dirfd, const char *pathname, const struct timespec ts[2], int flags);

#endif /* SMCROUTE_UTIL_H_ */
