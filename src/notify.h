/* Wrappers for different service monitors */
#ifndef SMCROUTE_NOTIFY_H_
#define SMCROUTE_NOTIFY_H_

#include "config.h"

void    notify_ready(void);
void    notify_reload(void);

#ifdef HAVE_LIBSYSTEMD
void    systemd_notify_ready(char *status);
void    systemd_notify_reload(char *status);
#else
#define systemd_notfiy_ready(status)
#define systemd_notify_reload(status)
#endif

#endif /* SMCROUTE_NOTIFY_H_ */
