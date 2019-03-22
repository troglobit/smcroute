/* generic service monitor backend */

#include <errno.h>
#include <unistd.h>

#include "log.h"
#include "notify.h"
#include "util.h"

void notify_ready(char *pidfn, uid_t uid, gid_t gid)
{
	const char *msg = "Ready, waiting for client request or kernel event.";

	if (pidfile_create(pidfn, uid, gid))
		smclog(LOG_WARNING, "Failed create/chown PID file: %s", strerror(errno));

	systemd_notify_ready(msg);
	smclog(LOG_NOTICE, msg);
}

void notify_reload(void)
{
	const char *msg = "Reloading configuration, please wait ...";

	systemd_notify_reload(msg);
	smclog(LOG_NOTICE, msg);
}
