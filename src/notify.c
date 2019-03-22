/* generic service monitor backend */
#include "notify.h"

void notify_ready(void)
{
	systemd_notify_ready("Ready, waiting for client request or kernel event.");
}

void notify_reload(void)
{
	systemd_notify_reload("Reloading configuration, please wait ...");
}
