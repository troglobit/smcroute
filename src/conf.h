#ifndef SMCROUTE_CONF_H_
#define SMCROUTE_CONF_H_

#include "config.h"

extern int conf_vrfy;

int conf_mgroup (int cmd, char *ifname, char *source, char *group);
int conf_mroute (int cmd, char *ifname, char *source, char *group, char *outbound[], int num);
int conf_read   (char *file, int do_vifs);

#endif /* SMCROUTE_CONF_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
