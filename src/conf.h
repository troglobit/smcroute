#ifndef SMCROUTE_CONF_H_
#define SMCROUTE_CONF_H_

#include "config.h"

#define SMCROUTE_SYSTEM_CONF "/etc/smcroute.conf"

extern const char *conf_file;

#ifdef ENABLE_DOTCONF
void    read_conf_file(const char *file, int enable);
#else
#define read_conf_file(file, enable)
#endif

#endif /* SMCROUTE_CONF_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
