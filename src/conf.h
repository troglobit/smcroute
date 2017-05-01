#ifndef SMCROUTE_CONF_H_
#define SMCROUTE_CONF_H_

#include "config.h"

#define SMCROUTE_SYSTEM_CONF "/etc/smcroute.conf"

extern const char *conf_file;

#ifdef ENABLE_DOTCONF
void    conf_read(const char *file, int do_vifs);
#else
#define conf_read(file, do_vifs)
#endif

#endif /* SMCROUTE_CONF_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
