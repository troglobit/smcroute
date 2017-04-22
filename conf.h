#ifndef SMCROUTE_CONF_H_
#define SMCROUTE_CONF_H_

#include "config.h"
#include "mclab.h"

#ifdef ENABLE_DOTCONF
int parse_conf_file(const char *file);
void read_conf_file(const char *file);

#else
#define parse_conf_file(file)
#define read_conf_file(file)
#endif

#endif /* SMCROUTE_CONF_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
