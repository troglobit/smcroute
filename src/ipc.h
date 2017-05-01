/* Daemon IPC API */
#ifndef SMCROUTE_IPC_H_
#define SMCROUTE_IPC_H_

#include "config.h"

#ifdef ENABLE_CLIENT
int   ipc_init    (void);
void  ipc_exit    (void);

int   ipc_send    (int sd, char *buf, size_t len);
void *ipc_receive (int sd, char *buf, size_t len);
#else
#define ipc_init()
#define ipc_exit()
#endif

#endif /* SMCROUTE_IPC_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
