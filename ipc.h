/* Daemon and client IPC API */
#ifndef SMCROUTE_IPC_H_
#define SMCROUTE_IPC_H_

#include <stdint.h>

int   ipc_server_init (void);
void *ipc_server_read (uint8_t buf[], int len);
int   ipc_client_init (void);
int   ipc_send        (const void *buf, int len);
int   ipc_receive     (uint8_t buf[], int len);
void  ipc_exit        (void);

#endif /* SMCROUTE_IPC_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
