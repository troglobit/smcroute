/* Daemon and client IPC API */
#ifndef SMCROUTE_IPC_H_
#define SMCROUTE_IPC_H_

int   ipc_server_init (void);
int   ipc_client_init (void);
void  ipc_exit        (void);

void *ipc_server_read (char *buf, size_t len);

int   ipc_send        (char *buf, size_t len);
int   ipc_receive     (char *buf, size_t len);

#endif /* SMCROUTE_IPC_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
