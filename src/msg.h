/* SMCRoute IPC API
 *
 * XXX: Add example packet layouts
 */
#ifndef SMCROUTE_MSG_H_
#define SMCROUTE_MSG_H_

#include <stdint.h>
#include "mroute.h"

struct ipc_msg {
	size_t   len;		/* total size of packet including cmd header */
	uint16_t cmd;		/* 'a'=Add,'r'=Remove,'j'=Join,'l'=Leave,'k'=Kill */
	uint16_t count;		/* command argument count */
	char    *argv[0]; 	/* 'count' * '\0' terminated strings + '\0' */
};

#define MX_CMDPKT_SZ 1024	/* command size including appended strings */

char *msg_to_mgroup4(struct ipc_msg *msg, struct in_addr *src, struct in_addr *grp);
char *msg_to_mgroup6(struct ipc_msg *msg, struct in6_addr *src, struct in6_addr *grp);

const char *msg_to_mroute  (struct mroute  *mroute, const struct ipc_msg *msg);
const char *msg_to_mroute4 (struct mroute4 *mroute, const struct ipc_msg *msg);
const char *msg_to_mroute6 (struct mroute6 *mroute, const struct ipc_msg *msg);

#endif /* SMCROUTE_MSG_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
