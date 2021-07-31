/* IGMP/MLD group subscription API */
#ifndef SMCROUTE_MCGROUP_H_
#define SMCROUTE_MCGROUP_H_

#include "inet.h"
#include "queue.h"

struct mcgroup {
	LIST_ENTRY(mcgroup) link;

	char           ifname[IFNAMSIZ];
	struct iface  *iface;
	inet_addr_t    source;
	inet_addr_t    group;
	uint8_t        len;
	int            sd;
};

void mcgroup_exit   (void);

int  mcgroup_action    (int cmd, const char *ifname, inet_addr_t *source, inet_addr_t *group, int len);

int  mcgroup_show      (int sd, int detail);

#endif /* SMCROUTE_MCGROUP_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
