/* Physical and virtual interface API */
#ifndef SMCROUTE_IFVC_H_
#define SMCROUTE_IFVC_H_

#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>

#define DEFAULT_THRESHOLD 1	/* Packet TTL must be at least 1 to pass */

struct iface {
	char name[IFNAMSIZ + 1];
	struct in_addr inaddr;	/* == 0 for non IP interfaces */
	u_short ifindex;	/* Physical interface index   */
	short flags;
	short vif;
	short mif;
	uint8_t mrdisc;		/* Enable multicast router discovery */
	uint8_t threshold;	/* TTL threshold: 1-255, default: 1 */
};

struct ifmatch {
	unsigned int iter;
	unsigned int match_count;
};

void          iface_init              (void);
void          iface_exit              (void);

struct iface *iface_iterator          (int first);

struct iface *iface_find_by_name      (const char *ifname);
struct iface *iface_find_by_vif       (int vif);

void          iface_match_init        (struct ifmatch *state);
struct iface *iface_match_by_name     (const char *ifname, struct ifmatch *state);
int           ifname_is_wildcard      (const char *ifname);

int           iface_get_vif           (struct iface *iface);
int           iface_get_mif           (struct iface *iface);

int           iface_match_vif_by_name (const char *ifname, struct ifmatch *state, struct iface **found);
int           iface_match_mif_by_name (const char *ifname, struct ifmatch *state, struct iface **found);

#endif /* SMCROUTE_IFVC_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
