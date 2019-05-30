/* Physical and virtual interface API */
#ifndef SMCROUTE_IFVC_H_
#define SMCROUTE_IFVC_H_

#include "config.h"

#include <arpa/inet.h>		/* inet_ntop() */
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>

#define DEFAULT_THRESHOLD 1	/* Packet TTL must be at least 1 to pass */
#ifdef  HAVE_IPV6_MULTICAST_HOST
#define INET_ADDRSTR_LEN  INET6_ADDRSTRLEN
#else
#define INET_ADDRSTR_LEN  INET_ADDRSTRLEN
#endif
typedef struct sockaddr_storage inet_addr_t;

struct iface {
	char name[IFNAMSIZ + 1];
	struct in_addr inaddr;	/* == 0 for non IP interfaces */
	int   ifindex;          /* Physical interface index   */
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
void          iface_refresh           (void *arg);
void          iface_exit              (void);

struct iface *iface_iterator          (int first);

struct iface *iface_find              (int ifindex);
struct iface *iface_find_by_name      (const char *ifname);
struct iface *iface_find_by_vif       (int vif);

void          iface_match_init        (struct ifmatch *state);
struct iface *iface_match_by_name     (const char *ifname, struct ifmatch *state);
int           ifname_is_wildcard      (const char *ifname);

int           iface_get_vif           (struct iface *iface);
int           iface_get_mif           (struct iface *iface);

int           iface_match_vif_by_name (const char *ifname, struct ifmatch *state, struct iface **found);
int           iface_match_mif_by_name (const char *ifname, struct ifmatch *state, struct iface **found);

int           iface_show              (int sd, int detail);

static inline int is_anyaddr(inet_addr_t *ss)
{
	struct sockaddr_in *sin;

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (ss->ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		return !memcmp(&sin6->sin6_addr, &in6addr_any, sizeof(in6addr_any));
	}
#endif

	sin = (struct sockaddr_in *)ss;
	return sin->sin_addr.s_addr == INADDR_ANY;
}

static inline const char *convert_address(inet_addr_t *ss, char *buf, size_t len)
{
	struct sockaddr_in *sin;

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (ss->ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, len);
	}
#endif

	sin = (struct sockaddr_in *)ss;
	return inet_ntop(AF_INET, &sin->sin_addr, buf, len);
}

#endif /* SMCROUTE_IFVC_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
