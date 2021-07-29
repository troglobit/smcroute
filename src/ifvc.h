/* Physical and virtual interface API */
#ifndef SMCROUTE_IFVC_H_
#define SMCROUTE_IFVC_H_

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
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

static inline void inet_addr4_set(inet_addr_t *dst, const struct in_addr *src)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)dst;

	assert(dst && src);
	sin->sin_family = AF_INET;
	sin->sin_addr = *src;
}

static inline struct sockaddr_in *inet_addr4_get(inet_addr_t *addr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;

	assert(addr);
	assert(sin->sin_family == AF_INET);

	return sin;
}

#ifdef  HAVE_IPV6_MULTICAST_HOST
static inline void inet_addr6_set(inet_addr_t *dst, const struct in6_addr *src)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)dst;

	assert(dst && src);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = *src;
}

static inline struct sockaddr_in6 *inet_addr6_get(inet_addr_t *addr)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

	assert(addr);
	assert(sin6->sin6_family == AF_INET6);

	return sin6;
}
#endif

static inline void inet_anyaddr(sa_family_t family, inet_addr_t *ss)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, &in6addr_any, sizeof(in6addr_any));
		return;
	}
#endif

	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
}

static inline int inet_addr_cmp(inet_addr_t *a, inet_addr_t *b)
{
	if (!a || !b) {
		errno = EINVAL;
		return 1;
	}

	if (a->ss_family == AF_INET && b->ss_family == AF_INET) {
		struct sockaddr_in *sa = (struct sockaddr_in *)a;
		struct sockaddr_in *sb = (struct sockaddr_in *)b;

		return sa->sin_addr.s_addr - sb->sin_addr.s_addr;
	}

#ifdef  HAVE_IPV6_MULTICAST_HOST
	if (a->ss_family == AF_INET6 && b->ss_family == AF_INET6) {
		struct sockaddr_in6 *sa = (struct sockaddr_in6 *)a;
		struct sockaddr_in6 *sb = (struct sockaddr_in6 *)b;

		return memcmp(sa, sb, sizeof(*sa));
	}
#endif

	errno = EAFNOSUPPORT;
	return 1;
}

static inline const char *inet_addr2str(inet_addr_t *ss, char *buf, size_t len)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (ss->ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, len);
	}
#endif

	return inet_ntop(AF_INET, &sin->sin_addr, buf, len);
}

static inline int inet_str2addr(const char *str, inet_addr_t *ss)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	int rc;

	if (!str || !ss) {
		errno = EINVAL;
		return -1;
	}

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (strchr(str, ':')) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

		ss->ss_family = AF_INET6;
		rc = inet_pton(AF_INET6, str, &sin6->sin6_addr);
	} else
#endif
	{
		ss->ss_family = AF_INET;
		rc = inet_pton(AF_INET, str, &sin->sin_addr);
	}

	if (rc == 0 || rc == -1)
		return 1;

	return 0;
}

static inline int is_multicast(inet_addr_t *ss)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (ss->ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		return IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr);
	}
#endif

	return IN_MULTICAST(ntohl(sin->sin_addr.s_addr));
}

static inline int is_anyaddr(inet_addr_t *ss)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (ss->ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
		return !memcmp(&sin6->sin6_addr, &in6addr_any, sizeof(in6addr_any));
	}
#endif

	return sin->sin_addr.s_addr == htonl(INADDR_ANY);
}

void          iface_init              (void);
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

static inline int iface_exist(char *ifname)
{
	struct ifmatch ifm;

	iface_match_init(&ifm);
	return iface_match_by_name(ifname, &ifm) != NULL;
}

#endif /* SMCROUTE_IFVC_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
