/* Common include file
 *
 * Copyright (C) 2001-2005  Carsten Schill <carsten@cschill.de>
 * Copyright (C) 2006-2009  Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2009       Todd Hayton <todd.hayton@gmail.com>
 * Copyright (C) 2009-2011  Micha Lenk <micha@debian.org>
 * Copyright (C) 2011-2017  Joachim Nilsson <troglobit@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef SMCROUTE_MCLAB_H_
#define SMCROUTE_MCLAB_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "queue.h"
#include "config.h"
#include "common.h"

#ifdef HAVE_LINUX_MROUTE_H
#define _LINUX_IN_H             /* For Linux <= 2.6.25 */
#include <linux/types.h>
#include <linux/mroute.h>
#endif

#ifdef HAVE_LINUX_MROUTE6_H
#include <linux/mroute6.h>
#endif

#ifdef HAVE_LINUX_FILTER_H
#include <linux/filter.h>
#endif

#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif

#ifdef HAVE_NETINET_IP_MROUTE_H
#include <netinet/ip_mroute.h>
#else
# ifdef __APPLE__
#  include "ip_mroute.h"
# endif
#endif

#ifdef HAVE_NETINET6_IP6_MROUTE_H
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <netinet6/ip6_mroute.h>
#endif

typedef u_int8_t uint8;
typedef u_int16_t uint16;
typedef u_int32_t uint32;

#define SA(x)   ((struct sockaddr *)x)
#define SIN4(x) ((struct sockaddr_in *)x)
#define SIN6(x) ((struct sockaddr_in6 *)x)

#ifndef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a) (((__const uint8_t *) (a))[0] == 0xff)
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#endif

/* From The Practice of Programming, by Kernighan and Pike */
#ifndef NELEMS
#define NELEMS(array) (sizeof(array) / sizeof(array[0]))
#endif

struct iface {
	char name[IFNAMSIZ + 1];
	struct in_addr inaddr;	/* == 0 for non IP interfaces */
	u_short ifindex;	/* Physical interface index   */
	short flags;
	short vif;
	short mif;
	uint8_t threshold;	/* TTL threshold: 1-255, default: 1 */
};

extern int do_vifs;

/* ifvc.c */
void          iface_init            (void);
void          iface_exit            (void);
struct iface *iface_find_by_name    (const char *ifname);
struct iface *iface_find_by_index   (unsigned int ifindex);
struct iface *iface_find_by_vif     (int vif);
int           iface_get_vif         (struct iface *iface);
int           iface_get_mif         (struct iface *iface);
int           iface_get_vif_by_name (const char *ifname);
int           iface_get_mif_by_name (const char *ifname);

/* mroute-api.c */

/*
 * IPv4 multicast route
 */
#ifndef MAXVIFS
#define MAXVIFS 32
#endif

#define MAX_MC_VIFS MAXVIFS		/* from linux/mroute.h */

struct mroute4 {
	LIST_ENTRY(mroute4) link;

	struct in_addr sender;
	struct in_addr group;           /* multicast group */
	short          len;		/* prefix len, or 0:disabled */

	short          inbound;         /* incoming VIF    */
	uint8          ttl[MAX_MC_VIFS];/* outgoing VIFs   */
};
typedef struct mroute4 mroute4_t;

/*
 * IPv6 multicast route
 */
#ifdef HAVE_IPV6_MULTICAST_ROUTING
#ifndef MAXMIFS
#define MAXMIFS 32
#endif

#define MAX_MC_MIFS MAXMIFS		/* from linux/mroute6.h */
#else
#define MAX_MC_MIFS 1			/* Dummy value for builds w/o IPv6 routing */
#endif

struct mroute6 {
	struct sockaddr_in6 sender;
	struct sockaddr_in6 group;      /* multicast group */
	short inbound;                  /* incoming VIF    */
	uint8 ttl[MAX_MC_MIFS];         /* outgoing VIFs   */
};
typedef struct mroute6 mroute6_t;

/*
 * Generic multicast route (wrapper for IPv4/IPv6 mroute)
 */
struct mroute {
	int version;		/* 4 or 6 */
	union {
		mroute4_t mroute4;
		mroute6_t mroute6;
	} u;
};
typedef struct mroute mroute_t;

/*
 * Raw IGMP socket used as interface for the IPv4 mrouted API.
 * Receives IGMP packets and upcall messages from the kernel.
 */
extern int mroute4_socket;

/*
 * Raw ICMPv6 socket used as interface for the IPv6 mrouted API.
 * Receives MLD packets and upcall messages from the kenrel.
 */
#define DEFAULT_THRESHOLD 1             /* Packet TTL must be at least 1 to pass */

extern int mroute6_socket;

int  mroute4_enable    (void);
void mroute4_disable   (void);
int  mroute4_dyn_add   (mroute4_t *mroute);
void mroute4_dyn_flush (void);
int  mroute4_add       (mroute4_t *mroute);
int  mroute4_del       (mroute4_t *mroute);

int  mroute6_enable    (void);
void mroute6_disable   (void);
int  mroute6_add       (mroute6_t *mroute);
int  mroute6_del       (mroute6_t *mroute);

int  mroute_add_vif    (char *ifname, uint8_t threshold);
int  mroute_del_vif    (char *ifname);

/* mcgroup.c */
int  mcgroup4_join      (const char *ifname, struct in_addr  source, struct in_addr  group);
int  mcgroup4_leave     (const char *ifname, struct in_addr  source, struct in_addr  group);
void mcgroup4_disable   (void);

int  mcgroup6_join      (const char *ifname, struct in6_addr group);
int  mcgroup6_leave     (const char *ifname, struct in6_addr group);
void mcgroup6_disable   (void);

/* log.c */
#define LOG_INIT 10

extern int  log_level;
extern char log_message[128];

int loglvl(const char *level);
void smclog(int severity, const char *fmt, ...);

/* parse-conf.c */
int run_script(mroute_t *mroute);
int parse_conf_file(const char *file);

/* pidfile.c */
int pidfile(const char *basename, uid_t uid, gid_t gid);

#endif /* SMCROUTE_MCLAB_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
