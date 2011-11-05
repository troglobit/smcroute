/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006-2009 Julien BLACHE <jb@jblache.org>
**  Copyright (C) 2009      Todd Hayton <todd.hayton@gmail.com>
**  Copyright (C) 2009-2011 Micha Lenk <micha@debian.org>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
**
**  $Id: mclab.h,v 1.7 2002/07/07 19:39:28 cschill Exp $	
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"

#ifdef HAVE_LINUX_MROUTE_H
#include <linux/mroute.h>
#endif

#ifdef HAVE_LINUX_MROUTE6_H
#include <linux/mroute6.h>
#endif

#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif

#ifdef HAVE_NETINET_IP_MROUTE_H
#include <netinet/ip_mroute.h>
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

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#endif

/* http://stackoverflow.com/questions/1598773/is-there-a-standard-function-in-c-that-would-return-the-length-of-an-array/1598827#1598827 
 * Evidently Google uses it in Chromium.  It is actually intended to look like 0[arr], read the link, or search the web.
 */
#define ARRAY_ELEMENTS(arr) ((sizeof(arr)/sizeof(0[arr])) / ((size_t)(!(sizeof(arr) % sizeof(0[arr])))))

#define MAX_MC_VIFS    MAXVIFS	/* = to MAXVIFS from linux/mroute.h */
#define MAX_MC_MIFS    MAXMIFS	/* = to MAXMIFS from linux/mroute6.h */

struct iface {
	char name[IFNAMSIZ];
	struct in_addr inaddr;	/* == 0 for non IP interfaces */
	u_short ifindex;	/* Physical interface index   */
	short flags;
	short vif;
	short mif;
};

extern int do_debug_logging;

/* ifvc.c */
#define MAX_IF         40	// max. number of interfaces recognized

void          iface_init            (void);
struct iface *iface_find_by_name    (const char *ifname);
struct iface *iface_find_by_index   (unsigned int ifindex);
int           iface_get_vif         (struct iface *iface);
int           iface_get_mif         (struct iface *iface);
int           iface_get_vif_by_name (const char *ifname);
int           iface_get_mif_by_name (const char *ifname);

/* mroute-api.c */

/*
 * IPv4 multicast route
 */
struct mroute4 {
	struct in_addr sender;
	struct in_addr group;           /* multicast group */
	short inbound;                  /* incoming VIF    */
	uint8 ttl[MAX_MC_VIFS];         /* outgoing VIFs   */
};

/*
 * IPv6 multicast route
 */
struct mroute6 {
	struct sockaddr_in6 sender;
	struct sockaddr_in6 group;      /* multicast group */
	short inbound;                  /* incoming VIF    */
	uint8 ttl[MAX_MC_MIFS];         /* outgoing VIFs   */
};

/*
 * Generic multicast route (wrapper for IPv4/IPv6 mroute) 
 */
struct mroute {
	int version;		/* 4 or 6 */
	union {
		struct mroute4 mroute4;
		struct mroute6 mroute6;
	} u;
};

/* 
 * Raw IGMP socket used as interface for the IPv4 mrouted API.
 * Receives IGMP packets and upcall messages from the kernel.
 */
extern int mroute4_socket;

/*
 * Raw ICMPv6 socket used as interface for the IPv6 mrouted API.
 * Receives MLD packets and upcall messages from the kenrel.
 */
extern int mroute6_socket;

int  mroute4_enable  (void);
void mroute4_disable (void);
int  mroute4_add     (struct mroute4 *mroute);
int  mroute4_del     (struct mroute4 *mroute);

int  mroute6_enable  (void);
void mroute6_disable (void);
int  mroute6_add     (struct mroute6 *mroute);
int  mroute6_del     (struct mroute6 *mroute);

/* ipc.c */
int         ipc_server_init (void);
struct cmd *ipc_server_read (uint8 buf[], int len);
int         ipc_client_init (void);
int         ipc_send        (const void *buf, int len);
int         ipc_receive     (uint8 buf[], int len);
void        ipc_exit        (void);

/* cmdpkt.c
 *
 * XXX: Add example packet layouts
 */
struct cmd {
	unsigned len;		/* total size of packet including cmd header */
	uint16   cmd;		/* 'a'=Add,'r'=Remove,'j'=Join,'l'=Leave,'k'=Kill */
	uint16   count;		/* command argument count */
	/* 'count' * '\0' terminated strings + '\0' */
};

#define MX_CMDPKT_SZ 1024	/* command size including appended strings */

void       *cmd_build              (char cmd, const char *argv[], int count);
const char *cmd_convert_to_mroute  (struct mroute  *mroute, const struct cmd *packet);
const char *cmd_convert_to_mroute4 (struct mroute4 *mroute, const struct cmd *packet);
const char *cmd_convert_to_mroute6 (struct mroute6 *mroute, const struct cmd *packet);

/* mcgroup.c */
int mcgroup4_join  (const char *ifname, struct in_addr  group);
int mcgroup4_leave (const char *ifname, struct in_addr  group);
int mcgroup6_join  (const char *ifname, struct in6_addr group);
int mcgroup6_leave (const char *ifname, struct in6_addr group);

/* syslog.c */
#define LOG_INIT 10

extern int log_stderr;		/* Log threshold for stderr, LOG_WARNING .... LOG_DEBUG */
extern int log_last_severity;	/* last logged serverity   */
extern int log_last_error;	/* last logged errno value */
extern char log_last_message[128];	/* last logged message     */

void smclog(int severity, int code, const char *fmt, ...);

/* udpsock.c */
int udp_socket_open(uint32 inaddr, uint16 port);

#ifndef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a) (((__const uint8_t *) (a))[0] == 0xff)
#endif

/* parse-conf.c */
#define SMCROUTE_SYSTEM_CONF "/etc/smcroute.conf"

int parse_conf_file(const char *file);

/* pidfile.c */
int pidfile(const char *basename);

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
