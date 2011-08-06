/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006-2008 Julien BLACHE <jb@jblache.org>
**  Copyright (C) 2009      Julien BLACHE <jb@jblache.org>,
**                          Todd Hayton <todd.hayton@gmail.com>, and
**                          Micha Lenk <micha@debian.org>
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

typedef u_int8_t   uint8;
typedef u_int16_t  uint16;
typedef u_int32_t  uint32;

#define SA( x ) ((struct sockaddr *)x)
#define SIN4( x ) ((struct sockaddr_in *)x)
#define SIN6( x ) ((struct sockaddr_in6 *)x)

#ifndef MIN
#define MIN( a, b ) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX( a, b ) ((a) < (b) ? (b) : (a))
#endif
#define VCMC( Vc )  (sizeof( Vc ) / sizeof( (Vc)[ 0 ] ))
#define VCEP( Vc )  (&(Vc)[ VCMC( Vc ) ])

#define MAX_MC_VIFS    MAXVIFS     /* = to MAXVIFS from linux/mroute.h */
#define MAX_MC_MIFS    MAXMIFS     /* = to MAXMIFS from linux/mroute6.h */

struct IfDesc {
  char Name[ sizeof( ((struct ifreq *)NULL)->ifr_name ) ];
  struct in_addr InAdr;          /* == 0 for non IP interfaces */            
  u_short IfIndex;               /* Physical interface index   */
  short Flags;
};

/* ifvc.c
 */
#define MAX_IF         40     // max. number of interfaces recognized 

void buildIfVc( void );
struct IfDesc *getIfByName( const char *IfName );
struct IfDesc *getIfByIx( unsigned Ix );

/* mroute-api.c
 */

/*
 * IPv4 multicast route
 */
struct MRoute4Desc {
  struct in_addr OriginAdr;    /* sender          */
  struct in_addr McAdr;        /* multicast group */
  short InVif;                 /* incoming VIF    */
  uint8 TtlVc[ MAX_MC_VIFS ];  /* outgoing VIFs   */
};

/*
 * IPv6 multicast route
 */
struct MRoute6Desc {
  struct sockaddr_in6 OriginAdr; /* sender          */
  struct sockaddr_in6 McAdr;     /* multicast group */
  short InMif;                   /* incoming VIF    */
  uint8 TtlVc[ MAX_MC_MIFS ];    /* outgoing VIFs   */
};

/*
 * Generic multicast route (wrapper for IPv4/IPv6 mroute) 
 */
struct MRouteDesc {
  int ipVersion; /* 4 or 6 */
  union {
    struct MRoute4Desc mRoute4Desc;
    struct MRoute6Desc mRoute6Desc;
  } u;
};

/* 
 * Raw IGMP socket used as interface for the IPv4 mrouted API.
 * Receives IGMP packets and upcall messages from the kernel.
 */
extern int MRouterFD4;

/*
 * Raw ICMPv6 socket used as interface for the IPv6 mrouted API.
 * Receives MLD packets and upcall messages from the kenrel.
 */
extern int MRouterFD6;

int enableMRouter4( void );
void disableMRouter4( void );
int addMRoute4( struct MRoute4Desc * Dp );
int delMRoute4( struct MRoute4Desc * Dp );
void addVIF( struct IfDesc *Dp );
int getVifIx( struct IfDesc *IfDp );

int enableMRouter6( void );
void disableMRouter6( void );
int addMRoute6( struct MRoute6Desc * Dp );
int delMRoute6( struct MRoute6Desc * Dp );
void addMIF( struct IfDesc *Dp );
int getMifIx( struct IfDesc *IfDp );

/* ipc.c
 */
int initIpcServer( void );
struct CmdPkt *readIpcServer( uint8 Bu[], int BuSz );
int initIpcClient( void );
int  sendIpc( const void *Bu, int Sz );
int  readIpc( uint8 Bu[], int BuSz );
void cleanIpc( void );

/* cmdpkt.c
 *
 * XXX show sample packet layouts
 */
struct CmdPkt {
  unsigned PktSz; /* total size of packet including CmdPkt header */
  uint16   Cmd;   /* 'a'=Add,'r'=Remove,'j'=Join,'l'=Leave,'k'=Kill */
  uint16   ParCn; /* command argument count */
  /* 'ParCn' * '\0' terminated strings + '\0' */
};

#define MX_CMDPKT_SZ 1024   /* CmdPkt size including appended strings */

void *buildCmdPkt( char Cmd, const char *ArgVc[], int ParCn );
const char *convCmdPkt2MRouteDesc( struct MRouteDesc *MrDp, const struct CmdPkt *PktPt );
const char *convCmdPkt2MRoute4Desc( struct MRoute4Desc *MrDp, const struct CmdPkt *PktPt );
const char *convCmdPkt2MRoute6Desc( struct MRoute6Desc *MrDp, const struct CmdPkt *PktPt );

/* lib.c
 */
char *fmtInAdr( char *St, struct in_addr InAdr );
char *fmtSockAdr( char *St, const struct sockaddr_in *SockAdrPt );
int getInAdr( uint32 *InAdrPt, uint16 *PortPt, char *St );
void getSockAdr( struct sockaddr * SaPt, socklen_t * SaLenPt, char * AddrSt, char * PortSt );

/* mcgroup.c
 */
int joinMcGroup4( int UdpSock, const char *IfName, struct in_addr McAdr );
int leaveMcGroup4( int UdpSock, const char *IfName, struct in_addr McAdr );
int joinMcGroup6( int UdpSock, const char *IfName, struct in6_addr McAdr );
int leaveMcGroup6( int UdpSock, const char *IfName, struct in6_addr McAdr );


/* syslog.c
 */

#define LOG_INIT 10

extern int  Log2Stderr;           /* Log threshold for stderr, LOG_WARNING .... LOG_DEBUG */
extern int  LogLastServerity;     /* last logged serverity   */
extern int  LogLastErrno;         /* last logged errno value */
extern char LogLastMsg[ 128 ];    /* last logged message     */

void smclog( int Serverity, int Errno, const char *FmtSt, ... );

/* udpsock.c
 */
int openUdpSocket( uint32 PeerInAdr, uint16 PeerPort );

static inline int IN6_MULTICAST(const struct in6_addr *addr)
{
  uint32_t * addr32p = (uint32_t *)addr->s6_addr;
  return (*addr32p & htonl(0xFF000000)) == htonl(0xFF000000);
}









