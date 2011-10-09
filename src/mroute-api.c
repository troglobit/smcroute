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
**  $Id: mroute-api.c 85 2011-08-08 16:47:53Z micha $	
**
**  This module contains the interface routines to the Linux mrouted API
**
*/
#include <unistd.h>
#include <arpa/inet.h>
#include "config.h"
#include "mclab.h"

#ifdef HAVE_NETINET6_IP6_MROUTE_H
 #include <netinet6/ip6_mroute.h>
#endif

/* MAX_MC_VIFS from mclab.h must have same value as MAXVIFS from mroute.h */
#if MAX_MC_VIFS != MAXVIFS
# error "constants don't match, correct mclab.h"
#endif

#ifdef HAVE_IPV6_MULTICAST_ROUTING
/* MAX_MC_MIFS from mclab.h must have same value as MAXVIFS from mroute6.h */
#if MAX_MC_MIFS != MAXMIFS
# error "constants don't match, correct mclab.h"
#endif
#endif

/*
 * Need a raw IGMP socket as interface for the IPv4 mrouted API
 * Receives IGMP packets and kernel upcall messages.
 */
int MRouterFD4;

#ifdef HAVE_IPV6_MULTICAST_ROUTING
/*
 * Need a raw ICMPv6 socket as interface for the IPv6 mrouted API
 * Receives MLD packets and kernel upcall messages.
 */
int MRouterFD6;
#endif

/* IPv4 internal virtual interfaces (VIF) descriptor vector */
static struct VifDesc {
  struct IfDesc *IfDp;
} VifDescVc[ MAXVIFS ];

#ifdef HAVE_IPV6_MULTICAST_ROUTING
/* IPv6 internal virtual interfaces (VIF) descriptor vector */
static struct MifDesc {
  struct IfDesc *IfDp;
} MifDescVc[ MAXMIFS ];
#endif

/********************************************************************
 * IPv4 
 *******************************************************************/

int enableMRouter4()
/*
** Initialises the mrouted API and locks it by this exclusively.
**     
** returns: - 0 if the functions succeeds     
**          - the errno value for non-fatal failure condition
*/
{
  int Va = 1;

  if( (MRouterFD4 = socket( AF_INET, SOCK_RAW, IPPROTO_IGMP )) < 0 ) {
    int err = errno;
    smclog( LOG_INIT, errno, "IGMP socket open" );
    return err;
  }
  
  if( setsockopt( MRouterFD4, IPPROTO_IP, MRT_INIT, 
		  (void *)&Va, sizeof( Va ) ) ) {
    int err = errno;
    close( MRouterFD4 );
    MRouterFD4 = -1;
    return err;
  }

  /* Initialize virtual interface table */
  memset(&VifDescVc, 0, sizeof(VifDescVc));

  return 0;
}

void disableMRouter4()
/*
** Diables the mrouted API and relases by this the lock.
**          
*/
{
  if( MRouterFD4 < 0 ) return;
  if( setsockopt( MRouterFD4, IPPROTO_IP, MRT_DONE, NULL, 0 ) )
    smclog( LOG_ERR, errno, "MRT_DONE" );
  
  close( MRouterFD4 );
  MRouterFD4 = -1;
}

void addVIF( struct IfDesc *IfDp )
/*
** Adds the interface '*IfDp' as virtual interface to the mrouted API
** 
*/
{
  struct vifctl VifCtl;
  int VifIndex = -1;
  int i;

  /* search free VifDesc */
  for (i=0; i < MAXVIFS; i++) {
    if ( !VifDescVc[i].IfDp ) {
      VifIndex = i;
      break;
    }
  }
    
  /* no more space */
  if( VifIndex == -1 ) {
    smclog( LOG_ERR, ENOMEM, "addVIF, out of VIF space" );
    return;
  }

  VifDescVc[VifIndex].IfDp = IfDp;

  memset(&VifCtl, 0, sizeof(VifCtl));
  VifCtl.vifc_vifi = VifIndex; 
  VifCtl.vifc_flags = 0;        /* no tunnel, no source routing, register ? */
  VifCtl.vifc_threshold = 1;    /* Packet TTL must be at least 1 to pass them */
  VifCtl.vifc_rate_limit = 0;   /* hopefully no limit */
  VifCtl.vifc_lcl_addr.s_addr = IfDp->InAdr.s_addr;
  VifCtl.vifc_rmt_addr.s_addr = INADDR_ANY;

  smclog( LOG_NOTICE, 0, "adding VIF, Vif-Ix %d Fl 0x%04x IP 0x%08x %s", 
       VifCtl.vifc_vifi, VifCtl.vifc_flags,  VifCtl.vifc_lcl_addr.s_addr, IfDp->Name );

  if( setsockopt( MRouterFD4, IPPROTO_IP, MRT_ADD_VIF, 
		  (void *)&VifCtl, sizeof( VifCtl ) ) )
    smclog( LOG_ERR, errno, "MRT_ADD_VIF %s", IfDp->Name );
  else
    IfDp->VifIndex = VifIndex;
}

int addMRoute4( struct MRoute4Desc *Dp )
/*
** Adds the multicast routed '*Dp' to the kernel routes
**
** returns: - 0 if the function succeeds
**          - the errno value for non-fatal failure condition
*/
{
  struct mfcctl CtlReq;
  int ret = 0;
  
  memset(&CtlReq, 0, sizeof(CtlReq));

  CtlReq.mfcc_origin    = Dp->OriginAdr;
  CtlReq.mfcc_mcastgrp  = Dp->McAdr;
  CtlReq.mfcc_parent    = Dp->InVif;

  /* copy the TTL vector
   */
  if(    sizeof( CtlReq.mfcc_ttls ) != sizeof( Dp->TtlVc ) 
      || VCMC( CtlReq.mfcc_ttls ) != VCMC( Dp->TtlVc ) )
    smclog( LOG_ERR, 0, "data types doesn't match in " __FILE__ ", source adaption needed !" );

  memcpy( CtlReq.mfcc_ttls, Dp->TtlVc, sizeof( CtlReq.mfcc_ttls ) );

  {
    char FmtBuO[ INET_ADDRSTRLEN ], FmtBuM[ INET_ADDRSTRLEN ];

    smclog( LOG_NOTICE, 0, "adding MFC: %s -> %s, InpVIf: %d", 
	    inet_ntop( AF_INET, &CtlReq.mfcc_origin,   FmtBuO, INET_ADDRSTRLEN ), 
	    inet_ntop( AF_INET, &CtlReq.mfcc_mcastgrp, FmtBuM, INET_ADDRSTRLEN ), 
	    CtlReq.mfcc_parent
	    );
  }

  if( setsockopt( MRouterFD4, IPPROTO_IP, MRT_ADD_MFC,
		  (void *)&CtlReq, sizeof( CtlReq ) ) ) {
    ret = errno;
    smclog( LOG_WARNING, errno, "MRT_ADD_MFC" );
  }

  return ret;
}

int delMRoute4( struct MRoute4Desc *Dp )
/*
** Removes the multicast routed '*Dp' from the kernel routes
**
** returns: - 0 if the function succeeds
**          - the errno value for non-fatal failure condition
*/
{
  struct mfcctl CtlReq;
  int ret = 0;
  
  memset(&CtlReq, 0, sizeof(CtlReq));

  CtlReq.mfcc_origin   = Dp->OriginAdr;
  CtlReq.mfcc_mcastgrp = Dp->McAdr;

  {
    char FmtBuO[ INET_ADDRSTRLEN ], FmtBuM[ INET_ADDRSTRLEN ];

    smclog( LOG_NOTICE, 0, "removing MFC: %s -> %s", 
	    inet_ntop( AF_INET, &CtlReq.mfcc_origin,   FmtBuO, INET_ADDRSTRLEN ), 
	    inet_ntop( AF_INET, &CtlReq.mfcc_mcastgrp, FmtBuM, INET_ADDRSTRLEN )
	    );
  }

  if( setsockopt( MRouterFD4, IPPROTO_IP, MRT_DEL_MFC,
		  (void *)&CtlReq, sizeof( CtlReq ) ) ) {
      ret = errno;
      smclog( LOG_WARNING, errno, "MRT_DEL_MFC" );
  }

  return ret;
}

int getVifIx( struct IfDesc *IfDp )
/*
** Returns for the virtual interface index for '*IfDp'
**
** returns: - the virtual interface index if the interface is registered
**          - -1 if no virtual interface exists for the interface 
**          
*/
{
  if (IfDp == NULL) return -1;
  return IfDp->VifIndex;
}


/********************************************************************
 * IPv6 
 *******************************************************************/

int enableMRouter6()
/*
** Initialises the mrouted API and locks it by this exclusively.
**     
** returns: - 0 if the functions succeeds     
**          - the errno value for non-fatal failure condition
*/
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
  return 0;
#else
  int Va = 1;

  if( (MRouterFD6 = socket( AF_INET6, SOCK_RAW, IPPROTO_ICMPV6 )) < 0 ) {
    int err = errno;
    smclog( LOG_INIT, errno, "ICMPv6 socket open" );
    return err;
  }
  
  if( setsockopt( MRouterFD6, IPPROTO_IPV6, MRT6_INIT, 
		  (void *)&Va, sizeof( Va ) ) ) {
    int err = errno;
    close( MRouterFD6 );
    MRouterFD6 = -1;
    return err;
  }

  /* 
   * On Linux pre 2.6.29 kernels net.ipv6.conf.all.mc_forwarding
   * is not set on MRT6_INIT so we have to do this manually
   */
  {
    int    fd;
    char * file = "/proc/sys/net/ipv6/conf/all/mc_forwarding";
    
    fd = open( file, O_WRONLY );
    if ( fd < 0 ) {
      if ( errno != EACCES )
        smclog( LOG_ERR, errno, "open(%s)", file);  
    } else {
       if (-1 == write( fd, "1", 1 ))
          smclog( LOG_ERR, errno, "Failed enabling IPv6 mv_forwarding" );
      (void) close( fd );
    }
  }
  return 0;
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
}

void disableMRouter6()
/*
** Diables the mrouted API and relases by this the lock.
**          
*/
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
  return;
#else
  if( MRouterFD6 < 0 ) return;
  if( setsockopt( MRouterFD6, IPPROTO_IPV6, MRT6_DONE, NULL, 0 ) )
    smclog( LOG_ERR, errno, "MRT6_DONE" );
  
  close( MRouterFD6 );
  MRouterFD6 = -1;
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
}

void addMIF( struct IfDesc *IfDp )
/*
** Adds the interface '*IfDp' as virtual interface to the mrouted API
** 
*/
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
  return;
#else
  struct mif6ctl MifCtl;
  struct MifDesc *MifDp;

  memset(&MifCtl, 0, sizeof(MifCtl));

  /* search free MifDesc
   */
  for( MifDp = MifDescVc; MifDp < VCEP( MifDescVc ); MifDp++ ) {
    if( ! MifDp->IfDp )
      break;
  }
    
  /* no more space
   */
  if( MifDp >= VCEP( MifDescVc ) )
    smclog( LOG_ERR, ENOMEM, "addMIF, out of MIF space" );

  MifDp->IfDp = IfDp;

  MifCtl.mif6c_mifi      = MifDp - MifDescVc; 
  MifCtl.mif6c_flags     = 0;             /* no register */
#ifdef HAVE_MIF6CTL_VIFC_THRESHOLD
  MifCtl.vifc_threshold  = 1;             /* Packet TTL must be at least 1 to pass them */
#endif
  MifCtl.mif6c_pifi      = IfDp->IfIndex; /* physical interface index */
#ifdef HAVE_MIF6CTL_VIFC_RATE_LIMIT
  MifCtl.vifc_rate_limit = 0;             /* hopefully no limit */
#endif

  smclog( LOG_NOTICE, 0, "adding MIF, Mif-Ix %d PHY Ix %d Fl 0x%x %s", 
	  MifCtl.mif6c_mifi, MifCtl.mif6c_pifi, MifCtl.mif6c_flags, MifDp->IfDp->Name );

  if( setsockopt( MRouterFD6, IPPROTO_IPV6, MRT6_ADD_MIF, 
		  (char *)&MifCtl, sizeof( MifCtl ) ) )
    smclog( LOG_ERR, errno, "MRT6_ADD_MIF %s", IfDp->Name );
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
}

int addMRoute6( struct MRoute6Desc *Dp )
/*
** Adds the multicast routed '*Dp' to the kernel routes
**
** returns: - 0 if the function succeeds
**          - the errno value for non-fatal failure condition
*/
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
  return 0;
#else
  struct mf6cctl CtlReq;
  int            ret   = 0;
  int            MifIx = 0;

  memset(&CtlReq, 0, sizeof(CtlReq));

  CtlReq.mf6cc_origin    = Dp->OriginAdr;
  CtlReq.mf6cc_mcastgrp  = Dp->McAdr;
  CtlReq.mf6cc_parent    = Dp->InMif;

  /* copy the outgoing MIFs
   */
  for ( MifIx = 0; MifIx < MAX_MC_MIFS; MifIx++ ) {
    if ( Dp->TtlVc[ MifIx ] > 0 )
      IF_SET( MifIx, &CtlReq.mf6cc_ifset );
  }

  {
    char FmtBuO[ INET6_ADDRSTRLEN ], FmtBuM[ INET6_ADDRSTRLEN ];

    smclog( LOG_NOTICE, 0, "adding MFC: %s -> %s, InpMIf: %d", 
	    inet_ntop( AF_INET6, &CtlReq.mf6cc_origin.sin6_addr,   FmtBuO, INET6_ADDRSTRLEN ), 
	    inet_ntop( AF_INET6, &CtlReq.mf6cc_mcastgrp.sin6_addr, FmtBuM, INET6_ADDRSTRLEN ), 
	    CtlReq.mf6cc_parent
	    );
  }

  if( setsockopt( MRouterFD6, IPPROTO_IPV6, MRT6_ADD_MFC,
		  (void *)&CtlReq, sizeof( CtlReq ) ) ) {
    ret = errno;
    smclog( LOG_WARNING, errno, "MRT6_ADD_MFC" );
  }

  return ret;
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
}

int delMRoute6( struct MRoute6Desc *Dp )
/*
** Removes the multicast routed '*Dp' from the kernel routes
**
** returns: - 0 if the function succeeds
**          - the errno value for non-fatal failure condition
*/
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
  return 0;
#else
  struct mf6cctl CtlReq;
  int ret = 0;
  
  memset(&CtlReq, 0, sizeof(CtlReq));

  CtlReq.mf6cc_origin   = Dp->OriginAdr;
  CtlReq.mf6cc_mcastgrp = Dp->McAdr;

  {
    char FmtBuO[ INET_ADDRSTRLEN ], FmtBuM[ INET_ADDRSTRLEN ];

    smclog( LOG_NOTICE, 0, "removing MFC: %s -> %s", 
	    inet_ntop( AF_INET6, &CtlReq.mf6cc_origin.sin6_addr,   FmtBuO, INET6_ADDRSTRLEN ), 
	    inet_ntop( AF_INET6, &CtlReq.mf6cc_mcastgrp.sin6_addr, FmtBuM, INET6_ADDRSTRLEN )
	    );
  }

  if( setsockopt( MRouterFD6, IPPROTO_IPV6, MRT6_DEL_MFC,
		  (void *)&CtlReq, sizeof( CtlReq ) ) ) {
    ret = errno;
    smclog( LOG_WARNING, errno, "MRT_DEL_MFC" );
  }

  return ret;
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
}

int getMifIx( struct IfDesc *IfDp )
/*
** Returns for the virtual interface index for '*IfDp'
**
** returns: - the virtual interface index if the interface is registered
**          - -1 if no virtual interface exists for the interface 
**          
*/
{
#ifndef HAVE_IPV6_MULTICAST_ROUTING
  return -1;
#else
  struct MifDesc *Dp;

  for( Dp = MifDescVc; Dp < VCEP( MifDescVc ); Dp++ ) 
    if( Dp->IfDp == IfDp )
      return Dp - MifDescVc;

  return -1;
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
}

