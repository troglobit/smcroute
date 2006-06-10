/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001 Carsten Schill <carsten@cschill.de>
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
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**
**  $Id: mroute-api.c,v 1.5 2002/02/17 13:41:28 cschill Exp $	
**
**  This module contains the interface routines to the Linux mrouted API
**
*/

#define USE_LINUX_IN_H
#include "mclab.h"

// MAX_MC_VIFS from mclab.h must have same value as MAXVIFS from mroute.h
#if MAX_MC_VIFS != MAXVIFS
# error "constants don't match, correct mclab.h"
#endif

// need an IGMP socket as interface for the mrouted API
// - receives the IGMP messages
int MRouterFD;

// my internal virtual interfaces descriptor vector  
static struct VifDesc {
  struct IfDesc *IfDp;
} VifDescVc[ MAXVIFS ];

int enableMRouter()
/*
** Initialises the mrouted API and locks it by this exclusively.
**     
** returns: - 0 if the functions succeeds     
**          - the errno value for non-fatal failure condition
*/
{
  int Va = 1;

  if( (MRouterFD = socket( AF_INET, SOCK_RAW, IPPROTO_IGMP )) < 0 )
    log( LOG_ERR, errno, "IGMP socket open" );
  
  if( setsockopt( MRouterFD, IPPROTO_IP, MRT_INIT, 
		  (void *)&Va, sizeof( Va ) ) ) 
    return errno;

  return 0;
}

void disableMRouter()
/*
** Diables the mrouted API and relases by this the lock.
**          
*/
{
  if( setsockopt( MRouterFD, IPPROTO_IP, MRT_DONE, NULL, 0 ) 
      || close( MRouterFD )
  ) {
    MRouterFD = 0;
    log( LOG_ERR, errno, "MRT_DONE/close" );
  }
  
  MRouterFD = 0;
}

void addVIF( struct IfDesc *IfDp )
/*
** Adds the interface '*IfDp' as virtual interface to the mrouted API
** 
*/
{
  struct vifctl VifCtl;
  struct VifDesc *VifDp;

  /* search free VifDesc
   */
  for( VifDp = VifDescVc; VifDp < VCEP( VifDescVc ); VifDp++ ) {
    if( ! VifDp->IfDp )
      break;
  }
    
  /* no more space
   */
  if( VifDp >= VCEP( VifDescVc ) )
    log( LOG_ERR, ENOMEM, "addVIF, out of VIF space" );

  VifDp->IfDp = IfDp;

  VifCtl.vifc_vifi  = VifDp - VifDescVc; 
  VifCtl.vifc_flags = 0;        /* no tunnel, no source routing, register ? */
  VifCtl.vifc_threshold = 1;    /* Packet TTL must be at least 1 to pass them */
  VifCtl.vifc_rate_limit = 0;   /* hopefully no limit */
  VifCtl.vifc_lcl_addr.s_addr = VifDp->IfDp->InAdr.s_addr;
  VifCtl.vifc_rmt_addr.s_addr = INADDR_ANY;

  log( LOG_NOTICE, 0, "adding VIF, Ix %d Fl 0x%x IP 0x%08x %s", 
       VifCtl.vifc_vifi, VifCtl.vifc_flags,  VifCtl.vifc_lcl_addr.s_addr, VifDp->IfDp->Name );

  if( setsockopt( MRouterFD, IPPROTO_IP, MRT_ADD_VIF, 
		  (char *)&VifCtl, sizeof( VifCtl ) ) )
    log( LOG_ERR, errno, "MRT_ADD_VIF" );
}

int addMRoute( struct MRouteDesc *Dp )
/*
** Adds the multicast routed '*Dp' to the kernel routes
**
** returns: - 0 if the function succeeds
**          - the errno value for non-fatal failure condition
*/
{
  struct mfcctl CtlReq;
  
  CtlReq.mfcc_origin    = Dp->OriginAdr;
  CtlReq.mfcc_mcastgrp  = Dp->McAdr;
  CtlReq.mfcc_parent    = Dp->InVif;

  /* copy the TTL vector
   */
  if(    sizeof( CtlReq.mfcc_ttls ) != sizeof( Dp->TtlVc ) 
      || VCMC( CtlReq.mfcc_ttls ) != VCMC( Dp->TtlVc )
  )
    log( LOG_ERR, 0, "data types doesn't match in " __FILE__ ", source adaption needed !" );

  memcpy( CtlReq.mfcc_ttls, Dp->TtlVc, sizeof( CtlReq.mfcc_ttls ) );

  {
    char FmtBuO[ 32 ], FmtBuM[ 32 ];

    log( LOG_NOTICE, 0, "adding MFC: %s -> %s, InpVIf: %d", 
	    fmtInAdr( FmtBuO, CtlReq.mfcc_origin ), 
	    fmtInAdr( FmtBuM, CtlReq.mfcc_mcastgrp ),
	    CtlReq.mfcc_parent == ALL_VIFS ? -1 : CtlReq.mfcc_parent
	    );
  }

  if( setsockopt( MRouterFD, IPPROTO_IP, MRT_ADD_MFC,
		  (void *)&CtlReq, sizeof( CtlReq ) ) ) 
    log( LOG_WARNING, errno, "MRT_ADD_MFC" );
}

int delMRoute( struct MRouteDesc *Dp )
/*
** Removes the multicast routed '*Dp' from the kernel routes
**
** returns: - 0 if the function succeeds
**          - the errno value for non-fatal failure condition
*/
{
  struct mfcctl CtlReq;
  
  CtlReq.mfcc_origin    = Dp->OriginAdr;
  CtlReq.mfcc_mcastgrp  = Dp->McAdr;
  CtlReq.mfcc_parent    = Dp->InVif;

  /* clear the TTL vector
   */
  memset( CtlReq.mfcc_ttls, 0, sizeof( CtlReq.mfcc_ttls ) );

  {
    char FmtBuO[ 32 ], FmtBuM[ 32 ];

    log( LOG_NOTICE, 0, "removing MFC: %s -> %s, InpVIf: %d", 
	    fmtInAdr( FmtBuO, CtlReq.mfcc_origin ), 
	    fmtInAdr( FmtBuM, CtlReq.mfcc_mcastgrp ),
	    CtlReq.mfcc_parent == ALL_VIFS ? -1 : CtlReq.mfcc_parent
	    );
  }

  if( setsockopt( MRouterFD, IPPROTO_IP, MRT_DEL_MFC,
		  (void *)&CtlReq, sizeof( CtlReq ) ) ) 
    log( LOG_WARNING, errno, "MRT_DEL_MFC" );
}

int getVifIx( struct IfDesc *IfDp )
/*
** Returns for the virtual interface index for '*IfDp'
**
** returns: - the vitrual interface index if the interface is registered
**          - -1 if no virtual interface exists for the interface 
**          
*/
{
  struct VifDesc *Dp;

  for( Dp = VifDescVc; Dp < VCEP( VifDescVc ); Dp++ ) 
    if( Dp->IfDp == IfDp )
      return Dp - VifDescVc;

  return -1;
}


