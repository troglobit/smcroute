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
**  $Id: mcgroup.c,v 1.2 2001/08/26 19:56:08 cschill Exp $	
**
**  This module contains the remaining functions that where not placed in 
**  separate modules
**
*/

#include "mclab.h"


static int joinleave( int Cmd, int UdpSock, const char *IfName, struct in_addr McAdr )
/*
**          
*/
{
  struct ip_mreq CtlReq;
  struct IfDesc *IfDp = getIfByName( IfName );
  const char *CmdSt = Cmd == 'j' ? "join" : "leave";
  

  if( ! IfDp ) { 
    log( LOG_WARNING, 0, "%sMcGroup, unknown interface %s", CmdSt, IfName );
    return 1;
  }

  CtlReq.imr_multiaddr.s_addr = McAdr.s_addr;
  CtlReq.imr_interface.s_addr = IfDp->InAdr.s_addr;

  {
    char FmtBu[ 32 ];
    log( LOG_NOTICE, 0, "%sMcGroup: %s on %s", CmdSt, 
	 fmtInAdr( FmtBu, McAdr ), IfDp ? IfDp->Name : "<any>" );
  }

  if( setsockopt( UdpSock, IPPROTO_IP, 
		  Cmd == 'j' ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, 
		  (void *)&CtlReq, sizeof( CtlReq ) ) ) 
  {
    log( LOG_WARNING, errno, "MRT_%s_MEMBERSHIP failed", Cmd == 'j' ? "ADD" : "DROP" );
    return 1;
  }

  return 0;
}

int joinMcGroup( int UdpSock, const char *IfName, struct in_addr McAdr )
/*
** Joins the MC group with the address 'McAdr' on the interface 'IfName'. 
** The join is bound to the UDP socket 'UdpSock', so if this socket is 
** closed the membership is dropped.
**          
** returns: - 0 if the function succeeds
**          - 1 if parameters are wrong or the join fails
*/
{
  return joinleave( 'j', UdpSock, IfName, McAdr );
}

int leaveMcGroup( int UdpSock, const char *IfName, struct in_addr McAdr )
/*
** Leaves the MC group with the address 'McAdr' on the interface 'IfName'. 
**          
** returns: - 0 if the function succeeds
**          - 1 if parameters are wrong or the join fails
*/
{
  return joinleave( 'l', UdpSock, IfName, McAdr );
}
