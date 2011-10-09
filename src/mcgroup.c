/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006-2009 Julien BLACHE <jb@jblache.org>
**  Copyright (C) 2009      Todd Hayton <todd.hayton@gmail.com>
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
**  $Id: mcgroup.c 85 2011-08-08 16:47:53Z micha $	
**
**  This module contains the remaining functions that where not placed in 
**  separate modules
**
*/

#include "mclab.h"

static int joinleave4( int, int, const char *, struct in_addr );
static int joinleave6( int, int, const char *, struct in6_addr );

int joinMcGroup4( int UdpSock, const char *IfName, struct in_addr McAdr )
/*
** Joins the MC group with the address 'McAdr' on the interface 'IfName'. 
** The join is bound to the UDP socket 'UdpSock', so if this socket is 
** closed the membership is dropped.
**          
** returns: - 0 if the function succeeds
**          - 1 if parameters are wrong or the join fails
*/
{
  return joinleave4( 'j', UdpSock, IfName, McAdr );
}

int leaveMcGroup4( int UdpSock, const char *IfName, struct in_addr McAdr )
/*
** Leaves the MC group with the address 'McAdr' on the interface 'IfName'. 
**          
** returns: - 0 if the function succeeds
**          - 1 if parameters are wrong or the join fails
*/
{
  return joinleave4( 'l', UdpSock, IfName, McAdr );
}

int joinMcGroup6( int UdpSock, const char *IfName, struct in6_addr McAdr )
/*
** Joins the MC group with the address 'McAdr' on the interface 'IfName'. 
** The join is bound to the UDP socket 'UdpSock', so if this socket is 
** closed the membership is dropped.
**          
** returns: - 0 if the function succeeds
**          - 1 if parameters are wrong or the join fails
*/
{
  return joinleave6( 'j', UdpSock, IfName, McAdr );
}

int leaveMcGroup6( int UdpSock, const char *IfName, struct in6_addr McAdr )
/*
** Leaves the MC group with the address 'McAdr' on the interface 'IfName'. 
**          
** returns: - 0 if the function succeeds
**          - 1 if parameters are wrong or the join fails
*/
{
  return joinleave6( 'l', UdpSock, IfName, McAdr );
}

static int joinleave4( int Cmd, int UdpSock, const char *IfName, struct in_addr McAdr )
/*
**          
*/
{
  struct ip_mreq CtlReq;
  struct IfDesc *IfDp = getIfByName( IfName );
  const char *CmdSt = Cmd == 'j' ? "join" : "leave";
  

  if( ! IfDp ) { 
    smclog( LOG_WARNING, 0, "%sMcGroup, unknown interface %s", CmdSt, IfName );
    return 1;
  }

  CtlReq.imr_multiaddr.s_addr = McAdr.s_addr;
  CtlReq.imr_interface.s_addr = IfDp->InAdr.s_addr;

  {
    char FmtBu[ INET_ADDRSTRLEN ];
    smclog( LOG_NOTICE, 0, "%sMcGroup: %s on %s", CmdSt, 
	    inet_ntop( AF_INET, &McAdr, FmtBu, sizeof( FmtBu ) ), IfDp ? IfDp->Name : "<any>" );
  }

  if( setsockopt( UdpSock, IPPROTO_IP, 
		  Cmd == 'j' ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, 
		  (void *)&CtlReq, sizeof( CtlReq ) ) ) 
  {
    smclog( LOG_WARNING, errno, "%s MEMBERSHIP failed", Cmd == 'j' ? "ADD" : "DROP" );
    return 1;
  }

  return 0;
}

static int joinleave6( int Cmd, int UdpSock, const char *IfName, struct in6_addr McAdr )
/*
**          
*/
{
#ifndef HAVE_IPV6_MULTICAST_HOST
  return 0;
#else
  struct ipv6_mreq CtlReq;
  struct IfDesc *IfDp = getIfByName( IfName );
  const char *CmdSt = Cmd == 'j' ? "join" : "leave";
  

  if( ! IfDp ) { 
    smclog( LOG_WARNING, 0, "%sMcGroup, unknown interface %s", CmdSt, IfName );
    return 1;
  }

  CtlReq.ipv6mr_multiaddr = McAdr;
  CtlReq.ipv6mr_interface = IfDp->IfIndex;

  {
    char FmtBu[ INET6_ADDRSTRLEN ];
    smclog( LOG_NOTICE, 0, "%sMcGroup: %s on %s", CmdSt, 
	    inet_ntop( AF_INET6, &McAdr, FmtBu, sizeof( FmtBu ) ), IfDp ? IfDp->Name : "<any>" );
  }

  if( setsockopt( UdpSock, IPPROTO_IPV6, 
		  Cmd == 'j' ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, 
		  (void *)&CtlReq, sizeof( CtlReq ) ) ) 
  {
    smclog( LOG_WARNING, errno, "%s MEMBERSHIP failed", Cmd == 'j' ? "ADD" : "DROP" );
    return 1;
  }

  return 0;
#endif /* HAVE_IPV6_MULTICAST_HOST */
}

