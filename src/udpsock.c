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
**  $Id: udpsock.c,v 1.1 2001/07/11 15:55:42 cschill Exp $	
**
**  This module contains UDP socket function(s)
**
*/

#include "mclab.h"

int openUdpSocket( uint32 PeerInAdr, uint16 PeerPort )
/*
** Creates and connects a simple UDP socket to the target 
** 'PeerInAdr':'PeerPort'
**
** returns: - the opened socket
**          
*/
{
  int Sock;
  struct sockaddr_in SockAdr;

  if( (Sock = socket( AF_INET, SOCK_DGRAM, 0 )) < 0 )
    log( LOG_ERR, errno, "UDP socket open" );
  
  SockAdr.sin_family      = AF_INET;
  SockAdr.sin_port        = PeerPort;
  SockAdr.sin_addr.s_addr = PeerInAdr;
  memset( &SockAdr.sin_zero, 0, sizeof( SockAdr.sin_zero ) );

  if( connect( Sock, (struct sockaddr *)&SockAdr, sizeof( SockAdr ) ) )
    log( LOG_ERR, errno, "UDP socket connect" );

  return Sock;
}
