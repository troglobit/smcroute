/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
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
**  $Id$
**
**  Multicast test tool
**
*/

#include <stdio.h>
#include <unistd.h>

#include "mclab.h"

const char Usage[] = "mcsender [-t<n>]<target>\n";
const char McMsg[] = "this is the test message from mclab/mcsender\n"; 

uint32 TarInAdr;
uint16 TarPort;
unsigned Ttl = 1;

int main( int ArgCn, char *ArgVc[] )
{
  if( ArgCn < 2 ) {
USAGE:
    printf( Usage );
    return 1;
  }

  while( *++ArgVc ) {
    char *Pt = *ArgVc;

    // option
    if( *Pt == '-' ) {
      switch( *++Pt ) {

        case 't':
	  if( sscanf( Pt +1, " %u", &Ttl ) != 1 || Ttl < 1 )
	    goto USAGE;
	  break;

        default:
	  goto USAGE;
      }
    }
    // argument
    else {
      if( getInAdr( &TarInAdr, &TarPort, Pt ) != 2 ) {
	printf( "not a valid UDP target (u.v.w.x:z): %s\n", *ArgVc );
	return 2;
      }
    }
  }

  // need this argument
  if( ! TarInAdr )
    goto USAGE;


  {
    int UdpSock = openUdpSocket( TarInAdr, TarPort );

    if( setsockopt( UdpSock, IPPROTO_IP, IP_MULTICAST_TTL, 
		    &Ttl, sizeof( Ttl ) ) )
      smclog( LOG_ERR, errno, "set IP_MULTICAST_TTL" );
      
    while( 1 ) {
      if( send( UdpSock, McMsg, sizeof( McMsg ), 0 ) != sizeof( McMsg ) )
	smclog( LOG_WARNING, errno, "send to UDP socket" );

      sleep( 1 );
    }
  }

  return 0;
}
