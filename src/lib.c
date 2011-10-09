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
**  $Id: lib.c 85 2011-08-08 16:47:53Z micha $	
**
**  This module contains the remaining functions that where not placed in 
**  separate modules
**
*/

#include "mclab.h"

char *fmtInAdr( char *St, struct in_addr InAdr )
/*
** Formats 'InAdr' into a dotted decimal string. 
**
** returns: - pointer to 'St'
**          
*/
{
  sprintf( St, "%u.%u.%u.%u", 
	   ((uint8 *)&InAdr.s_addr)[ 0 ],
	   ((uint8 *)&InAdr.s_addr)[ 1 ],
	   ((uint8 *)&InAdr.s_addr)[ 2 ],
	   ((uint8 *)&InAdr.s_addr)[ 3 ] );

  return St;
}

char *fmtSockAdr( char *St, const struct sockaddr_in *SockAdrPt )
/*
** Formats 'SockAdrPt' into a dotted decimal string.
**
** returns: - pointer to 'St'
**          
*/
{
  uint32 Adr;
  uint8  *AdrByPt;
  char *Pt = St;

  if( SockAdrPt->sin_family != AF_INET )
    smclog( LOG_ERR, 0, "fmtSockAdr: not an INET address" );

  Adr = SockAdrPt->sin_addr.s_addr;
  
  for( AdrByPt = (uint8 *)&Adr; AdrByPt < (uint8 *)(&Adr +1); AdrByPt++ ) { 
    Pt += sprintf( Pt, "%u", *AdrByPt );
    *Pt++ = '.';
  }
  *--Pt ='\0';
  
  if( SockAdrPt->sin_port )
    Pt += sprintf( Pt, ":%u", SockAdrPt->sin_port ); 

  return St;
}


int getInAdr( uint32 *InAdrPt, uint16 *PortPt, char *St )
/*
** Converts the dotted decimal internet address plus port
** (xx.xx.xx.xx:pp) in 'St' into their integer 
** representations.
**
** 'PortPt' can be NULL if no port number is included or
** should not be converted.
**
** If 'PortPt' is not NULL, then a port number must exist
** in 'St'
**  
** returns: - 0 -> conversion failed
**          - 1 -> only address part returned (InAdrPt)
**          - 2 -> address and port returned
**          
*/
{
  unsigned AdrVc[ 4 ], Port;

  /* read address + port
   */
  if( PortPt ) {
    if( sscanf( St, "%u.%u.%u.%u:%us", &AdrVc[ 0 ], &AdrVc[ 1 ], 
		&AdrVc[ 2 ], &AdrVc[ 3 ], &Port ) != 5 ) 
      return 0;

    Port = htons( Port );
  }
  else {
    if( sscanf( St, "%u.%u.%u.%u", &AdrVc[ 0 ], &AdrVc[ 1 ], 
		&AdrVc[ 2 ], &AdrVc[ 3 ]  ) != 4 ) 
      return 0;

    Port = 0;
  }

  {
    int Ix;

    for( Ix = 0; Ix < 4; Ix++ ) {
      if( AdrVc[ Ix ] > 255 )
	return 0;

      ((uint8 *)InAdrPt)[ Ix ] = AdrVc[ Ix ];
    }
  }
  
  if( ! PortPt ) 
    return 1;

  if( Port > 0xffffu ) 
    return 0;

  *PortPt = Port;
  return 2;
}

void getSockAdr( struct sockaddr * SaPt, socklen_t * SaLenPt, char * AddrSt, char * PortSt )
/*
** Converts the internet address plus port string in 'St' 
** into their network byte order representations.
**
**  
** returns: - 0 -> conversion failed
**          - 1 -> only address part returned (InAdrPt)
**          - 2 -> address and port returned
**          
*/
{
  struct sockaddr_in  * Sin4;
  struct sockaddr_in6 * Sin6;

  if ( strchr( AddrSt, ':' ) == NULL ) {
    Sin4 = SIN4( SaPt );
    memset( Sin4, 0, sizeof( *Sin4 ) );

    Sin4->sin_family = AF_INET;
    Sin4->sin_port   = htons( atoi( PortSt ) );

    if ( inet_pton( AF_INET, AddrSt, &Sin4->sin_addr ) <= 0 )
      smclog( LOG_ERR, errno, "inet_pton failed for address %s", AddrSt );

    *SaLenPt = sizeof( struct sockaddr_in );

  } else {
    Sin6 = SIN6( SaPt );
    memset( Sin6, 0, sizeof( *Sin6 ) );

    Sin6->sin6_family = AF_INET6;
    Sin6->sin6_port   = htons( atoi( PortSt ) );

    if ( inet_pton( AF_INET6, AddrSt, &Sin6->sin6_addr ) <= 0 )
      smclog( LOG_ERR, errno, "inet_pton failed for address %s", AddrSt );

    *SaLenPt = sizeof( struct sockaddr_in6 );

  }

  return;
}
