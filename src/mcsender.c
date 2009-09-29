/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006 Julien BLACHE <jb@jblache.org>
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

const char Usage[] = "mcsender [-t<n>] [-i<ifname>] <ip-address:port>\n";
const char McMsg[] = "this is the test message from mclab/mcsender\n"; 

static void usage(void);

static void SetOif4(int, char *);
static void SetTtl4(int, unsigned);

static void SetOif6(int, char *);
static void SetTtl6(int, unsigned);

int main( int ArgCn, char *ArgVc[] )
{
  unsigned                TtlVal = 0;
  char                  * OifVal = NULL;
  char                  * AddrSt = NULL;
  char                  * PortSt = NULL;
  char                  * Pt;
  void                    (*SetTtl)(int, unsigned) = NULL;
  void                    (*SetOif)(int, char *)   = NULL;
  struct sockaddr_storage TarAdr;

  if( ArgCn < 2 ) {
    usage();
    exit(1);
  }

  while( *++ArgVc ) {
    Pt = *ArgVc;

    /* option */
    if( *Pt == '-' ) {
      switch( *++Pt ) {

      case 't':
	if( sscanf( Pt + 1, " %u", &TtlVal ) != 1 || TtlVal < 1 ) {
	  usage();
	  exit( 1 );
	}
	break;

      case 'i':
	OifVal = Pt + 1;
	break;

      default:
	usage();
	exit( 1 );
      }
    } else {  /* argument */

      memset( &TarAdr, 0, sizeof( TarAdr ) );

      AddrSt = Pt;

      Pt = strrchr( AddrSt, ':' );
      if ( Pt == NULL ) {
	usage();
	exit( 1 );
      }

      *Pt++ = '\0';
      PortSt = Pt;

      getSockAdr( SA( &TarAdr ), AddrSt, PortSt );

      SetTtl = ( TarAdr.ss_family == AF_INET ) ? SetTtl4 : SetTtl6;
      SetOif = ( TarAdr.ss_family == AF_INET ) ? SetOif4 : SetOif6;
    }
  }

  {
    int UdpSock = socket( TarAdr.ss_family, SOCK_DGRAM, IPPROTO_UDP );
    if ( UdpSock < 0 ) 
      smclog( LOG_ERR, errno, "UDP socket open" );

    if (TtlVal) (*SetTtl)(UdpSock, TtlVal);
    if (OifVal) (*SetOif)(UdpSock, OifVal);

    while( 1 ) {
      if( sendto( UdpSock, McMsg, sizeof( McMsg ), 0, 
		  SA( &TarAdr ), sizeof( TarAdr ) ) != sizeof( McMsg ) )
	smclog( LOG_WARNING, errno, "send to UDP socket" );

      sleep( 1 );
    }
  }

  exit( 0 );
}

static void usage( void )
{
  fprintf( stderr, "Usage: %s\n", Usage );
}

static void SetTtl4( int Sock, unsigned Ttl )
{
  if( setsockopt( Sock, IPPROTO_IP, IP_MULTICAST_TTL, 
		  &Ttl, sizeof( Ttl ) ) )
    smclog( LOG_ERR, errno, "set IP_MULTICAST_TTL" );
}

static void SetOif4( int Sock, char * IfName )
{
  struct ifreq         IfReq;
  struct sockaddr_in * Sin4  = NULL;

  memset( &IfReq, 0, sizeof( IfReq ) );
  strncpy( IfReq.ifr_name, IfName, sizeof( IfReq.ifr_name ) );

  if ( ioctl( Sock, SIOCGIFADDR, &IfReq ) < 0 )
    smclog( LOG_ERR, errno, "ioctl SIOCGIFADDR" );

  switch ( IfReq.ifr_addr.sa_family ) {
  case AF_INET:
    Sin4 = SIN4( &IfReq.ifr_addr );
    break;

  default:
    fprintf( stderr, "SetOif4 - invalid address family: %d\n", IfReq.ifr_addr.sa_family );
    exit(1);
  }
  
  if( setsockopt( Sock, IPPROTO_IP, IP_MULTICAST_IF, 
		  &Sin4->sin_addr, sizeof( struct in_addr ) ) )
    smclog( LOG_ERR, errno, "set IP_MULTICAST_IF" );  
}

static void SetTtl6(int Sock, unsigned Ttl)
{
  if( setsockopt( Sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 
		  &Ttl, sizeof( Ttl ) ) )
    smclog( LOG_ERR, errno, "set IPV6_MULTICAST_HOPS" );
}

static void SetOif6(int Sock, char * IfName)
{
  unsigned IfIndex;

  IfIndex = if_nametoindex( IfName );

  if( setsockopt( Sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, 
		  &IfIndex, sizeof( IfIndex ) ) )
    smclog( LOG_ERR, errno, "set IPV6_MULTICAST_IF" );  
}
