
#include "mclab.h"

const char Usage[] = "mcsender [-t<n>]<target>\n";
const char McMsg[] = "this is the test message from mclab/mcsender\n"; 

uint32 TarInAdr;
uint16 TarPort;
unsigned Ttl = 1;

int main( int ArgCn, char *ArgVc[] )
{
  char *TargetArg;

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
      log( LOG_ERR, errno, "set IP_MULTICAST_TTL" );
      
    while( 1 ) {
      if( send( UdpSock, McMsg, sizeof( McMsg ), 0 ) != sizeof( McMsg ) )
	log( LOG_WARNING, errno, "send to UDP socket" );

      sleep( 1 );
    }
  }

  return 0;
}
