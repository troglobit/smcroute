
#include "mclab.h"

int main()
{
  int UdpSock = openUdpSocket( 0x010a0a0a, 7 );
  
  //  buildIfVc(); // brauch ich diesen Call ????
  joinMcGroup( UdpSock, "eth0", 0xe1e1e1e1 );

  printf( "\nEnter for end\n" );
  getchar();

  close( UdpSock );
 
  return 0;
}
