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
**  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
**
**  $Id$	
**
**  This module contains the IPC functions for client and server
**
*/

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "mclab.h"

#define SOCKET_PATH "/var/run/smcroute"

// server's listen socket
static int ListenSock; 

// connected server or client socket
static int ConSock = -1;

int initIpcServer()
/*
** Inits an IPC listen socket 
**
** returns: - the socket descriptor
**
*/
{
  struct sockaddr_un UnixAddr; 

  if( (ListenSock = socket( AF_UNIX, SOCK_STREAM, 0 )) < 0 )
    {
      smclog( LOG_INIT, errno, "initIpcServer, socket() failed" );
      return -1;
    }

  UnixAddr.sun_family = AF_UNIX;
  strcpy( UnixAddr.sun_path, SOCKET_PATH );
 
  unlink( SOCKET_PATH );

  if( bind( ListenSock, (struct sockaddr *)&UnixAddr, 
	    sizeof( UnixAddr.sun_family ) + strlen( UnixAddr.sun_path )) < 0 
      || listen( ListenSock, 1 ) )
    {
      smclog( LOG_INIT, errno, "initIpcServer, bind()/listen() failed" );
      close(ListenSock);
      return -1;
    }

  return ListenSock;
}

int initIpcClient()
/*
** Connects to the IPC socket of the server
**
** returns: - 0, if function succeeds
**          - errno value, of connection attempt. Typically: 
**            - EACCES - Permission denied
**            - ENOENT - No such file or directory
**            - ECONREFUSED - Connection refused
*/
{
  struct sockaddr_un UnixAddr; 

  if( (ConSock = socket( AF_UNIX, SOCK_STREAM, 0 )) < 0 )
    smclog( LOG_ERR, errno, "initIpcClient, socket() failed" );

  UnixAddr.sun_family = AF_UNIX;
  strcpy( UnixAddr.sun_path, SOCKET_PATH );

  if( connect( ConSock, (struct sockaddr *)&UnixAddr, 
	       sizeof( UnixAddr.sun_family ) + strlen( UnixAddr.sun_path )) 
      < 0 ) 
  {
    int Err = errno;

    close( ConSock ); ConSock = 0;
    return Err;
  }

  smclog( LOG_DEBUG, 0, "client connected, fd %d", ConSock );
  return 0;
}

struct CmdPkt *readIpcServer( uint8 Bu[], int BuSz )
/*
** Reads a message from the IPC socket and stores in 'Bu' with a max. size of 'BuSz'. 
** Connects and resets connection as necessary.
**
** returns: Pointer to a successfuly read command packet in 'Bu' 
**
*/
{
  while( 1 ) {
    int RdSz;
    socklen_t AddrLn = 0;

    // wait for connections
    if( ConSock < 0 ) {
      smclog( LOG_DEBUG, 0, "readIpcServer, waiting for connection..." );

      if( (ConSock = accept( ListenSock, NULL, &AddrLn )) < 0 )
	smclog( LOG_ERR, errno, "readIpcServer, accept() failed" );
    
      smclog( LOG_DEBUG, 0, "readIpcServer, accepted connection" );
    }
  
    // read
    memset( Bu, 0, BuSz );             // had some problems with buffer garbage
    RdSz = read( ConSock, Bu, BuSz );                       
    smclog( LOG_DEBUG, 0, "readIpcServer, CmdPkt read (%d)", RdSz );

    // successfull read
    if( RdSz >= sizeof( struct CmdPkt ) && RdSz == ((struct CmdPkt *)Bu)->PktSz )   
      return (struct CmdPkt *)Bu;

    // connection lost ? -> reset connection
    if( ! RdSz ) {       
      smclog( LOG_DEBUG, 0, "readIpcServer, connection lost" );
      close( ConSock );
      ConSock = -1;
      continue;
    }
    
    // error
    smclog( LOG_WARNING, errno, "readIpcServer, read() failed" );
  }
}

int sendIpc( const void *Bu, int Sz )
/*
** Sends the IPC message in 'Bu' with the size 'Sz' to the peer.
**
** returns: - number of bytes written (Sz)
**          - -1 if write failed
**
*/
{
  if( write( ConSock, Bu, Sz ) != Sz ) {
    smclog( LOG_ERR, errno, "sendIpc, write failed (%d)", Sz );
    return -1;
  }

  return Sz;
}


int readIpc( uint8 Bu[], int BuSz )
/*
** Reads the next IPC message in 'Bu' with the max. size 'BuSz' from the peer.
**
** returns: - number of bytes read (0..BuSz)
**          - -1 if read failed
** 
*/
{
  int RdSz = read( ConSock, Bu, BuSz );                       
  smclog( LOG_DEBUG, 0, "readIpc, read (%d)", RdSz );

  if( RdSz < 1 )
    smclog( LOG_WARNING, errno, "readIpc, read() failed" );

  return RdSz;
}


void cleanIpc()
/*
** Clean up IPC.
**
** 
*/
{
  if( ListenSock ) {
    close( ListenSock );
    unlink( SOCKET_PATH );
  }

  if( ConSock >= 0 )
    close( ConSock );
}
