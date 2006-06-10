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
**  $Id: ipc.c,v 1.7 2002/02/17 13:41:28 cschill Exp $	
**
**  This module contains the IPC functions for client and server
**
*/

#include "mclab.h"

#define SOCKET_PATH "/var/lib/smcroute"

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
    log( LOG_ERR, errno, "initIpcServer, socket() failed" );

  UnixAddr.sun_family = AF_UNIX;
  strcpy( UnixAddr.sun_path, SOCKET_PATH );
 
  unlink( SOCKET_PATH );

  if( bind( ListenSock, (struct sockaddr *)&UnixAddr, 
	    sizeof( UnixAddr.sun_family ) + strlen( UnixAddr.sun_path )) < 0 
      || listen( ListenSock, 1 ) )
    log( LOG_ERR, errno, "initIpcServer, bind()/listen() failed" );

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
    log( LOG_ERR, errno, "initIpcClient, socket() failed" );

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

  log( LOG_DEBUG, 0, "client connected, fd %d", ConSock );
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
    int AddrLn = 0, RdSz;

    // wait for connections
    if( ConSock < 0 ) {
      log( LOG_DEBUG, 0, "readIpcServer, waiting for connection..." );

      if( (ConSock = accept( ListenSock, NULL, &AddrLn )) < 0 )
	log( LOG_ERR, errno, "readIpcServer, accept() failed" );
    
      log( LOG_DEBUG, 0, "readIpcServer, accepted connection" );
    }
  
    // read
    memset( Bu, 0, BuSz );             // had some problems with buffer garbage
    RdSz = read( ConSock, Bu, BuSz );                       
    log( LOG_DEBUG, 0, "readIpcServer, CmdPkt read (%d)", RdSz );

    // successfull read
    if( RdSz >= sizeof( struct CmdPkt ) && RdSz == ((struct CmdPkt *)Bu)->PktSz )   
      return (struct CmdPkt *)Bu;

    // connection lost ? -> reset connection
    if( ! RdSz ) {       
      log( LOG_DEBUG, 0, "readIpcServer, connection lost" );
      close( ConSock );
      ConSock = -1;
      continue;
    }
    
    // error
    log( LOG_WARNING, errno, "readIpcServer, read() failed" );
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
    log( LOG_ERR, errno, "sendIpc, write failed (%d)", Sz );
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
  log( LOG_DEBUG, 0, "readIpc, read (%d)", RdSz );

  if( RdSz < 1 )
    log( LOG_WARNING, errno, "readIpc, read() failed" );

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
