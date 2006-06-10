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
**  $Id: smcroute.c,v 1.9 2002/02/17 13:41:28 cschill Exp $	
**
*/

#include "mclab.h"

#include "version.h"
#include "build.h"

static const char Version[] = 
"smcroute, Version " VERSION ", Build" BUILD "\n"
"Copyright 2001,2002 by Carsten Schill <carsten@cschill.de>\n"
"Distributed under the GNU GENERAL PUBLIC LICENSE, Version 2 - check GPL.txt\n"
"\n";

static const char Usage[] = 
"usage: smcroute\t[-v] [-d]\n"
"\n" 
"\t\t[-a <InputIntf> <OriginIpAdr> <McGroupAdr> <OutputIntf> [<OutputIntf>] ...]\n"
"\t\t[-r <InputIntf> <OriginIpAdr> <McGroupAdr>]\n"
"\n"
"\t\t[-j <InputIntf> <McGroupAdr>]\n"
"\t\t[-l <InputIntf> <McGroupAdr>]\n"
;

static const char MissingArgSt[] = "<missing argument>";

int McGroupSock;

static int getArgOptLn( const char *ArgVc[] )
/*
** Counts the number of arguments belonging to an option. Option is any argument
** begining with a '-'. 
** 
** returns: - the number of arguments (without the option itself), 
**          - 0, if we start already from the end of the argument vector
**          - -1, if we start not from an option
**
*/
{
  const char **Pp;

  // end of vector 
  if( ArgVc == NULL || *ArgVc == NULL )
    return 0; 

  // starting on wrong position
  if( **ArgVc != '-' )
    return -1;

  for( Pp = ArgVc +1; *Pp && **Pp != '-'; Pp++ )
    ;
    
  return Pp - ArgVc;
}


static void clean()
/*
** Cleans up, i.e. releases allocated resources. Called via atexit().
** 
*/        
{
  log( LOG_DEBUG, 0, "clean handler called" );
  disableMRouter();
  cleanIpc();
}


static void initMRouter()
/*
** Inits the necessary resources for MRouter.
**
*/
{
  int Err;

  buildIfVc();    

  switch( Err = enableMRouter() ) {
    case 0: break;
    case EADDRINUSE: log( LOG_ERR, EADDRINUSE, "MC-Router API already in use" ); break;
    default: log( LOG_ERR, Err, "MRT_INIT failed" );
  }
      
  /* create VIFs for all IP, non-loop interfaces
   */
  {
    unsigned Ix;
    struct IfDesc *Dp;

    for( Ix = 0; Dp = getIfByIx( Ix ); Ix++ ) 
      if( Dp->InAdr.s_addr && ! (Dp->Flags & IFF_LOOPBACK) )
	addVIF( Dp );
  }  

  atexit( clean );
}

int main( int ArgCn, const char *ArgVc[] )
/*
** main programm
** - scans options
**   - daemon mode: enters daemon status and goes in receive-execute command loop 
**   - client mode: creates commands from command line and sends them to the daemon
**
*/
{
  struct CmdPkt *CmdVc[ 16 ], **CmdVcPt = CmdVc;
  uint8 Bu[ MX_CMDPKT_SZ ];
  int StartDaemon = 0,
      ProgRt = 0;

  // init syslog
  openlog( ArgVc[ 0 ], LOG_PID, LOG_DAEMON );   
  
  if( ArgCn <= 1 ) {
Usage:    
    fputs( Version, stderr );
    fputs( Usage, stderr );
    return 1;
  }

  // scan options
  {
    int OptLn;

    for( OptLn = 1; (OptLn = getArgOptLn( ArgVc += OptLn )); ) {
  
      if( OptLn < 0 )           // error
	goto Usage;
    
      // handle option 
      switch( *(*ArgVc +1) ) {
        case 'a':                 // add route
	  if( OptLn < 5 ) {
	    fprintf( stderr, "not enough arguments for 'add' command\n" );
	    goto Usage;
	  }

BuildCmd:
	  if( CmdVcPt >= VCEP( CmdVc ) ) {
	    fprintf( stderr, "too much command options\n" );
	    goto Usage;
	  }
	  
	  *CmdVcPt++ = buildCmdPkt( *(*ArgVc +1), ArgVc +1, OptLn -1 );
	  break;

        case 'r':                 // remove route
	  if( OptLn < 4 ) {
	    fprintf( stderr, "wrong number of  arguments for 'remove' command\n" );
	    goto Usage;
	  }

	  goto BuildCmd;

        case 'j':                 // join
        case 'l':                 // leave
	  if( OptLn != 3 ) {
	    fprintf( stderr, "wrong number of arguments for 'join'/'leave' command\n" );
	    goto Usage;
	  }
	  
	  goto BuildCmd;

        case 'k':                 // kill daemon
	  if( OptLn != 1 ) {
	    fprintf( stderr, "no arguments allowed for 'k' option\n" );
	    goto Usage;
	  }

	  goto BuildCmd;

        case 'h':                 // help
	  puts( Version );
	  puts( Usage );
	  break;

        case 'v':                 // verbose
	  fputs( Version, stderr );
	  Log2Stderr = LOG_DEBUG;
	  break;

        case 'd':                 // daemon	
	  StartDaemon = 1;
	  break;

        default:                  // unknown option
	  fprintf( stderr, "unknown option: %s\n", *ArgVc );
	  goto Usage;
      }
    }
  }

  // !!! signal( SIGINT, SIGQUIT, SIGTERM  

  if( StartDaemon ) {                       // only daemon parent enters

    /* creat daemon process
     */
    if( ! fork() ) {                   // only daemon enters
      int IpcServerFD;

      // init before detach to see errors on the terminal
      initMRouter();
      IpcServerFD = initIpcServer();

      // detach deamon from terminal
      if( close( 0 ) < 0 || close( 1 ) < 0 || close( 2 ) < 0 
	  || open( "/dev/null", 0 ) != 0 || dup2( 0, 1 ) < 0 || dup2( 0, 2 ) < 0
	  || setpgrp() < 0
      )
	log( LOG_ERR, errno, "failed to detach deamon" );

      while( 1 ) {
	struct CmdPkt *PktPt;
        
	// watch the MRouter and the IPC socket to the smcroute client
	{
	  fd_set ReadFDS;
	  int MaxFD = MAX( IpcServerFD, MRouterFD );
	  int Rt;

	  FD_ZERO( &ReadFDS );
	  FD_SET( IpcServerFD, &ReadFDS );
	  FD_SET( MRouterFD, &ReadFDS );

	  // wait for input
	  Rt = select( MaxFD +1, &ReadFDS, NULL, NULL, NULL );

	  // log and ignore failures
	  if( Rt <= 0 ) {
	    log( LOG_WARNING, errno, "select() failure" );
	    continue;
	  }
	  
	  // receive and drop IGMP stuff
	  if( FD_ISSET( MRouterFD, &ReadFDS ) ) {
	    char Bu[ 128 ];
	    
	    Rt = read( MRouterFD, Bu, sizeof( Bu ) ); 
	    log( LOG_DEBUG, 0, "%d byte IGMP signaling dropped", Rt );
	  }

	  // loop back to select if there is no smcroute command
	  if( ! FD_ISSET( IpcServerFD, &ReadFDS ) ) 
	    continue;
	}

	// receive the command from the smcroute client
	PktPt = readIpcServer( Bu, sizeof( Bu ) );

	switch( PktPt->Cmd ) {
	  struct MRouteDesc MrDe;
	  const char *ErrSt;

          case 'a':
	  case 'r':  
	    if( (ErrSt = convCmdPkt2MRouteDesc( &MrDe, PktPt )) ) {
	      log( LOG_WARNING, 0, ErrSt );
	      sendIpc( LogLastMsg, strlen( LogLastMsg ) +1 );
	      break;
	    }

	    if( (PktPt->Cmd == 'a' && addMRoute( &MrDe ))
             || (PktPt->Cmd == 'r' && delMRoute( &MrDe )) 
            ) {
	      sendIpc( LogLastMsg, strlen( LogLastMsg ) +1 );
	      break;
	    }

	    sendIpc( "", 1 );
	    break;

          case 'j':
	  case 'l': 
	  {
	    const char *IfSt    = (const char *)(PktPt +1),
	      *McAdrSt = IfSt + strlen( IfSt ) +1;
	      
	    struct in_addr McAdr;
	    int Rt;

	    // check multicast address
	    if( ! *McAdrSt || ! inet_aton( McAdrSt, &McAdr ) 
		|| ! IN_MULTICAST( ntohl( McAdr.s_addr ) ) 
	    ) {
	      log( LOG_WARNING, 0, "invalid multicast group address: '%s'", 
		   McAdrSt );
	      sendIpc( LogLastMsg, strlen( LogLastMsg ) +1 );
	      break;
	    }

	    // create socket for IGMP as needed
	    if( ! McGroupSock ) 
	      McGroupSock = openUdpSocket( INADDR_ANY, 0 );

	    // join or leave
	    if( PktPt->Cmd == 'j' )
	      Rt = joinMcGroup( McGroupSock, IfSt, McAdr );
	    else
	      Rt = leaveMcGroup( McGroupSock, IfSt, McAdr );

	    // failed
	    if( Rt ) {
	      sendIpc( LogLastMsg, strlen( LogLastMsg ) +1 );
	      break;
	    }

	    sendIpc( "", 1 );
	    break;
	  }

          case 'k':
	    sendIpc( "", 1 );
	    exit( 0 );
	}
      }
    }
  }

  // Client or daemon parent only, the daemon never reach this point

  // send commands
  if( CmdVcPt > CmdVc ) {        
    struct CmdPkt **PktPp; 

    openlog( ArgVc[ 0 ], LOG_PID, LOG_USER );

    // connect to daemon
    {
      int Err;
      int RetryCn = 30;

Retry:
      switch( Err = initIpcClient() ) {

	case 0: 
	  break;

	case EACCES: 
	  log( LOG_ERR, EACCES, "need super-user rights to connect to daemon" ); 
	  break;

	case ENOENT:
	case ECONNREFUSED: 
	  // if we started the daemon -> give it 30 times a 1/10 second to 
	  // get ready
	  if( StartDaemon && --RetryCn ) {
	    usleep( 100000 );
	    goto Retry;
	  }

	  log( LOG_ERR, Err, "daemon not running ?" );
	  break;

	default:
	  log( LOG_ERR, Err, "can't connect to daemon" );
	  break;
      }
    }

    for( PktPp = CmdVc; PktPp < CmdVcPt; PktPp++ ) {
      int RdSz;
      
      if( (sendIpc( *PktPp, (*PktPp)->PktSz ) < 0) 
       || (RdSz = readIpc( Bu, sizeof( Bu ) )) < 0   
      )
	log( LOG_ERR, errno, "read/write to daemon failed" );

      log( LOG_DEBUG, 0, "RdSz: %d", RdSz );

      if( RdSz != 1 || *Bu != '\0' ) {
	fprintf( stderr, "daemon error: %s\n", Bu );
	ProgRt = 1;
      }

      free( *PktPp );
    }
  }

  return ProgRt;
}










