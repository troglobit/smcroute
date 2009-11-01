/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006-2008 Julien BLACHE <jb@jblache.org>
**  Copyright (C) 2009      Julien BLACHE <jb@jblache.org>,
**                          Todd Hayton <todd.hayton@gmail.com>, and
**                          Micha Lenk <micha@debian.org>
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
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>

#include "mclab.h"

#include "config.h"
#include "build.h"

static const char Version[] = 
"smcroute, Version " PACKAGE_VERSION ", Build" BUILD "\n"
"Copyright 2001-2005 Carsten Schill <carsten@cschill.de>\n"
"Copyright 2006-2009 Julien Blache <jb@jblache.org>,\n"
"                    Todd Hayton <todd.hayton@gmail.com>, and\n"
"                    Micha Lenk <micha@debian.org>\n"
"Distributed under the GNU GENERAL PUBLIC LICENSE, Version 2 - check GPL.txt\n"
"\n";

static const char Usage[] = 
"usage: smcroute\t[-v] [-d] [-k] [-D]\n"
"\n" 
"\t\t[-a <InputIntf> <OriginIpAdr> <McGroupAdr> <OutputIntf> [<OutputIntf>] ...]\n"
"\t\t[-r <InputIntf> <OriginIpAdr> <McGroupAdr>]\n"
"\n"
"\t\t[-j <InputIntf> <McGroupAdr>]\n"
"\t\t[-l <InputIntf> <McGroupAdr>]\n"
;

static const char MissingArgSt[] = "<missing argument>";

int McGroupSock4 = -1;
int McGroupSock6 = -1;

int do_debug_logging = 0;

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

  /* end of vector */
  if( ArgVc == NULL || *ArgVc == NULL )
    return 0; 

  /* starting on wrong position */
  if( **ArgVc != '-' )
    return -1;

  for( Pp = ArgVc +1; *Pp && **Pp != '-'; Pp++ )
    /* */;
    
  return Pp - ArgVc;
}


static void clean()
/*
** Cleans up, i.e. releases allocated resources. Called via atexit().
** 
*/        
{
  smclog( LOG_DEBUG, 0, "clean handler called" );
  disableMRouter4();
  disableMRouter6();
  cleanIpc();
}


static int initMRouter4()
/*
** Inits the necessary resources for IPv4 MRouter.
**
*/
{
  int Err;

  switch( Err = enableMRouter4() ) {
    case 0: break;
    case EADDRINUSE: smclog( LOG_INIT, EADDRINUSE, "MC-Router IPv4 API already in use" ); return -1;
    case ENOPROTOOPT: smclog( LOG_WARNING, 0, "Kernel does not support IPv4 multicast routing (skipping IPv4 routing)" ); return -1;
    default: smclog( LOG_INIT, Err, "MRT_INIT failed" ); return -1;
  }
      
  /* create VIFs for all IP, non-loop interfaces
   */
  {
    unsigned Ix;
    struct IfDesc *Dp;

    for( Ix = 0; (Dp = getIfByIx( Ix )); Ix++ ) 
      if( Dp->InAdr.s_addr && ! (Dp->Flags & IFF_LOOPBACK) )
	addVIF( Dp );
  }

  return 0;
}

static int initMRouter6()
/*
** Inits the necessary resources for IPv6 MRouter.
**
*/
{
  int Err;

  switch( Err = enableMRouter6() ) {
    case 0: break;
    case EADDRINUSE: smclog( LOG_INIT, EADDRINUSE, "MC-Router IPv6 API already in use" ); return -1;
    case ENOPROTOOPT: smclog( LOG_WARNING, 0, "Kernel does not support IPv6 multicast routing (skipping IPv6 routing)" ); return -1;
    default: smclog( LOG_INIT, Err, "MRT6_INIT failed" ); return -1;
  }
      
  /* create MIFs for all IP, non-loop interfaces
   */
  {
    unsigned Ix;
    struct IfDesc *Dp;

    for( Ix = 0; (Dp = getIfByIx( Ix )); Ix++ ) 
      if( Dp->InAdr.s_addr && ! (Dp->Flags & IFF_LOOPBACK) )
	addMIF( Dp );
  }

  return 0;
}

void ServerLoop(void)
{
  uint8 Bu[ MX_CMDPKT_SZ ];
  int IpcServerFD;
  unsigned short initialized_api_count;

  /*
   * Init everything before forking, so we can fail and return an
   * error code in the parent and the initscript will fail
   */

  /* 
   * Build list of multicast-capable physical interfaces that 
   * are currently assigned an IP address.
   */
  buildIfVc();    

  initialized_api_count = 0;
  if (initMRouter4() == 0)
    initialized_api_count++;

  if (initMRouter6() == 0)
    initialized_api_count++;

  /* At least one API (IPv4 or IPv6) must have initialized successfully
   * otherwise we abort the server initialization.
   */
  if (initialized_api_count == 0) {
    smclog( LOG_INIT, ENOPROTOOPT, "Kernel does not support multicast routing" );
    exit(1);
  }

  IpcServerFD = initIpcServer();
  if (IpcServerFD < 0) {
    clean();
    exit(2);
  }

  /* creat daemon process
   */
  if( ! fork() ) {                   /* only daemon enters */
    atexit( clean );

    /* Detach deamon from terminal */
    if( close( 0 ) < 0 || close( 1 ) < 0 || close( 2 ) < 0 
	|| open( "/dev/null", 0 ) != 0 || dup2( 0, 1 ) < 0 || dup2( 0, 2 ) < 0
	|| setpgrp() < 0
	)
      smclog( LOG_ERR, errno, "failed to detach deamon" );

    while( 1 ) {
      struct CmdPkt *PktPt;
        
      /* watch the MRouter and the IPC socket to the smcroute client */
      {
	fd_set ReadFDS;
	int MaxFD = MAX( IpcServerFD, MAX( MRouterFD4, MRouterFD6 ) );
	int Rt;

	FD_ZERO( &ReadFDS );
	FD_SET( IpcServerFD, &ReadFDS );
	FD_SET( MRouterFD4, &ReadFDS );
	FD_SET( MRouterFD6, &ReadFDS );

	/* wait for input */
	Rt = select( MaxFD +1, &ReadFDS, NULL, NULL, NULL );

	/* log and ignore failures */
	if( Rt <= 0 ) {
	  smclog( LOG_WARNING, errno, "select() failure" );
	  continue;
	}
	  
	/* 
	 * Receive and drop IGMP stuff. This is either IGMP packets
	 * or upcall messages sent up from the kernel.
	 */
	if( FD_ISSET( MRouterFD4, &ReadFDS ) ) {
	  char Bu[ 128 ];
	    
	  Rt = read( MRouterFD4, Bu, sizeof( Bu ) ); 
	  if (do_debug_logging)
            smclog( LOG_DEBUG, 0, "%d byte IGMP signaling dropped", Rt );
	}

	/* 
	 * Receive and drop ICMPv6 stuff. This is either MLD packets
	 * or upcall messages sent up from the kernel.
	 */
	if( FD_ISSET( MRouterFD6, &ReadFDS ) ) {
	  char Bu[ 128 ];
	    
	  Rt = read( MRouterFD6, Bu, sizeof( Bu ) ); 
	  if (do_debug_logging)
	    smclog( LOG_DEBUG, 0, "%d byte MLD signaling dropped", Rt );
	}

	/* loop back to select if there is no smcroute command */
	if( ! FD_ISSET( IpcServerFD, &ReadFDS ) ) 
	  continue;
      }

      /* receive the command from the smcroute client */
      PktPt = readIpcServer( Bu, sizeof( Bu ) );

      switch( PktPt->Cmd ) {
	struct MRouteDesc MrDe;
	const char *ErrSt;

      case 'a':
      case 'r':  
	if( (ErrSt = convCmdPkt2MRouteDesc( &MrDe, PktPt )) ) {
	  smclog( LOG_WARNING, 0, ErrSt );
	  sendIpc( LogLastMsg, strlen( LogLastMsg ) +1 );
	  break;
	}

	if (MrDe.ipVersion == 4) {
	  if( (PktPt->Cmd == 'a' && addMRoute4( &MrDe.u.mRoute4Desc )) || 
	      (PktPt->Cmd == 'r' && delMRoute4( &MrDe.u.mRoute4Desc )) ) {
	    sendIpc( LogLastMsg, strlen( LogLastMsg ) +1 );
	    break;
	  }
	} else {
	  if( (PktPt->Cmd == 'a' && addMRoute6( &MrDe.u.mRoute6Desc )) || 
	      (PktPt->Cmd == 'r' && delMRoute6( &MrDe.u.mRoute6Desc )) ) {
	    sendIpc( LogLastMsg, strlen( LogLastMsg ) +1 );
	    break;
	  }
	}

	sendIpc( "", 1 );
	break;

      case 'j': /* j <InputIntf> <McGroupAdr> */
      case 'l': /* l <InputIntf> <McGroupAdr> */
	{
	  const char *IfSt    = (const char *)(PktPt +1);
	  const char *McAdrSt = IfSt + strlen( IfSt ) +1;
	  int         Rt;

	  if (strchr(McAdrSt, ':') == NULL) {
	    struct in_addr McAdr;

	    /* check multicast address */
	    if( ! *McAdrSt || ! inet_aton( McAdrSt, &McAdr ) 
		|| ! IN_MULTICAST( ntohl( McAdr.s_addr ) ) ) {
	      smclog( LOG_WARNING, 0, "invalid multicast group address: '%s'", 
		      McAdrSt );
	      sendIpc( LogLastMsg, strlen( LogLastMsg ) +1 );
	      break;
	    }

	    /* create socket for IGMP as needed */
	    if( McGroupSock4 < 0 ) 
	      McGroupSock4 = openUdpSocket( INADDR_ANY, 0 );

	    /* join or leave */
	    if( PktPt->Cmd == 'j' )
	      Rt = joinMcGroup4( McGroupSock4, IfSt, McAdr );
	    else
	      Rt = leaveMcGroup4( McGroupSock4, IfSt, McAdr );
	  } else { /* IPv6 */
	    struct in6_addr McAdr;

	    /* check multicast address */
	    if( ! *McAdrSt || ( inet_pton( AF_INET6, McAdrSt, &McAdr ) <= 0 ) 
		|| ! IN6_MULTICAST( &McAdr ) ) {
	      smclog( LOG_WARNING, 0, "invalid multicast group address: '%s'", 
		      McAdrSt );
	      sendIpc( LogLastMsg, strlen( LogLastMsg ) +1 );
	      break;
	    }

	    /* create socket for IGMP as needed */
	    if( McGroupSock6 < 0 ) {
	      McGroupSock6 = socket( AF_INET6, SOCK_DGRAM, IPPROTO_UDP );
	      if (McGroupSock6 < 0) 
		smclog( LOG_WARNING, errno, "socket failed" );
	    }

	    /* join or leave */
	    if( PktPt->Cmd == 'j' )
	      Rt = joinMcGroup6( McGroupSock6, IfSt, McAdr );
	    else
	      Rt = leaveMcGroup6( McGroupSock6, IfSt, McAdr );
	  }

	  /* failed */
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
  int StartDaemon = 0;
  int ProgRt = 0;

  /* init syslog */
  openlog( ArgVc[ 0 ], LOG_PID, LOG_DAEMON );   
  
  if( ArgCn <= 1 ) {
Usage:    
    fputs( Version, stderr );
    fputs( Usage, stderr );
    return 1;
  }

  /* scan options */
  {
    int OptLn;

    for( OptLn = 1; (OptLn = getArgOptLn( ArgVc += OptLn )); ) {
  
      if( OptLn < 0 )           /* error */
	goto Usage;
    
      /* handle option */
      switch( *(*ArgVc +1) ) {
      case 'a':                 /* add route */
	if( OptLn < 5 ) {
	  fprintf( stderr, "not enough arguments for 'add' command\n" );
	  goto Usage;
	}

BuildCmd:
	if( CmdVcPt >= VCEP( CmdVc ) ) {
	  fprintf( stderr, "too many command options\n" );
	  goto Usage;
	}
	  
	*CmdVcPt++ = buildCmdPkt( *(*ArgVc +1), ArgVc +1, OptLn -1 );
	break;

      case 'r':                 /* remove route */
	if( OptLn < 4 ) {
	  fprintf( stderr, "wrong number of  arguments for 'remove' command\n" );
	  goto Usage;
	}

	goto BuildCmd;

      case 'j':                 /* join */
      case 'l':                 /* leave */
	if( OptLn != 3 ) {
	  fprintf( stderr, "wrong number of arguments for 'join'/'leave' command\n" );
	  goto Usage;
	}
	  
	goto BuildCmd;

      case 'k':                 /* kill daemon */
	if( OptLn != 1 ) {
	  fprintf( stderr, "no arguments allowed for 'k' option\n" );
	  goto Usage;
	}

	goto BuildCmd;

      case 'h':                 /* help */
	puts( Version );
	puts( Usage );
	break;

      case 'v':                 /* verbose */
	fputs( Version, stderr );
	Log2Stderr = LOG_DEBUG;
	break;

      case 'd':                 /* daemon */
	StartDaemon = 1;
	break;

      case 'D':
        do_debug_logging = 1;
        break;

      default:                  /* unknown option */
	fprintf( stderr, "unknown option: %s\n", *ArgVc );
	goto Usage;
      }
    }
  }

  if( StartDaemon ) {                       /* only daemon parent enters */
    ServerLoop();
  }

  /* Client or daemon parent only, the daemon never reaches this point */

  /* send commands */
  if( CmdVcPt > CmdVc ) {        
    struct CmdPkt **PktPp; 

    openlog( ArgVc[ 0 ], LOG_PID, LOG_USER );

    /* connect to daemon */
    {
      int Err;
      int RetryCn = 30;

Retry:
      switch( Err = initIpcClient() ) {

	case 0: 
	  break;

	case EACCES: 
	  smclog( LOG_ERR, EACCES, "need super-user rights to connect to daemon" ); 
	  break;

	case ENOENT:
	case ECONNREFUSED: 
	  /*
	   * If we started the daemon -> give it 30 times a 1/10 second to 
	   * get ready
	   */
	  if( StartDaemon && --RetryCn ) {
	    usleep( 100000 );
	    goto Retry;
	  }

	  smclog( LOG_ERR, Err, "daemon not running ?" );
	  break;

	default:
	  smclog( LOG_ERR, Err, "can't connect to daemon" );
	  break;
      }
    }

    for( PktPp = CmdVc; PktPp < CmdVcPt; PktPp++ ) {
      int RdSz = 0;
      
      if( (sendIpc( *PktPp, (*PktPp)->PktSz ) < 0) 
       || (RdSz = readIpc( Bu, sizeof( Bu ) )) < 0   
      )
	smclog( LOG_ERR, errno, "read/write to daemon failed" );

      if (do_debug_logging)
        smclog( LOG_DEBUG, 0, "RdSz: %d", RdSz );

      if( RdSz != 1 || *Bu != '\0' ) {
	fprintf( stderr, "daemon error: %s\n", Bu );
	ProgRt = 1;
      }

      free( *PktPp );
    }
  }

  return ProgRt;
}










