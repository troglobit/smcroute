/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006-2009 Julien BLACHE <jb@jblache.org>
**  Copyright (C) 2009      Todd Hayton <todd.hayton@gmail.com>
**  Copyright (C) 2009-2011 Micha Lenk <micha@debian.org>
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
**  $Id: cmdpkt.c 85 2011-08-08 16:47:53Z micha $	
**
**  This module contains the functions to build and convert IPC command packets
**
*/

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mclab.h"

static int getVifIxfromArg( const char *ArgPt )
/*
** Gets the VIF index for a given interface name '*ArgPt'
**
** returns: - index of the VIF
**          - -1 if no VIF can be found for the interface name
**          
*/
{
  struct IfDesc *IfDp;
  int Rt;

  /* get input interface index -> InpVifIx
   */
  if( ! (IfDp = getIfByName( ArgPt )) ) 
    return -1;

  if( (Rt = getVifIx( IfDp )) < 0 ) 
    return -1;

  return Rt;
}

static int getMifIxfromArg( const char *ArgPt )
/*
** Gets the MIF index for a given interface name '*ArgPt'
**
** returns: - index of the MIF
**          - -1 if no MIF can be found for the interface name
**          
*/
{
  struct IfDesc *IfDp;
  int Rt;

  /* get input interface index -> InpVifIx
   */
  if( ! (IfDp = getIfByName( ArgPt )) ) 
    return -1;

  if( (Rt = getMifIx( IfDp )) < 0 ) 
    return -1;

  return Rt;
}

void *buildCmdPkt( char Cmd, const char *ArgVc[], int ParCn )
/*
** Builds an command packet with the command 'Cmd' and 'ParCn' arguments
** from 'ArgVc'.
**
** returns: - pointer to the dyn. allocated command packet
**          
*/
{
  unsigned AccStSz, PktSz;
  struct CmdPkt *PktPt;

  /* accumulate space for arg strings */
  {
    const char **Pp;
    int Cn;

    for( Cn = ParCn, Pp = ArgVc, AccStSz = 0; Cn; Cn--, Pp++ ) 
      AccStSz += strlen( *Pp ) +1;
  } 

  /* resulting packet size */
  PktSz = sizeof( struct CmdPkt ) + AccStSz +1;

  /* makes no sense */
  if( PktSz > MX_CMDPKT_SZ ) 
    smclog( LOG_ERR, 0, "option too big" );

  /* build packet */
  if( ! (PktPt = malloc( PktSz )) )
    smclog( LOG_ERR, errno, "out of memory for option arguments" );

  PktPt->PktSz = PktSz;
  PktPt->Cmd   = Cmd;
  PktPt->ParCn = ParCn;
  
  /* copy args */
  {
    char *FillPt;

    for( FillPt = (char *)(PktPt +1); ParCn; ParCn--, ArgVc++ ) {
      int Sz = strlen( *ArgVc ) +1;

      memcpy( FillPt, *ArgVc, Sz );
      FillPt += Sz;
    }
    
    *FillPt = '\0';           /* '\0' behind last string */
  }
  
  return PktPt;
} 

const char * 
convCmdPkt2MRouteDesc( struct MRouteDesc *MrDp, const struct CmdPkt *PktPt )
/*
** Converts a command packet 'PktPt' to an MRouteDesc struct 'MrDp' for the
** 'add' and 'remove' command. The IP version is determined by searching
** for ':' in the address strings to indicate IPv6 addresses.
**
** returns: - NULL if the conversion succeeded
**          - an error string with a hint why the conversion failed
**          
*/
{
  char *ArgSt = (char *)(PktPt +1);
  
  memset(MrDp, 0, sizeof(*MrDp));

  switch (PktPt->Cmd) {
  case 'a':
  case 'r':
    /* 
     *
     * -a eth0 1.1.1.1 239.1.1.1 eth1 eth2
     *
     *  +----+-----+---+--------------------------------------------+
     *  | 42 | 'a' | 5 | "eth0\01.1.1.1\0239.1.1.1\0eth1\0eth2\0\0" | 
     *  +----+-----+---+--------------------------------------------+
     *  ^              ^
     *  |              |  
     *  |              |
     *  +---CmdPkt-----+
     *
     * -r 1.1.1.1 239.1.1.1 
     *
     *  +----+-----+---+--------------------------+
     *  | 27 | 'r' | 2 | "1.1.1.1\0239.1.1.1\0\0" | 
     *  +----+-----+---+--------------------------+
     *  ^              ^
     *  |              |  
     *  |              |
     *  +---CmdPkt-----+
     *
     */
    if (PktPt->Cmd == 'a' || PktPt->ParCn > 2)     
      ArgSt += strlen(ArgSt) + 1;

    if (strchr(ArgSt, ':') != NULL) {
      MrDp->ipVersion = 6;
      return convCmdPkt2MRoute6Desc( &MrDp->u.mRoute6Desc, PktPt );
    } else {
      MrDp->ipVersion = 4;
      return convCmdPkt2MRoute4Desc( &MrDp->u.mRoute4Desc, PktPt );
    }
    break;

  default:
    return "Invalid command";
  }

  return NULL;
}

const char *
convCmdPkt2MRoute4Desc( struct MRoute4Desc *MrDp, const struct CmdPkt *PktPt )
/*
** Converts a command packet 'PktPt' to an MRoute4Desc struct 'MrDp' for the
** 'add' and 'remove' command.
**
** returns: - NULL if the conversion succeeded
**          - an error string with a hint why the conversion failed
**          
*/
{
  const char *ArgSt = (const char *)(PktPt +1);

  memset(MrDp, 0, sizeof(*MrDp));

  /* 
   *
   * -a eth0 1.1.1.1 239.1.1.1 eth1 eth2
   *
   *  +----+-----+---+--------------------------------------------+
   *  | 42 | 'a' | 5 | "eth0\01.1.1.1\0239.1.1.1\0eth1\0eth2\0\0" | 
   *  +----+-----+---+--------------------------------------------+
   *  ^              ^
   *  |              |  
   *  |              |
   *  +---CmdPkt-----+
   *        
   */

  /* get input interface index */
  if( ! *ArgSt || (MrDp->InVif = getVifIxfromArg( ArgSt )) < 0 ) 
    return "invalid input interface";

  /* get origin */
  ArgSt += strlen( ArgSt ) +1;
  if( ! *ArgSt || (inet_pton( AF_INET, ArgSt, &MrDp->OriginAdr ) <= 0) ) 
    return "invalid origin IP address";

  /* get multicast group */
  ArgSt += strlen( ArgSt ) +1;      
  if( ! *ArgSt || (inet_pton( AF_INET, ArgSt, &MrDp->McAdr ) <= 0)
   || ! IN_MULTICAST( ntohl( MrDp->McAdr.s_addr ) ) 
  ) 
    return "invalid multicast group address";

  /*
   * Scan output interfaces for the 'add' command only, just ignore it 
   * for the 'remove' command to be compatible to the first release.
   */
  if( PktPt->Cmd == 'a' ) {
    for( ArgSt += strlen( ArgSt ) +1; *ArgSt; ArgSt += strlen( ArgSt ) +1 ) {
      int VifIx;

      if( (VifIx = getVifIxfromArg( ArgSt )) < 0 )
	return "invalid output interface";
    
      if( VifIx == MrDp->InVif ) 
	smclog( LOG_WARNING, 0, "forwarding multicast to the input interface may not make sense: %s", ArgSt );
    
      MrDp->TtlVc[ VifIx ] = 1;           /* Use a TTL threashold */
    }
  }

  return NULL;
}

const char *
convCmdPkt2MRoute6Desc( struct MRoute6Desc *MrDp, const struct CmdPkt *PktPt )
/*
** Converts a command packet 'PktPt' to an MRoute6Desc struct 'MrDp' for the
** 'add' and 'remove' command.
**
** returns: - NULL if the conversion succeeded
**          - an error string with a hint why the conversion failed
**          
*/
{
  const char *ArgSt = (const char *)(PktPt +1);

  memset(MrDp, 0, sizeof(*MrDp));

  /* get input interface index */
  if( ! *ArgSt || (MrDp->InMif = getMifIxfromArg( ArgSt )) < 0 ) 
    return "invalid input interface";

  /* get origin */
  ArgSt += strlen( ArgSt ) +1;
  if( ! *ArgSt || (inet_pton( AF_INET6, ArgSt, &MrDp->OriginAdr.sin6_addr ) <= 0) ) 
    return "invalid origin IP address";

  /* get multicast group */
  ArgSt += strlen( ArgSt ) +1;      

  if( ! *ArgSt || (inet_pton( AF_INET6, ArgSt, &MrDp->McAdr.sin6_addr ) <= 0) 
      || ! IN6_MULTICAST( &MrDp->McAdr.sin6_addr ) ) 
    return "invalid multicast group address";

  /*
   * Scan output interfaces for the 'add' command only, just ignore it 
   * for the 'remove' command to be compatible to the first release.
   */
  if( PktPt->Cmd == 'a' ) {
    for( ArgSt += strlen( ArgSt ) +1; *ArgSt; ArgSt += strlen( ArgSt ) +1 ) {
      int MifIx;

      if( (MifIx = getMifIxfromArg( ArgSt )) < 0 )
	return "invalid output interface";
    
      if( MifIx == MrDp->InMif ) 
	smclog( LOG_WARNING, 0, "forwarding multicast to the input interface may not make sense: %s", ArgSt );
    
      MrDp->TtlVc[ MifIx ] = 1;           /* Use a TTL threashold */
    }
  }

  return NULL;
}




