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
**  $Id: cmdpkt.c,v 1.4 2001/08/27 09:33:22 cschill Exp $	
**
**  This module contains the functions to build and convert IPC command packets
**
*/

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

  // accumulate space for arg strings
  {
    const char **Pp;
    int Cn;

    for( Cn = ParCn, Pp = ArgVc, AccStSz = 0; Cn; Cn--, Pp++ ) 
      AccStSz += strlen( *Pp ) +1;
  } 

  // resulting packet size
  PktSz = sizeof( struct CmdPkt ) + AccStSz +1;

  // makes no sense
  if( PktSz > MX_CMDPKT_SZ ) 
    log( LOG_ERR, 0, "option too big" );

  // build packet
  if( ! (PktPt = malloc( PktSz )) )
    log( LOG_ERR, errno, "out of memory for option arguments" );

  PktPt->PktSz = PktSz;
  PktPt->Cmd   = Cmd;
  PktPt->ParCn = ParCn;
  
  // copy args
  {
    char *FillPt;

    for( FillPt = (char *)(PktPt +1); ParCn; ParCn--, ArgVc++ ) {
      int Sz = strlen( *ArgVc ) +1;

      memcpy( FillPt, *ArgVc, Sz );
      FillPt += Sz;
    }
    
    *FillPt = '\0';           // '\0' behind last string       
  }
  
  return PktPt;
} 

const char *
convCmdPkt2MRouteDesc( struct MRouteDesc *MrDp, const struct CmdPkt *PktPt )
/*
** Convers a command packet 'PktPt' to a MRouteDesc struct 'MrDp' for the
** 'add' and 'remove' command.
**
** returns: - NULL if the conversion succeeded
**          - an error string with a hint why the conversion failed
**          
*/
{
  const char *ArgSt = (const char *)(PktPt +1);

  // get input interface index 
  if( ! *ArgSt || (MrDp->InVif = getVifIxfromArg( ArgSt )) < 0 ) 
    return "invalid input interface";

  // get origin
  ArgSt += strlen( ArgSt ) +1;
  if( ! *ArgSt || ! inet_aton( ArgSt, &MrDp->OriginAdr ) ) 
    return "invalid origin IP address";

  // get multicast group
  ArgSt += strlen( ArgSt ) +1;      
  if( ! *ArgSt || ! inet_aton( ArgSt, &MrDp->McAdr )
   || ! IN_MULTICAST( ntohl( MrDp->McAdr.s_addr ) ) 
  ) 
    return "invalid multicast group address";

  // clear output interfaces 
  memset( MrDp->TtlVc, 0, sizeof( MrDp->TtlVc ) );

  // scan output interfaces for the 'add' command only, just ignore it 
  // for the 'remove' command to be compatible to the first release
  if( PktPt->Cmd == 'a' ) {
    for( ArgSt += strlen( ArgSt ) +1; *ArgSt; ArgSt += strlen( ArgSt ) +1 ) {
      int VifIx;

      if( (VifIx = getVifIxfromArg( ArgSt )) < 0 )
	return "invalid output interface";
    
      if( VifIx == MrDp->InVif ) 
	log( LOG_WARNING, 0, "forwarding multicast to the input interface may not make sense: %s", ArgSt );
    
      MrDp->TtlVc[ VifIx ] = 1;           // !!! use a TTL threashold 	
      ArgSt += strlen( ArgSt ) +1;          
    }
  }

  return NULL;
}




