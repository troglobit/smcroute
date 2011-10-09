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
**  $Id: ifvc.c 85 2011-08-08 16:47:53Z micha $	
**
**  This module manages an interface vector of the machine
**
*/

#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include "mclab.h"

struct IfDesc IfDescVc[ MAX_IF ], *IfDescEp = IfDescVc;

void buildIfVc()
/*
** Builds up a vector with the interface of the machine. Calls to the other functions of 
** the module will fail if they are called before the vector is build.
**          
*/
{
  struct ifaddrs *ifaddr, *ifa;

  memset(IfDescVc, 0, sizeof(IfDescVc));
  
  if (getifaddrs(&ifaddr) == -1) {
    smclog( LOG_ERR, errno, "Failed to retrieve interface addresses" );
    return;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    int family = ifa->ifa_addr->sa_family;

    /* Skip non-IPv4 and non-IPv6 interfaces */
    if ((family != AF_INET) && (family != AF_INET6)) continue;
    /* Skip interface without internet address */
    if (ifa->ifa_addr == NULL) continue;

    /* Copy data from interface iterator 'ifa' */
    strncpy(IfDescEp->Name, ifa->ifa_name, sizeof(IfDescEp->Name));
    if (family == AF_INET)
      IfDescEp->InAdr.s_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
    IfDescEp->Flags = ifa->ifa_flags;
    IfDescEp->IfIndex = if_nametoindex(IfDescEp->Name);
    IfDescEp->VifIndex = -1;
    IfDescEp++;
  }
  freeifaddrs(ifaddr);
}


struct IfDesc *getIfByName( const char *IfName )
/*
** Returns a pointer to the IfDesc of the interface 'IfName'
**
** returns: - pointer to the IfDesc of the requested interface
**          - NULL if no interface 'IfName' exists
**          
**          - if more than one interface 'IfName' exists, chose the
**            an interface that corresponds to a virtual interface
*/
{
  struct IfDesc *Dp;
  struct IfDesc *candidate = NULL;

  for( Dp = IfDescVc; Dp < IfDescEp; Dp++ ) 
    if( ! strcmp( IfName, Dp->Name ) ) {
      if (Dp->VifIndex >= 0) return Dp;
      candidate = Dp;
  }

  return candidate;
}

struct IfDesc *getIfByIx( unsigned Ix )
/*
** Returns a pointer to the IfDesc of the interface 'Ix'
**
** returns: - pointer to the IfDesc of the requested interface
**          - NULL if no interface 'Ix' exists
**          
*/
{
  struct IfDesc *Dp = &IfDescVc[ Ix ];
  return Dp < IfDescEp ? Dp : NULL;
}



