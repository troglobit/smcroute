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
**  $Id: udpsock.c 17 2006-06-24 12:34:30Z jblache $	
**
**  This module contains UDP socket function(s)
**
*/

#include "mclab.h"

/*
** Creates and connects a simple UDP socket to the target 
** 'inaddr':'Port'
**
** returns: - the opened socket
*/
int udp_socket_open(uint32 inaddr, uint16 port)
{
	int sd;
	struct sockaddr_in sa;

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0)
		smclog(LOG_ERR, errno, "UDP socket open");

	sa.sin_family = AF_INET;
	sa.sin_port = port;
	sa.sin_addr.s_addr = inaddr;
	memset(&sa.sin_zero, 0, sizeof(sa.sin_zero));

	if (connect(sd, (struct sockaddr *)&sa, sizeof(sa)))
		smclog(LOG_ERR, errno, "UDP socket connect");

	return sd;
}

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
