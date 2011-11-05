/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006-2008 Julien BLACHE <jb@jblache.org>
**  Copyright (C) 2009      Todd Hayton <todd.hayton@gmail.com>
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
**  $Id: mcsender.c 91 2011-08-08 18:46:43Z micha $
**
**  Multicast test tool
**
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "mclab.h"

int do_debug_logging = 0;

const char Usage[] = "mcsender [-t<n>] [-i<ifname>] <ip-address:port>\n";
const char McMsg[] = "this is the test message from mclab/mcsender\n";

static void usage(void);

static void SetOif4(int, char *);
static void SetTtl4(int, unsigned);

static void SetOif6(int, char *);
static void SetTtl6(int, unsigned);

static void getSockAdr(struct sockaddr *SaPt, socklen_t * SaLenPt, char *AddrSt, char *PortSt);

int main(int ArgCn, char *ArgVc[])
{
	unsigned TtlVal = 0;
	char *OifVal = NULL;
	char *AddrSt = NULL;
	char *PortSt = NULL;
	char *Pt;
	void (*SetTtl) (int, unsigned) = NULL;
	void (*SetOif) (int, char *) = NULL;
	struct sockaddr_storage TarAdr;
	socklen_t TarAdrLen = 0;

	if (ArgCn < 2) {
		usage();
		exit(1);
	}

	while (*++ArgVc) {
		Pt = *ArgVc;

		/* option */
		if (*Pt == '-') {
			switch (*++Pt) {

			case 'D':
				do_debug_logging = 1;
				break;

			case 't':
				if (sscanf(Pt + 1, " %u", &TtlVal) != 1 || TtlVal < 1) {
					usage();
					exit(1);
				}
				break;

			case 'i':
				OifVal = Pt + 1;
				break;

			default:
				usage();
				exit(1);
			}
		} else {	/* argument */

			memset(&TarAdr, 0, sizeof(TarAdr));

			AddrSt = Pt;

			Pt = strrchr(AddrSt, ':');
			if (Pt == NULL) {
				usage();
				exit(1);
			}

			*Pt++ = '\0';
			PortSt = Pt;

			getSockAdr(SA(&TarAdr), &TarAdrLen, AddrSt, PortSt);

			SetTtl = (TarAdr.ss_family == AF_INET) ? SetTtl4 : SetTtl6;
			SetOif = (TarAdr.ss_family == AF_INET) ? SetOif4 : SetOif6;
		}
	}

	if (TarAdrLen)
	{
		int UdpSock = socket(TarAdr.ss_family, SOCK_DGRAM, IPPROTO_UDP);

		if (UdpSock < 0)
			smclog(LOG_ERR, errno, "UDP socket open");

		if (TtlVal)
			(*SetTtl) (UdpSock, TtlVal);
		if (OifVal)
			(*SetOif) (UdpSock, OifVal);

		while (1) {
			if (sendto(UdpSock, McMsg, sizeof(McMsg), 0, SA(&TarAdr), TarAdrLen) != sizeof(McMsg))
				smclog(LOG_WARNING, errno, "send to UDP socket");

			sleep(1);
		}
	}

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "Usage: %s\n", Usage);
}

static void SetTtl4(int Sock, unsigned Ttl)
{
	if (setsockopt(Sock, IPPROTO_IP, IP_MULTICAST_TTL, &Ttl, sizeof(Ttl)))
		smclog(LOG_ERR, errno, "set IP_MULTICAST_TTL");
}

static void SetOif4(int Sock, char *ifname)
{
	struct ifreq IfReq;
	struct sockaddr_in *Sin4 = NULL;

	memset(&IfReq, 0, sizeof(IfReq));
	strncpy(IfReq.ifr_name, ifname, sizeof(IfReq.ifr_name));

	if (ioctl(Sock, SIOCGIFADDR, &IfReq) < 0)
		smclog(LOG_ERR, errno, "ioctl SIOCGIFADDR");

	switch (IfReq.ifr_addr.sa_family) {
	case AF_INET:
		Sin4 = SIN4(&IfReq.ifr_addr);
		break;

	default:
		fprintf(stderr, "SetOif4 - invalid address family: %d\n",
			IfReq.ifr_addr.sa_family);
		exit(1);
	}

	if (setsockopt(Sock, IPPROTO_IP, IP_MULTICAST_IF,
		       &Sin4->sin_addr, sizeof(struct in_addr)))
		smclog(LOG_ERR, errno, "set IP_MULTICAST_IF");
}

static void SetTtl6(int Sock, unsigned Ttl)
{
	if (setsockopt(Sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		       &Ttl, sizeof(Ttl)))
		smclog(LOG_ERR, errno, "set IPV6_MULTICAST_HOPS");
}

static void SetOif6(int Sock, char *ifname)
{
	unsigned ifindex;

	ifindex = if_nametoindex(ifname);

	if (setsockopt(Sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		       &ifindex, sizeof(ifindex)))
		smclog(LOG_ERR, errno, "set IPV6_MULTICAST_IF");
}

/*
** Converts the internet address plus port string in 'St' 
** into their network byte order representations.
**
** returns: - 0 -> conversion failed
**          - 1 -> only address part returned (inaddrPt)
**          - 2 -> address and port returned
**          
*/
static void getSockAdr(struct sockaddr *SaPt, socklen_t * SaLenPt, char *AddrSt, char *PortSt)
{
	struct sockaddr_in *Sin4;
	struct sockaddr_in6 *Sin6;

	if (strchr(AddrSt, ':') == NULL) {
		Sin4 = SIN4(SaPt);
		memset(Sin4, 0, sizeof(*Sin4));

		Sin4->sin_family = AF_INET;
		Sin4->sin_port = htons(atoi(PortSt));

		if (inet_pton(AF_INET, AddrSt, &Sin4->sin_addr) <= 0)
			smclog(LOG_ERR, errno, "inet_pton failed for address %s", AddrSt);

		*SaLenPt = sizeof(struct sockaddr_in);
	} else {
		Sin6 = SIN6(SaPt);
		memset(Sin6, 0, sizeof(*Sin6));

		Sin6->sin6_family = AF_INET6;
		Sin6->sin6_port = htons(atoi(PortSt));

		if (inet_pton(AF_INET6, AddrSt, &Sin6->sin6_addr) <= 0)
			smclog(LOG_ERR, errno, "inet_pton failed for address %s", AddrSt);

		*SaLenPt = sizeof(struct sockaddr_in6);
	}
}

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
