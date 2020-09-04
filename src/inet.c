/* Multicast Router Discovery Protocol, RFC4286 (IPv4 backend)
 *
 * Copyright (C) 2017-2020  Joachim Wiberg <troglobit@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <sys/socket.h>

#include "log.h"
#include "inet.h"
#include "mrdisc.h"
#include "socket.h"

#define MC_ALL_ROUTERS       "224.0.0.2"
#define MC_ALL_SNOOPERS      "224.0.0.106"

/* Checksum routine for Internet Protocol family headers */
static unsigned short in_cksum(unsigned short *addr, int len)
{
	unsigned short *w = addr;
	unsigned short answer = 0;
	int nleft = len;
	int sum = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum  = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */

	return answer;
}

int inet_open(char *ifname)
{
	char loop;
	int sd, val, rc;
	struct ifreq ifr;
	struct ip_mreqn mreq;
	unsigned char ra[4] = { IPOPT_RA, 0x04, 0x00, 0x00 };

	sd = socket_create(AF_INET, SOCK_RAW, IPPROTO_IGMP, mrdisc_recv, NULL);
	if (sd < 0) {
		smclog(LOG_ERR, "Cannot open socket: %s", strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
		if (ENODEV == errno) {
			smclog(LOG_WARNING, "Not a valid interface, %s, skipping ...", ifname);
			socket_close(sd);
			return -1;
		}

		smclog(LOG_ERR, "Cannot bind socket to interface %s: %s", ifname, strerror(errno));
		socket_close(sd);
		return -1;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = inet_addr(MC_ALL_SNOOPERS);
	mreq.imr_ifindex = if_nametoindex(ifname);
        if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
		smclog(LOG_ERR, "Failed joining group %s: %s", MC_ALL_SNOOPERS);
		return -1;
	}

	/* mrdisc solicitation messages goes to the All-Routers group */
	mreq.imr_multiaddr.s_addr = inet_addr(MC_ALL_ROUTERS);
	mreq.imr_ifindex = if_nametoindex(ifname);
        if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
		smclog(LOG_ERR, "Failed joining group %s: %s", MC_ALL_SNOOPERS);
		return -1;
	}

	val = 1;
	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &val, sizeof(val));
	if (rc < 0) {
		smclog(LOG_ERR, "Cannot set TTL: %s", strerror(errno));
		socket_close(sd);
		return -1;
	}

	loop = 0;
	rc = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
	if (rc < 0) {
		smclog(LOG_ERR, "Cannot disable MC loop: %s", strerror(errno));
		socket_close(sd);
		return -1;
	}

	rc = setsockopt(sd, IPPROTO_IP, IP_OPTIONS, &ra, sizeof(ra));
	if (rc < 0) {
		smclog(LOG_ERR, "Cannot set IP OPTIONS: %s", strerror(errno));
		socket_close(sd);
		return -1;
	}

	return sd;
}

int inet_close(int sd)
{
	return  inet_send(sd, IGMP_MRDISC_TERM, 0) ||
		socket_close(sd);
}

static void compose_addr(struct sockaddr_in *sin, char *group)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family      = AF_INET;
	sin->sin_addr.s_addr = inet_addr(group);
}

int inet_send(int sd, uint8_t type, uint8_t interval)
{
	ssize_t num;
	struct igmp igmp;
	struct sockaddr dest;

	memset(&igmp, 0, sizeof(igmp));
	igmp.igmp_type = type;
	igmp.igmp_code = interval;
	igmp.igmp_cksum = in_cksum((unsigned short *)&igmp, sizeof(igmp));

	compose_addr((struct sockaddr_in *)&dest, MC_ALL_SNOOPERS);

	num = sendto(sd, &igmp, sizeof(igmp), 0, &dest, sizeof(dest));
	if (num < 0)
		return -1;

	return 0;
}

/* If called with interval=0, only read() */
int inet_recv(int sd, uint8_t interval)
{
	char buf[1530];
	ssize_t num;
	struct ip *ip;
	struct igmp *igmp;

	memset(buf, 0, sizeof(buf));
	num = read(sd, buf, sizeof(buf));
	if (num < 0)
		return -1;

	ip = (struct ip *)buf;
	igmp = (struct igmp *)(buf + (ip->ip_hl << 2));
	if (igmp->igmp_type == IGMP_MRDISC_SOLICIT && interval > 0) {
		smclog(LOG_DEBUG, "Received mrdisc solicitation");
		return inet_send(sd, IGMP_MRDISC_ANNOUNCE, interval);
	}

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
