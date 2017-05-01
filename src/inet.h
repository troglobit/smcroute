/* Multicast Router Discovery Protocol, RFC4286 (IPv4 backend)
 *
 * Copyright (C) 2017  Joachim Nilsson <troglobit@gmail.com>
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

#ifndef SMCROUTE_INET_H_
#define SMCROUTE_INET_H_

#include <stdint.h>

#define IGMP_MRDISC_ANNOUNCE 0x30
#define IGMP_MRDISC_SOLICIT  0x31
#define IGMP_MRDISC_TERM     0x32

int inet_open  (char *ifname);
int inet_close (int sd);

int inet_send  (int sd, uint8_t type, uint8_t interval);
int inet_recv  (int sd,               uint8_t interval);

#endif /* SMCROUTE_INET_H_ */
