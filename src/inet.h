/* Housekeeping IPv4/IPv6 wrapper functions
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

#ifndef SMCROUTE_INET_H_
#define SMCROUTE_INET_H_

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>		/* inet_ntop() */

#ifdef  HAVE_IPV6_MULTICAST_HOST
#define INET_ADDRSTR_LEN  INET6_ADDRSTRLEN
#else
#define INET_ADDRSTR_LEN  INET_ADDRSTRLEN
#endif
typedef struct sockaddr_storage inet_addr_t;

void                 inet_addr_set  (inet_addr_t *addr, const struct in_addr *ina);
struct in_addr      *inet_addr_get  (inet_addr_t *addr);

void                 inet_addr6_set (inet_addr_t *addr, const struct in6_addr *ina);
struct sockaddr_in6 *inet_addr6_get (inet_addr_t *addr);

void                 inet_anyaddr   (sa_family_t family, inet_addr_t *addr);

int                  inet_addr_cmp  (inet_addr_t *a, inet_addr_t *b);

const char          *inet_addr2str  (inet_addr_t *addr, char *str, size_t len);
int                  inet_str2addr  (const char *str, inet_addr_t *addr);

int                  is_multicast   (inet_addr_t *addr);
int                  is_anyaddr     (inet_addr_t *addr);

#endif /* SMCROUTE_INET_H_ */
