/* Common include file
 *
 * Copyright (C) 2001-2005  Carsten Schill <carsten@cschill.de>
 * Copyright (C) 2006-2009  Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2009       Todd Hayton <todd.hayton@gmail.com>
 * Copyright (C) 2009-2011  Micha Lenk <micha@debian.org>
 * Copyright (C) 2011-2017  Joachim Nilsson <troglobit@gmail.com>
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

#ifndef SMCROUTE_MCLAB_H_
#define SMCROUTE_MCLAB_H_

#include "config.h"
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <arpa/inet.h>

/* mcgroup.c */
int  mcgroup4_join      (const char *ifname, struct in_addr  source, struct in_addr  group);
int  mcgroup4_leave     (const char *ifname, struct in_addr  source, struct in_addr  group);
void mcgroup4_disable   (void);

int  mcgroup6_join      (const char *ifname, struct in6_addr group);
int  mcgroup6_leave     (const char *ifname, struct in6_addr group);
void mcgroup6_disable   (void);

/* pidfile.c */
int pidfile(const char *basename, uid_t uid, gid_t gid);

#endif /* SMCROUTE_MCLAB_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
