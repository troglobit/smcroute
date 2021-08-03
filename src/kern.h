/* Kernel API for join/leave multicast groups and add/del routes
 *
 * Copyright (c) 2011-2020  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef SMCROUTE_KERN_H_
#define SMCROUTE_KERN_H_

#include "mcgroup.h"
#include "mroute.h"

int kern_join_leave (int sd, int cmd, struct mcgroup *mcg);
int kern_mroute4    (int sd, int cmd, struct mroute *route, int active);
int kern_mroute6    (int sd, int cmd, struct mroute *route);

#endif /* SMCROUTE_KERN_H_ */
