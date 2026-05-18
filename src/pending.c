/* Pending mroute/mgroup directives whose inbound or outbound interface
 * is not yet available on the system.
 *
 * Lifecycle:
 *
 *   1. conf.c parser encounters an mroute/mgroup whose iface is missing
 *      and calls pending_add_*().  The directive is held here with its
 *      original strings, deduplicated by (iif, source, group, oifs).
 *      `smcroutectl show pending` lists what's waiting.
 *
 *   2. On a fresh reload (SIGHUP / `smcroutectl reload`) pending_clear()
 *      empties the list at reload_beg() so conf_read() can rebuild it
 *      from the current file.
 *
 *   3. ifevent_nl.c (Linux netlink) calls pending_drain() on every
 *      kernel link/address event.  For each entry whose every named
 *      iface is now present and `IFF_MULTICAST`-capable, drain replays
 *      the directive via conf_mroute()/conf_mgroup() (with conf=NULL,
 *      i.e. the IPC entry point) and drops the entry on success.
 *
 * This substrate is intentionally reusable for future dynamic-routing
 * features — e.g., the IGMP/MLD proxying TODO in doc/TODO.md would
 * enqueue routes here in response to incoming Membership Reports.
 *
 * Copyright (C) 2026  Joachim Wiberg <troglobit@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <errno.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "queue.h"
#include "conf.h"
#include "iface.h"
#include "ipc.h"
#include "log.h"
#include "mroute.h"
#include "pending.h"

enum pending_kind {
	PENDING_MROUTE,
	PENDING_MGROUP,
};

struct pending {
	TAILQ_ENTRY(pending) link;

	enum pending_kind kind;
	char	*iif;
	char	*source;
	char	*group;
	char	*oif[MAX_MC_VIFS];
	int	 num;
};

static TAILQ_HEAD(, pending) pending_list = TAILQ_HEAD_INITIALIZER(pending_list);

static const char *kind_name(enum pending_kind k)
{
	return k == PENDING_MROUTE ? "mroute" : "mgroup";
}

static void pending_free(struct pending *p)
{
	int i;

	free(p->iif);
	free(p->source);
	free(p->group);
	for (i = 0; i < p->num; i++)
		free(p->oif[i]);
	free(p);
}

/* strdup @src into *@dst.  Returns 0 on success, -1 on OOM. */
static int dup_field(char **dst, const char *src)
{
	if (!src) {
		*dst = NULL;
		return 0;
	}
	*dst = strdup(src);
	return *dst ? 0 : -1;
}

/* Bounded snprintf that appends to a buffer, clamping on overflow. */
static void append(char *buf, size_t size, size_t *off, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (*off >= size)
		return;
	va_start(ap, fmt);
	n = vsnprintf(buf + *off, size - *off, fmt, ap);
	va_end(ap);
	if (n <= 0)
		return;
	*off += (size_t)n;
	if (*off >= size)
		*off = size - 1;
}

static int streq(const char *a, const char *b)
{
	if (!a && !b)
		return 1;
	if (!a || !b)
		return 0;
	return !strcmp(a, b);
}

static int same_oifs(struct pending *p, char *const oif[], int num)
{
	int i;

	if (p->num != num)
		return 0;
	for (i = 0; i < num; i++) {
		if (!streq(p->oif[i], oif[i]))
			return 0;
	}
	return 1;
}

static struct pending *find_mroute(const char *iif, const char *source,
				   const char *group, char *const oif[], int num)
{
	struct pending *p;

	TAILQ_FOREACH(p, &pending_list, link) {
		if (p->kind != PENDING_MROUTE)
			continue;
		if (streq(p->iif, iif) && streq(p->source, source) &&
		    streq(p->group, group) && same_oifs(p, oif, num))
			return p;
	}
	return NULL;
}

static struct pending *find_mgroup(const char *iif, const char *source,
				   const char *group)
{
	struct pending *p;

	TAILQ_FOREACH(p, &pending_list, link) {
		if (p->kind != PENDING_MGROUP)
			continue;
		if (streq(p->iif, iif) && streq(p->source, source) &&
		    streq(p->group, group))
			return p;
	}
	return NULL;
}

void pending_init(void)
{
	TAILQ_INIT(&pending_list);
}

void pending_clear(void)
{
	struct pending *p, *tmp;

	TAILQ_FOREACH_SAFE(p, &pending_list, link, tmp) {
		TAILQ_REMOVE(&pending_list, p, link);
		pending_free(p);
	}
}

void pending_exit(void)
{
	pending_clear();
}

int pending_add_mroute(const char *iif, const char *source, const char *group,
		       char *const oif[], int num)
{
	struct pending *p;
	int i;

	if (find_mroute(iif, source, group, oif, num))
		return 0;

	p = calloc(1, sizeof(*p));
	if (!p)
		goto oom;

	p->kind = PENDING_MROUTE;
	p->num  = num;
	if (dup_field(&p->iif, iif) || dup_field(&p->source, source) ||
	    dup_field(&p->group, group))
		goto oom_free;
	for (i = 0; i < num; i++) {
		if (dup_field(&p->oif[i], oif[i]))
			goto oom_free;
	}

	TAILQ_INSERT_TAIL(&pending_list, p, link);
	smclog(LOG_NOTICE, "%s from %s group %s pending: interface not available",
	       kind_name(p->kind), iif, group);
	return 0;

oom_free:
	pending_free(p);
oom:
	smclog(LOG_ERR, "Out of memory in %s()", __func__);
	return -1;
}

int pending_add_mgroup(const char *iif, const char *source, const char *group)
{
	struct pending *p;

	if (find_mgroup(iif, source, group))
		return 0;

	p = calloc(1, sizeof(*p));
	if (!p)
		goto oom;

	p->kind = PENDING_MGROUP;
	if (dup_field(&p->iif, iif) || dup_field(&p->source, source) ||
	    dup_field(&p->group, group))
		goto oom_free;

	TAILQ_INSERT_TAIL(&pending_list, p, link);
	smclog(LOG_NOTICE, "%s from %s group %s pending: interface not available",
	       kind_name(p->kind), iif, group);
	return 0;

oom_free:
	pending_free(p);
oom:
	smclog(LOG_ERR, "Out of memory in %s()", __func__);
	return -1;
}

/* Wait for IFF_MULTICAST so a freshly-added iface mid-bringup does
 * not trigger a transient "not multicast capable" warning on drain. */
static int iface_ready(const char *name)
{
	struct ifmatch state;
	struct iface *iface;

	iface_match_init(&state);
	while ((iface = iface_match_by_name(name, 1, &state))) {
		if ((iface->flags & IFF_MULTICAST) == IFF_MULTICAST)
			return 1;
	}
	return 0;
}

static int all_ifaces_ready(struct pending *p)
{
	int i;

	if (!iface_ready(p->iif))
		return 0;
	for (i = 0; i < p->num; i++) {
		if (!iface_ready(p->oif[i]))
			return 0;
	}
	return 1;
}

void pending_drain(void)
{
	struct pending *p, *tmp;
	int rc;

	TAILQ_FOREACH_SAFE(p, &pending_list, link, tmp) {
		if (!all_ifaces_ready(p))
			continue;

		if (p->kind == PENDING_MROUTE)
			rc = conf_mroute(NULL, 1, p->iif, p->source, p->group,
					 p->oif, p->num);
		else
			rc = conf_mgroup(NULL, 1, p->iif, p->source, p->group);

		if (rc)
			continue;

		smclog(LOG_NOTICE, "Activated pending %s from %s group %s",
		       kind_name(p->kind), p->iif, p->group);
		TAILQ_REMOVE(&pending_list, p, link);
		pending_free(p);
	}
}

static int show_one(int sd, struct pending *p)
{
	char   buf[512];
	size_t len = 0;
	int    i;

	append(buf, sizeof(buf), &len, "%-7s from %s", kind_name(p->kind), p->iif);
	if (p->source)
		append(buf, sizeof(buf), &len, " source %s", p->source);
	append(buf, sizeof(buf), &len, " group %s", p->group);
	if (p->num > 0)
		append(buf, sizeof(buf), &len, " to");
	for (i = 0; i < p->num; i++)
		append(buf, sizeof(buf), &len, " %s", p->oif[i]);
	append(buf, sizeof(buf), &len, "\n");

	return ipc_send(sd, buf, len);
}

static int show_one_json(int sd, struct pending *p, int first)
{
	char buf[512];
	size_t len = 0;
	int i;

	append(buf, sizeof(buf), &len,
	       "%s{\"kind\":\"%s\",\"iif\":\"%s\",\"source\":",
	       first ? "" : ",", kind_name(p->kind), p->iif);
	if (p->source)
		append(buf, sizeof(buf), &len, "\"%s\"", p->source);
	else
		append(buf, sizeof(buf), &len, "null");
	append(buf, sizeof(buf), &len, ",\"group\":\"%s\",\"oifs\":[", p->group);
	for (i = 0; i < p->num; i++)
		append(buf, sizeof(buf), &len, "%s\"%s\"",
		       i == 0 ? "" : ",", p->oif[i]);
	append(buf, sizeof(buf), &len, "]}");

	return ipc_send(sd, buf, len);
}

int pending_show(int sd, enum show_mode mode)
{
	struct pending *p;
	const char *header = "PENDING ROUTES AND GROUPS\n";

	if (mode == SHOW_JSON) {
		int first = 1;

		ipc_send(sd, "{\"pending\":[", 12);
		TAILQ_FOREACH(p, &pending_list, link) {
			if (show_one_json(sd, p, first) < 0)
				return -1;
			first = 0;
		}
		ipc_send(sd, "]}\n", 3);
		return 0;
	}

	if (TAILQ_EMPTY(&pending_list)) {
		header = "No pending routes or groups\n";
		return ipc_send(sd, header, strlen(header));
	}

	if (ipc_send(sd, header, strlen(header)) < 0)
		return -1;

	TAILQ_FOREACH(p, &pending_list, link) {
		if (show_one(sd, p) < 0)
			return -1;
	}

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
