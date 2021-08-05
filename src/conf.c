/* Simple .conf file parser for smcroute
 *
 * Copyright (c) 2011-2020 Joachim Wiberg <troglobit@gmail.com>
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

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "log.h"
#include "conf.h"
#include "iface.h"
#include "script.h"
#include "mcgroup.h"
#include "util.h"

#define MAX_LINE_LEN 512

#define DEBUG(fmt, args...) {						    \
	if (lineno)							    \
		smclog(LOG_DEBUG, "%s:%02d: " fmt, conf, lineno, ##args);   \
	else								    \
		smclog(LOG_DEBUG, "ipc: " fmt, ##args);			    \
	}
#define INFO(fmt, args...) {						    \
	if (lineno)							    \
		smclog(LOG_INFO, "%s:%02d: " fmt, conf, lineno, ##args);    \
	else								    \
		smclog(LOG_INFO, "ipc: " fmt, ##args);			    \
	}

#define WARN(fmt, args...) {						    \
	if (lineno)							    \
		smclog(LOG_WARNING, "%s:%02d: " fmt, conf, lineno, ##args); \
	else								    \
		smclog(LOG_WARNING, "ipc: " fmt, ##args);		    \
	if (conf_vrfy)							    \
		rc++;							    \
	}

/* Tokens */
#define MGROUP 1
#define MROUTE 2
#define PHYINT 3

static int lineno = 0;
static const char *conf = NULL;

static char *pop_token(char **line)
{
	char *end, *token;

	if (!line)
		return NULL;

	token = *line;
	if (!token)
		return NULL;

	/* Find start of token, skip whitespace. */
	while (*token && isspace((int)*token))
		token++;

	/* Find end of token. */
	end = token;
	while (*end && !isspace((int)*end))
		end++;
	if (end == token) {
		*line = NULL;
		return NULL;
	}

	*end = 0;		/* Terminate token. */
	*line = end + 1;

	return token;
}

static int match(char *keyword, char *token)
{
	size_t len;

	if (!keyword || !token)
		return 0;

	len = strlen(keyword);
	return !strncmp(keyword, token, len);
}

int conf_mgroup(int cmd, char *ifname, char *source, char *group)
{
	inet_addr_t src = { 0 }, grp = { 0 };
	int grp_len = 0;
	int len_max;
	int rc = 0;

	if (!ifname || !group) {
		errno = EINVAL;
		return 1;
	}

	grp_len = is_range(group);
	if (inet_str2addr(group, &grp) || !is_multicast(&grp)) {
		WARN("join: Invalid multicast group: %s", group);
		goto done;
	}

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (grp.ss_family == AF_INET6)
		len_max = 128;
	else
#endif
	len_max = 32;
	if (grp_len < 0 || grp_len > len_max) {
		WARN("join: Invalid group prefix length (0-%d): %d", len_max, grp_len);
		goto done;
	}
	if (!grp_len)
		grp_len = len_max;

	if (source) {
		int src_len = is_range(source);

		if (src_len > 0)
			WARN("join: ignoring source prefix len: %d", src_len);

		if (inet_str2addr(source, &src)) {
			WARN("join: Invalid multicast source: %s", source);
			goto done;
		}
	} else
		inet_anyaddr(grp.ss_family, &src);


	rc += mcgroup_action(cmd, ifname, &src, &grp, grp_len);
done:
	return rc;
}

int conf_mroute(int cmd, char *ifname, char *source, char *group, char *outbound[], int num)
{
	struct ifmatch state_in, state_out;
	struct mroute mroute = { 0 };
	struct iface *iface;
	int len_max;
	int rc = 0;
	int vif;

	if (!ifname || !group) {
		errno = EINVAL;
		return 1;
	}

	mroute.len = is_range(group);
	if (inet_str2addr(group, &mroute.group) || !is_multicast(&mroute.group)) {
		WARN("mroute: Invalid multicast group: %s", group);
		goto done;
	}

#ifdef HAVE_IPV6_MULTICAST_HOST
	if (mroute.group.ss_family == AF_INET6)
		len_max = 128;
	else
#endif
		len_max = 32;
	if (mroute.len < 0 || mroute.len > len_max) {
		WARN("mroute: Invalid multicast group prefix length, %d", mroute.len);
		goto done;
	}

	if (source) {
		mroute.src_len = is_range(source);
		if (mroute.src_len < 0 || mroute.src_len > len_max) {
			WARN("mroute: invalid prefix length: %d", mroute.src_len);
			goto done;
		}

		if (inet_str2addr(source, &mroute.source)) {
			WARN("mroute: Invalid source address: %s", source);
			goto done;
		}
	} else {
		inet_anyaddr(mroute.group.ss_family, &mroute.source);
		mroute.src_len = 0;
	}

	iface_match_init(&state_in);
	DEBUG("mroute: checking for input iface %s ...", ifname);
	while (iface_match_vif_by_name(ifname, &state_in, &iface) != NO_VIF) {
		char src[INET_ADDRSTR_LEN], grp[INET_ADDRSTR_LEN];

#ifdef HAVE_IPV6_MULTICAST_HOST
		if (mroute.group.ss_family == AF_INET6)
			vif = iface->mif;
		else
#endif
		vif = iface->vif;
		DEBUG("mroute: input iface %s has vif %d", ifname, vif);
		mroute.inbound = vif;

		if (cmd) {
			int i, total = 0;

			for (i = 0; i < num; i++) {
				iface_match_init(&state_out);

				DEBUG("mroute: checking for %s ...", outbound[i]);
				while (iface_match_vif_by_name(outbound[i], &state_out, &iface) != NO_VIF) {
#ifdef HAVE_IPV6_MULTICAST_HOST
					if (mroute.group.ss_family == AF_INET6)
						vif = iface->mif;
					else
#endif
					vif = iface->vif;
					if (vif == mroute.inbound) {
						/* In case of wildcard match in==out is normal, so don't complain */
						if (!ifname_is_wildcard(ifname) && !ifname_is_wildcard(outbound[i]))
							INFO("mroute: Same outbound interface (%s) as inbound (%s) may cause routing loops.",
							     outbound[i], iface->name);
					}

					/* Use configured TTL threshold for the output phyint */
					mroute.ttl[vif] = iface->threshold;
					total++;
				}
				if (!state_out.match_count)
					WARN("mroute: Invalid outbound interface, skipping %s", outbound[i]);
			}

			if (!total) {
				WARN("mroute: no outbound interfaces, cannot add multicast route.");
				rc += 1;
			} else {
				smclog(LOG_DEBUG, "mroute: adding route from %s (%s/%u,%s/%u)", iface->name,
				       inet_addr2str(&mroute.source, src, sizeof(src)), mroute.src_len,
				       inet_addr2str(&mroute.group, grp, sizeof(grp)), mroute.len);
#ifdef HAVE_IPV6_MULTICAST_HOST
				if (mroute.group.ss_family == AF_INET6)
					rc += mroute6_add(&mroute);
				else
#endif
				rc += mroute4_add(&mroute);
			}
		} else {
			smclog(LOG_DEBUG, "mroute: deleting route froum %s (%s/%u,%s/%u)", iface->name,
			       inet_addr2str(&mroute.source, src, sizeof(src)), mroute.src_len,
			       inet_addr2str(&mroute.group, grp, sizeof(grp)), mroute.len);
#ifdef HAVE_IPV6_MULTICAST_HOST
			if (mroute.group.ss_family == AF_INET6)
				rc += mroute6_del(&mroute);
			else
#endif
			rc += mroute4_del(&mroute);
		}
	}

	if (!state_in.match_count) {
		WARN("mroute: invalid inbound interface: %s", ifname);
		rc++;
	}

done:
	return rc;
}

static int conf_phyint(int enable, char *ifname, int mrdisc, int threshold)
{
	if (enable)
		return mroute_add_vif(ifname, mrdisc, threshold);

	return mroute_del_vif(ifname);
}

static char *chomp(char *str)
{
	char *p;

	if (!str || strlen(str) < 1) {
		errno = EINVAL;
		return NULL;
	}

	p = str + strlen(str) - 1;
        while (p >= str && *p == '\n')
		*p-- = 0;

	return str;
}

/*
 * This function parses the given configuration file according to the
 * below format rules.  Joins multicast groups and creates multicast
 * routes accordingly in the kernel.  Whitespace is ignored.
 *
 * Format:
 *    phyint IFNAME <enable|disable> [threshold <1-255>]
 *    mgroup   from IFNAME [source ADDRESS] group MCGROUP
 *    mroute   from IFNAME source ADDRESS   group MCGROUP to IFNAME [IFNAME ...]
 */
static int conf_parse(const char *file, int do_vifs)
{
	char *linebuf, *line;
	int rc = 0;
	FILE *fp;

	fp = fopen(file, "r");
	if (!fp)
		return 1;

	linebuf = malloc(MAX_LINE_LEN * sizeof(char));
	if (!linebuf) {
		int tmp = errno;

		fclose(fp);
		errno = tmp;

		return 1;
	}

	conf = file;
	lineno = 1;
	while ((line = fgets(linebuf, MAX_LINE_LEN, fp))) {
		int   op = 0, num = 0, enable = do_vifs;
		int   mrdisc = 0, threshold = DEFAULT_THRESHOLD;
		char *token;
		char *ifname = NULL;
		char *source = NULL;
		char *group  = NULL;
		char *dest[32];

		/* Strip any line end character(s) */
		chomp(line);

		DEBUG("%s", line);
		while ((token = pop_token(&line))) {
			/* Strip comments. */
			if (match("#", token))
				break;

			if (!op) {
				if (match("mgroup", token)) {
					op = MGROUP;
				} else if (match("mroute", token)) {
					op = MROUTE;
				} else if (match("phyint", token)) {
					op = PHYINT;
					ifname = pop_token(&line);
					if (!ifname)
						op = 0;
				} else if (match("ssmgroup", token)) {
					op = MGROUP; /* Compat */
				} else {
					WARN("Unknown command %s, skipping.", token);
					continue;
				}
			}

			if (match("from", token)) {
				ifname = pop_token(&line);
			} else if (match("source", token)) {
				source = pop_token(&line);
			} else if (match("group", token)) {
				group = pop_token(&line);
			} else if (match("to", token)) {
				while ((dest[num] = pop_token(&line)))
					num++;
			} else if (match("enable", token)) {
				enable = 1;
			} else if (match("disable", token)) {
				enable = 0;
			} else if (match("mrdisc", token)) {
				mrdisc = 1;
			} else if (match("ttl-threshold", token)) {
				token = pop_token(&line);
				if (token) {
					int ttl = atoi(token);

					if (ttl >= 1 && ttl <= 255)
						threshold = ttl;
				}
			}
		}

		if (ifname && !iface_exist(ifname)) {
			WARN("Interface %s matches no valid system interfaces, skipping.", ifname);
			continue;
		}

		switch (op) {
		case MGROUP:
			rc += conf_mgroup(1, ifname, source, group);
			break;

		case MROUTE:
			rc += conf_mroute(1, ifname, source, group, dest, num);
			break;

		case PHYINT:
			rc += conf_phyint(enable, ifname, mrdisc, threshold);
			break;

		default:
			WARN("Unknown token %d", op);
			break;
		}

		lineno++;
	}

	free(linebuf);
	fclose(fp);
	lineno = 0;

	return rc;
}

/* Parse .conf file and setup routes */
int conf_read(char *file, int do_vifs)
{
	int rc;

	if (access(file, R_OK)) {
		if (errno == ENOENT)
			smclog(LOG_NOTICE, "Configuration file %s does not exist", file);
		else
			smclog(LOG_WARNING, "Unexpected error when accessing %s: %s", file, strerror(errno));

		if (!conf_vrfy)
			smclog(LOG_NOTICE, "Continuing anyway, waiting for client to connect.");

		return 1;
	}

	rc = conf_parse(file, do_vifs);
	if (rc)
		smclog(LOG_WARNING, "Failed reading %s: %s.", file, errno ? strerror(errno): "parse error");
	else
		script_exec(NULL);

	return rc;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
