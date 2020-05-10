/* Simple .conf file parser for smcroute
 *
 * Copyright (c) 2011-2017  Joachim Nilsson <troglobit@gmail.com>
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
#include "ifvc.h"
#include "script.h"
#include "mcgroup.h"
#include "util.h"

#define MAX_LINE_LEN 512

#define DEBUG(fmt, args...)						\
	smclog(LOG_DEBUG, "%s: L%02d: " fmt, conf, lineno, ##args)
#define INFO(fmt, args...)						\
	smclog(LOG_INFO, "%s: L%02d: " fmt, conf, lineno, ##args)
#define WARN(fmt, args...) {						\
		smclog(LOG_WARNING, "%s: L%02d: " fmt, conf,		\
		       lineno, ##args);					\
		if (conf_vrfy)						\
			return 1;					\
	}

/* Tokens */
#define MGROUP 1
#define MROUTE 2
#define PHYINT 3

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

static int join_mgroup(int lineno, char *ifname, char *source, char *group)
{
	int rc = 0, len = 0;

	if (!ifname || !group) {
		errno = EINVAL;
		return 1;
	}

	if (strchr(group, ':')) {
#if !defined(HAVE_IPV6_MULTICAST_HOST) || !defined(HAVE_IPV6_MULTICAST_ROUTING)
		WARN("Ignoring join %s on %s, IPv6 disabled.", group, ifname);
#else
		struct sockaddr_in6 src, grp;

		memset(&src, 0, sizeof(src));
		memset(&grp, 0, sizeof(grp));

		src.sin6_family = AF_INET6;
		grp.sin6_family = AF_INET6;

		if (source) {
			if ((len = is_range(source)) > 0) {
				WARN("join: Ignore source perfix len: %d", len);
			}

			if (inet_pton(AF_INET6, source, &src.sin6_addr) <= 0) {
				WARN("join: Invalid IPv6 multicast source: %s", group);
				return 1;
			}
		}

		if (group) {
			len = is_range(group);
			if (len < 0 || len > 128) {
				WARN("Invalid IPv6 group prefix length (0-128): %d", len);
				return 1;
			}
			if (!len)
				len = 128;

			if (inet_pton(AF_INET6, group, &grp.sin6_addr) <= 0 ||
					!IN6_IS_ADDR_MULTICAST(&grp.sin6_addr)) {
				WARN("join: Invalid IPv6 multicast group: %s", group);
				return 1;
			}
		}
		else {
			WARN("join: missing IPv6 multicast group");
			return 1;
		}

		/* XXX: Add support for GROUP/LEN to IPv6 */
		rc = mcgroup_action('j', ifname, (inet_addr_t *)&src, (inet_addr_t *)&grp, len);
#endif
	} else {
		struct sockaddr_in src, grp;
		int len = 0;

		memset(&src, 0, sizeof(src));
		memset(&grp, 0, sizeof(grp));

		src.sin_family = AF_INET;
		grp.sin_family = AF_INET;

		if (source) {
			if ((len = is_range(source)) > 0) {
				WARN("join: Ignore source perfix len: %d", len);
			}

			if (inet_pton(AF_INET, source, &src.sin_addr) <= 0) {
				WARN("join: Invalid IPv4 multicast source: %s", source);
				return 1;
			}
		}

		if (group) {
			len = is_range(group);
			if (len < 0 || len > 32) {
				WARN("join: Invalid IPv4 group s prefix length (0-32): %d", len);
				return 1;
			}
			if (!len)
				len = 32;

			if (inet_pton(AF_INET, group, &grp.sin_addr) <= 0 ||
					!IN_MULTICAST(ntohl(grp.sin_addr.s_addr))) {
				WARN("join: Invalid IPv4 multicast group: %s", group);
				return 1;
			}
		}

		rc = mcgroup_action('j', ifname, (inet_addr_t *)&src, (inet_addr_t *)&grp, len);
	}

	return rc;
}

static int add_mroute(int lineno, char *ifname, char *group, char *source, char *outbound[], int num)
{
	struct ifmatch state_in, state_out;
	struct iface *iface;
	int i = 0, len = 0, rc = 0, total;

	if (!ifname || !group || !outbound || !num) {
		errno = EINVAL;
		return 1;
	}

	if (strchr(group, ':')) {
#if !defined(HAVE_IPV6_MULTICAST_HOST) || !defined(HAVE_IPV6_MULTICAST_ROUTING)
		WARN("Ignoring mroute for %s from %s, IPv6 disabled.", group, ifname);
		return 0;
#else
		struct mroute6 mroute;
		int mif;

		iface_match_init(&state_in);
		while ((mif = iface_match_mif_by_name(ifname, &state_in, NULL)) >= 0) {
			memset(&mroute, 0, sizeof(mroute));
			mroute.inbound = mif;

			if (!source) {
				mroute.source.sin6_addr = in6addr_any;
				mroute.src_len = 0;
			} else {
				if (inet_pton(AF_INET6, source, &mroute.source.sin6_addr) <= 0) {
					WARN("mroute: Invalid source IPv6 address: %s", source);
					return 1;
				}

				if ((len = is_range(source)) != 0) {
					WARN("mroute: Ignore source prefix length: %d", len);
				}

				mroute.src_len = 128;
			}

			if (!group) {
				mroute.group.sin6_addr = in6addr_any;
				mroute.len = 0;
			} else {
				if (inet_pton(AF_INET6, group, &mroute.group.sin6_addr) <= 0 ||
						!(IN6_IS_ADDR_MULTICAST(&mroute.group.sin6_addr) ||
						  IN6_IS_ADDR_UNSPECIFIED(&mroute.group.sin6_addr))) {
					WARN("mroute: Invalid IPv6 multicast group: %s", group);
					return 1;
				}

				mroute.len = is_range(group);

				if (mroute.len < 0 || mroute.len > 128)
				{
					WARN("mroute: Invalid IPv6 multicast group prefix length: %d", mroute.len);
					return 1;
				}

				if (mroute.len != 0)
				{
					WARN("mroute: Ignore IPv6 multicast group prefix length: %d", mroute.len);
					mroute.len = 128;
				}
				else
				{
					// Assume missing prefix for specified address as 128
					mroute.len = 128;
				}

				// reset group len to be 0 for in6addr_any group
				if (IN6_IS_ADDR_UNSPECIFIED(&mroute.group.sin6_addr)) {
					mroute.len = 0;
				}
			}

			total = 0;
			for (i = 0; i < num; i++) {
				iface_match_init(&state_out);
				while ((mif = iface_match_mif_by_name(outbound[i], &state_out, &iface)) >= 0) {
					if (mif == mroute.inbound) {
						/* In case of wildcard match in==out is normal, so don't complain */
						if (!ifname_is_wildcard(ifname) && !ifname_is_wildcard(outbound[i]))
							INFO("mroute: Same outbound IPv6 interface (%s) as inbound (%s) may cause routing loops.", outbound[i], ifname);
					}

					/* Use a TTL threshold to indicate the list of outbound interfaces. */
					mroute.ttl[mif] = iface->threshold;
					total++;
				}
				if (!state_out.match_count)
					WARN("mroute: Invalid outbound IPv6 interface: %s", outbound[i]);
			}

			if (!total) {
				WARN("mroute: No valid outbound interfaces, skipping multicast route.");
				rc += 1;
			} else {
				rc += mroute6_add(&mroute);
			}
		}

		if (!state_in.match_count) {
			WARN("mroute: Invalid inbound IPv6 interface: %s", ifname);
			return 1;
		}

		return rc;
#endif
	} else {
		struct mroute4 mroute;
		int vif;

		iface_match_init(&state_in);
		while ((vif = iface_match_vif_by_name(ifname, &state_in, NULL)) >= 0) {
			memset(&mroute, 0, sizeof(mroute));
			mroute.inbound = vif;

			if (!source) {
				mroute.source.s_addr = htonl(INADDR_ANY);
				mroute.src_len = 0;
			} else {
				mroute.src_len = is_range(source);
				if (mroute.src_len < 0 || mroute.src_len > 32) {
					WARN("mroute: invalid prefix length: %d", mroute.src_len);
					return 1;
				}

				if (inet_pton(AF_INET, source, &mroute.source) <= 0) {
					WARN("mroute: Invalid source IPv4 address: %s", source);
					return 1;
				}
			}

			if (!group) {
				WARN("mroute: Invalid IPv4 multicast group: %s", group);
				return 1;
			} else {
				mroute.len = is_range(group);

				if (mroute.len < 0 || mroute.len > 32) {
					WARN("mroute: Invalid IPv4 multicast group prefix length, %d", mroute.len);
					return 1;
				}

				if (inet_pton(AF_INET, group, &mroute.group) <= 0 ||
						!IN_MULTICAST(ntohl(mroute.group.s_addr))) {
					WARN("mroute: Invalid IPv4 multicast group: %s", group);
					return 1;
				}
			}

			total = 0;
			for (i = 0; i < num; i++) {
				iface_match_init(&state_out);
				while ((vif = iface_match_vif_by_name(outbound[i], &state_out, &iface)) >= 0) {
					if (vif == mroute.inbound) {
						/* In case of wildcard match in==out is normal, so don't complain */
						if (!ifname_is_wildcard(ifname) && !ifname_is_wildcard(outbound[i]))
							INFO("mroute: Same outbound IPv4 interface (%s) as inbound (%s) may cause routing loops.", outbound[i], ifname);
					}

					/* Use a TTL threshold to indicate the list of outbound interfaces. */
					mroute.ttl[vif] = iface->threshold;
					total++;
				}
				if (!state_out.match_count)
					WARN("mroute: Invalid outbound IPv4 interface: %s", outbound[i]);
			}

			if (!total) {
				WARN("mroute: No valid outbound IPv4 interfaces, skipping multicast route.");
				rc += 1;
			} else {
				rc += mroute4_add(&mroute);
			}
		}

		if (!state_in.match_count) {
			WARN("mroute: Invalid inbound IPv4 interface: %s", ifname);
			return 1;
		}
	}

	return rc;
}

static char *chomp(char *str)
{
	char *p;

	if (!str || strlen(str) < 1) {
		errno = EINVAL;
		return NULL;
	}

	p = str + strlen(str) - 1;
        while (*p == '\n')
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
	FILE *fp;
	char *linebuf, *line;
	int lineno = 1;
	int rc = 0;

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

		DEBUG("'%s'", line);
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
					int num = atoi(token);

					if (num >= 1 || num <= 255)
						threshold = num;
				}
			}
		}

		if (op == MGROUP) {
			rc += join_mgroup(lineno, ifname, source, group);
		} else if (op == MROUTE) {
			rc += add_mroute(lineno, ifname, group, source, dest, num);
		} else if (op == PHYINT) {
			if (enable)
				rc += mroute_add_vif(ifname, mrdisc, threshold);
			else
				rc += mroute_del_vif(ifname);
		}

		lineno++;
	}

	free(linebuf);
	fclose(fp);

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
