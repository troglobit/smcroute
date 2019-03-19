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

#include "log.h"
#include "conf.h"
#include "ifvc.h"
#include "script.h"
#include "mcgroup.h"

#define MAX_LINE_LEN 512
#define DEBUG(fmt, args...)			\
	smclog(LOG_DEBUG, "%s:%02d: " fmt, conf, lineno, ##args)
#define INFO(fmt, args...)			\
	smclog(LOG_INFO, "%s:%02d: " fmt, conf, lineno, ##args)
#define WARN(fmt, args...) {						\
		smclog(LOG_WARNING, "%s:%02d: " fmt, conf,		\
		       lineno, ##args);					\
		if (conf_vrfy)						\
			return 1;					\
	}

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
	int result;

	if (!ifname || !group) {
		errno = EINVAL;
		return 1;
	}

	if (strchr(group, ':')) {
#if !defined(HAVE_IPV6_MULTICAST_HOST) || !defined(HAVE_IPV6_MULTICAST_ROUTING)
		WARN("Ignored, IPv6 disabled.");
		result = 0;
#else
		struct in6_addr grp;

		if (source)
			WARN("IPv6 is not (yet) supported for Source Specific Multicast.");

		if (inet_pton(AF_INET6, group, &grp) <= 0 || !IN6_IS_ADDR_MULTICAST(&grp)) {
			WARN("Invalid IPv6 multicast group: %s", group);
			return 1;
		}

		result = mcgroup6_join(ifname, grp);
#endif
	} else {
		struct in_addr src;
		struct in_addr grp;
		char *ptr;
		int len = 0;

		memset(&src, 0, sizeof(src));

		if (source && (inet_pton(AF_INET, source, &src) <= 0)) {
			WARN("Invalid IPv4 multicast source: %s", source);
			return 1;
		}

		ptr = strchr(group, '/');
		if (ptr) {
			*ptr++ = 0;
			len = atoi(ptr);

			if (len < 0 || len > 32) {
				WARN("Invalid IPv4 group prefix length (0-32): %d", len);
				return 1;
			}
		}

		if ((inet_pton(AF_INET, group, &grp) <= 0) || !IN_MULTICAST(ntohl(grp.s_addr))) {
			WARN("Invalid IPv4 multicast group: %s", group);
			return 1;
		}

		result = mcgroup4_join(ifname, src, grp, len);
	}

	return result;
}

static int add_mroute(int lineno, char *ifname, char *group, char *source, char *outbound[], int num)
{
	int i, total, ret, vif, result = 0;
	char *ptr;
	struct mroute4 mroute;
	struct iface *iface;
	struct ifmatch state_in, state_out;

	if (!ifname || !group || !outbound || !num) {
		errno = EINVAL;
		return 1;
	}

	if (strchr(group, ':')) {
#if !defined(HAVE_IPV6_MULTICAST_HOST) || !defined(HAVE_IPV6_MULTICAST_ROUTING)
		WARN("Ignored, IPv6 disabled.");
		return 0;
#else
		struct mroute6 mroute;
		int mif;

		iface_match_init(&state_in);
		while ((mif = iface_match_mif_by_name(ifname, &state_in, NULL)) >= 0) {
			memset(&mroute, 0, sizeof(mroute));
			mroute.inbound = mif;

			if (!source || inet_pton(AF_INET6, source, &mroute.source.sin6_addr) <= 0) {
				WARN("Invalid source IPv6 address: %s", source ?: "NONE");
				return 1;
			}

			if (inet_pton(AF_INET6, group, &mroute.group.sin6_addr) <= 0 || !IN6_IS_ADDR_MULTICAST(&mroute.group.sin6_addr)) {
				WARN("Invalid IPv6 multicast group: %s", group);
				return 1;
			}

			total = 0;
			for (i = 0; i < num; i++) {
				iface_match_init(&state_out);
				while ((mif = iface_match_mif_by_name(outbound[i], &state_out, &iface)) >= 0) {
					if (mif == mroute.inbound) {
						/* In case of wildcard match in==out is normal, so don't complain */
						if (!ifname_is_wildcard(ifname) && !ifname_is_wildcard(outbound[i]))
							INFO("Same outbound IPv6 interface (%s) as inbound (%s) may cause routing loops.", outbound[i], ifname);
					}

					/* Use a TTL threshold to indicate the list of outbound interfaces. */
					mroute.ttl[mif] = iface->threshold;
					total++;
				}
				if (!state_out.match_count)
					WARN("Invalid outbound IPv6 interface: %s", outbound[i]);
			}

			if (!total) {
				WARN("No valid outbound interfaces, skipping multicast route.");
				result += 1;
			} else {
				result += mroute6_add(&mroute);
			}
		}

		if (!state_in.match_count) {
			WARN("Invalid inbound IPv6 interface: %s", ifname);
			return 1;
		}
		return result;
#endif
	}

	iface_match_init(&state_in);
	while ((vif = iface_match_vif_by_name(ifname, &state_in, NULL)) >= 0) {
		memset(&mroute, 0, sizeof(mroute));
		mroute.inbound = vif;

		if (!source) {
			mroute.source.s_addr = htonl(INADDR_ANY);
		} else {
			ptr = strchr(source, '/');
			if (ptr) {
				*ptr++ = 0;
				mroute.src_len = atoi(ptr);
				if (mroute.src_len < 0 || mroute.src_len > 32) {
					WARN("Invalid prefix length, %s/%d", source, mroute.src_len);
					return 1;
				}
			}

			if (inet_pton(AF_INET, source, &mroute.source) <= 0) {
				WARN("Invalid source IPv4 address: %s", source);
				return 1;
			}
		}


		ptr = strchr(group, '/');
		if (ptr) {
			*ptr++ = 0;
			mroute.len = atoi(ptr);
			if (mroute.len < 0 || mroute.len > 32) {
				WARN("Invalid prefix length, %s/%d", group, mroute.len);
				return 1;
			}
		}

		ret = inet_pton(AF_INET, group, &mroute.group);
		if (ret <= 0 || !IN_MULTICAST(ntohl(mroute.group.s_addr))) {
			WARN("Invalid IPv4 multicast group: %s", group);
			return 1;
		}

		total = 0;
		for (i = 0; i < num; i++) {
			iface_match_init(&state_out);
			while ((vif = iface_match_vif_by_name(outbound[i], &state_out, &iface)) >= 0) {
				if (vif == mroute.inbound) {
					/* In case of wildcard match in==out is normal, so don't complain */
					if (!ifname_is_wildcard(ifname) && !ifname_is_wildcard(outbound[i]))
						INFO("Same outbound IPv4 interface (%s) as inbound (%s) may cause routing loops.", outbound[i], ifname);
				}

				/* Use a TTL threshold to indicate the list of outbound interfaces. */
				mroute.ttl[vif] = iface->threshold;
				total++;
			}
			if (!state_out.match_count)
				WARN("Invalid outbound IPv4 interface: %s", outbound[i]);
		}

		if (!total) {
			WARN("No valid outbound IPv4 interfaces, skipping multicast route.");
			result += 1;
		} else {
			result += mroute4_add(&mroute);
		}
	}

	if (!state_in.match_count) {
		WARN("Invalid inbound IPv4 interface: %s", ifname);
		return 1;
	}

	return result;
}

/*
 * This function parses the given configuration file according to the
 * below format rules.  Joins multicast groups and creates multicast
 * routes accordingly in the kernel.  Whitespace is ignored.
 *
 * Format:
 *    phyint IFNAME <enable|disable> [threshold <1-255>]
 *    mgroup   from IFNAME                group MCGROUP
 *    ssmgroup from IFNAME source ADDRESS group MCGROUP
 *    mroute   from IFNAME source ADDRESS group MCGROUP to IFNAME [IFNAME ...]
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

		DEBUG(".conf line: '%s'", line);
		while ((token = pop_token(&line))) {
			/* Strip comments. */
			if (match("#", token))
				break;

			if (!op) {
				if (match("mgroup", token)) {
					op = 1;
				} else if (match("mroute", token)) {
					op = 2;
				} else if (match("phyint", token)) {
					op = 3;
					ifname = pop_token(&line);
					if (!ifname)
						op = 0;
				} else if (match("ssmgroup", token)) {
					op = 1; /* Compat */
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

		if (op == 1) {
			rc += join_mgroup(lineno, ifname, source, group);
		} else if (op == 2) {
			rc += add_mroute(lineno, ifname, group, source, dest, num);
		} else if (op == 3) {
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
