/* Simple .conf file parser for smcroute
 *
 * Copyright (c) 2011-2013  Joachim Nilsson <troglobit@gmail.com>
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef UNITTEST
#include "mclab.h"
#endif

#define MAX_LINE_LEN 512
char *exec_reload  = NULL;
char *exec_install = NULL;

int run_callback(char *cmd, mroute4_t *mroute)
{
	int status;
	char source[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];

	if (mroute) {
		inet_ntop(AF_INET, &mroute->sender.s_addr, source, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &mroute->group.s_addr, group, INET_ADDRSTRLEN);

		setenv("source", source, 1);
		setenv("group", group, 1);
	}

	status = system(exec_install);
	if (WIFEXITED(status))
		smclog(LOG_DEBUG, 0, "Callback '%s' exited normally with status %d",
		       exec_install, WEXITSTATUS(status));
	else
		smclog(LOG_DEBUG, 0, "Callback '%s' did not exit normally!",
		       exec_install);

	if (mroute) {
		unsetenv("source");
		unsetenv("group");
	}

	return WIFEXITED(status);
}

static char *pop_token(char **line)
{
	char *end, *token;

	if (!line)
		return NULL;

	token = *line;
	if (!token)
		return NULL;

	/* Find start of token, skip whitespace. */
	while (*token && isspace(*token))
		token++;

	/* Find end of token. */
	end = token;
	while (*end && !isspace(*end))
		end++;
	if (*end == 0 || end == token) {
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

static int join_mgroup (int lineno, char *ifname, char *group)
{
	int result;

	if (!ifname || !group) {
		errno = EINVAL;
		return 1;
	}

	if (strchr(group, ':')) {
#if !defined(HAVE_IPV6_MULTICAST_HOST) || !defined(HAVE_IPV6_MULTICAST_ROUTING)
		smclog(LOG_WARNING, 0, "%02: Ignored, IPv6 disabled.", lineno);
		result = 0;
#else
		struct in6_addr grp;

		if (inet_pton(AF_INET6, group, &grp) <= 0 || !IN6_IS_ADDR_MULTICAST(&grp)) {
			smclog(LOG_WARNING, 0, "%02d: Invalid IPv6 multicast group: %s", lineno, group);
			return 1;
		}

		result = mcgroup6_join(ifname, grp);
#endif
	} else {
		struct in_addr grp;

		if ((inet_pton(AF_INET, group, &grp) <= 0) || !IN_MULTICAST(ntohl(grp.s_addr))) {
			smclog(LOG_WARNING, 0, "%02d: Invalid IPv4 multicast group: %s", lineno, group);
			return 1;
		}

		result = mcgroup4_join(ifname, grp);
	}

	return result;
}

static int add_mroute (int lineno, char *ifname, char *group, char *source, char *outbound[], int num)
{
	int i, total, result;

	if (!ifname || !group || !outbound || !num) {
		errno = EINVAL;
		return 1;
	}

	if (strchr(group, ':')) {
#if !defined(HAVE_IPV6_MULTICAST_HOST) || !defined(HAVE_IPV6_MULTICAST_ROUTING)
		smclog(LOG_WARNING, 0, "%02: Ignored, IPv6 disabled.", lineno);
		result = 0;
#else
		mroute6_t mroute;

		memset(&mroute, 0, sizeof(mroute));
		mroute.inbound = iface_get_mif_by_name(ifname);
		if (mroute.inbound < 0) {
			smclog(LOG_WARNING, 0, "%02d: Invalid inbound IPv6 interface: %s", lineno, ifname);
			return 1;
		}
		if (!source || inet_pton(AF_INET6, source, &mroute.sender.sin6_addr) <= 0) {
			smclog(LOG_WARNING, 0, "%02d: Invalid source IPv6 address: %s", lineno, source ?: "NONE");
			return 1;
		}

		if (inet_pton(AF_INET6, group, &mroute.group.sin6_addr) <= 0 || !IN6_IS_ADDR_MULTICAST(&mroute.group.sin6_addr)) {
			smclog(LOG_WARNING, 0, "%02d: Invalid IPv6 multicast group: %s", lineno, group);
			return 1;
		}

		total = num;
		for (i = 0; i < num; i++) {
			int mif = iface_get_mif_by_name(outbound[i]);

			if (mif < 0) {
				total--;
				smclog(LOG_WARNING, 0, "%02d: Invalid outbound IPv6 interface: %s", lineno, outbound[i]);
				continue; /* Try next, if any. */
			}

			if (mif == mroute.inbound)
				smclog(LOG_WARNING, 0, "%02d: Same outbound IPv6 interface (%s) as inbound (%s)?", lineno, outbound[i], ifname);

			mroute.ttl[mif] = 1;	/* Use a TTL threshold to indicate the list of outbound interfaces. */
		}

		if (!total) {
			smclog(LOG_WARNING, 0, "%02d: No valid outbound interfaces, skipping multicast route.", lineno);
			result = 1;
		} else {
			result = mroute6_add(&mroute);
		}
#endif
	} else {
		struct mroute4 mroute;

		memset(&mroute, 0, sizeof(mroute));
		mroute.inbound = iface_get_vif_by_name(ifname);
		if (mroute.inbound < 0) {
			smclog(LOG_WARNING, 0, "%02d: Invalid inbound IPv4 interface: %s", lineno, ifname);
			return 1;
		}

		if (!source) {
			mroute.sender.s_addr = INADDR_ANY;
		} else if (inet_pton(AF_INET, source, &mroute.sender) <= 0) {
			smclog(LOG_WARNING, 0, "%02d: Invalid source IPv4 address: %s", lineno, source);
			return 1;
		}

		if ((inet_pton(AF_INET, group, &mroute.group) <= 0) || !IN_MULTICAST(ntohl(mroute.group.s_addr))) {
			smclog(LOG_WARNING, 0, "%02d: Invalid IPv4 multicast group: %s", lineno, group);
			return 1;
		}

		total = num;
		for (i = 0; i < num; i++) {
			int vif = iface_get_vif_by_name(outbound[i]);

			if (vif < 0) {
				total--;
				smclog(LOG_WARNING, 0, "%02d: Invalid outbound IPv4 interface: %s", lineno, outbound[i]);
				continue; /* Try next, if any. */
			}

			if (vif == mroute.inbound)
				smclog(LOG_WARNING, 0, "%02d: Same outbound IPv4 interface (%s) as inbound (%s)?", lineno, outbound[i], ifname);

			mroute.ttl[vif] = 1;	/* Use a TTL threshold to indicate the list of outbound interfaces. */
		}

		if (!total) {
			smclog(LOG_WARNING, 0, "%02d: No valid outbound IPv4 interfaces, skipping multicast route.", lineno);
			result = 1;
		} else {
			result = mroute4_add(&mroute);
		}
	}

	return result;
}

static void set_exec(char *cmd)
{
	int type = 0;
	char *cond = strstr(cmd, "on ");

	if (cond) {
		*cond = 0;
		cond += 3;

		if (!strncmp(cond, "reload", 6))
			type = 1;
		if (!strncmp(cond, "install", 7))
			type = 2;
	}

	if (type == 1) {
		if (exec_reload)
			free(exec_reload);
		exec_reload  = strdup(cmd);
	} else if (type == 2) {
		if (exec_install)
			free(exec_install);
		exec_install = strdup(cmd);
	} else {
		if (exec_reload)
			free(exec_reload);
		if (exec_install)
			free(exec_install);
		exec_reload  = strdup(cmd);
		exec_install = strdup(cmd);
	}
}

/**
 * parse_conf_file - Parse smcroute.conf
 * @file: File name to parse
 *
 * This function parses the given @file according to the below format rules.
 * Joins multicast groups and creates multicast routes accordingly in the
 * kernel.
 *
 * Format:
 *    exec /path/to/script [optional args] [on <reload | install>]
 *    mgroup from IFNAME group MCGROUP
 *    mroute from IFNAME source ADDRESS group MCGROUP to IFNAME [IFNAME ...]
 */
int parse_conf_file(const char *file)
{
	int lineno = 1;
	char *linebuf, *line;
	FILE *fp = fopen(file, "r");

	if (!fp)
		return 1;

	linebuf = malloc(MAX_LINE_LEN * sizeof(char));
	if (!linebuf) {
		int tmp = errno;

		fclose(fp);
		errno = tmp;

		return 1;
	}

	while ((line = fgets(linebuf, MAX_LINE_LEN, fp))) {
		char *token;
		char *ifname = NULL;
		char *source = NULL;
		char *group  = NULL;
		int   op = 0, num = 0;
		char *dest[32];

		while ((token = pop_token(&line))) {
			/* Strip comments. */
			if (match ("#", token)) {
#ifdef UNITTEST
				printf("%02d: COMMENT: %s", lineno, line);
#endif
				break;
			}

			if (!op) {
				if (match ("mgroup", token)) {
					op = 1;
				} else if (match ("mroute", token)) {
					op = 2;
				} else if (match ("exec", token)) {
					set_exec(line);
					line = NULL;
					continue;
				} else {
#ifdef UNITTEST
					printf("%02d: Unknown command: %s", lineno, line);
#else
					smclog(LOG_WARNING, 0, "%02d: Unknown command %s, skipping.", lineno, token);
#endif
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
			}
		}

#ifdef UNITTEST
		if (op == 1) {
			printf("%02d: Found: %s %s\n", lineno, ifname, group);
		} else if (op == 2) {
			int i;

			printf("%02d: Found: %s %s %s ", lineno, ifname, source, group);
			for (i = 0; i < num; i++)
				printf("%s ", dest[i]);
			printf("\n");
		} else {
			printf("%02d: DUMP: %s\n", lineno, linebuf);
		}
#else
		if (op == 1)
			join_mgroup(lineno, ifname, group);
		else if (op == 2)
			add_mroute(lineno, ifname, group, source, dest, num);
#endif	/* UNITTEST */

		lineno++;
	}

	free(linebuf);
	fclose(fp);

	if (exec_reload)
		run_callback(exec_reload, NULL);

	return 0;
}

void free_conf(void)
{
	if (exec_reload) {
		free(exec_reload);
		exec_reload = NULL;
	}
	if (exec_install) {
		free(exec_install);
		exec_install = NULL;
	}
}

#ifdef UNITTEST
int main (int argc, char *argv[])
{
	if (argc < 2) {
		printf("Missing file argument.\n");
		return 1;
	}

	return parse_conf_file(argv[1]);
}
#endif	/* UNITTEST */

/**
 * Local Variables:
 *  compile-command: "gcc -g -o unittest -DUNITTEST parse-conf.c && ./unittest ../smcroute.conf"
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
