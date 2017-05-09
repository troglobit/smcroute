/* Client for smcrouted, not needed if only using smcroute.conf
 *
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

#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "msg.h"
#include "util.h"

struct arg {
	char *name;
	int   min_args;		/* 0: command takes no arguments */
	int   val;
	char *help;
	char *example;		/* optional */
	int   has_detail;
} args[] = {
	{ NULL,      0, 'd', "Detailed output in show command", NULL, 0 },
	{ NULL,      0, 't', "Skip table heading in show command", NULL, 0 },
	{ "help",    0, 'h', "Show help text", NULL, 0 },
	{ "version", 0, 'v', "Show program version", NULL, 0 },
	{ "flush" ,  0, 'F', "Flush all dynamically set (*,G) multicast routes", NULL, 0 },
	{ "kill",    0, 'k', "Kill running daemon", NULL, 0 },
	{ "restart", 0, 'H', "Tell daemon to restart and reload its .conf file, like SIGHUP", NULL, 0 },
	{ "show",    0, 's', "Show passive (*,G) and active routes, as well as joined groups", NULL, 1 },
	{ "add",     3, 'a', "Add a multicast route",    "eth0 192.168.2.42 225.1.2.3 eth1 eth2", 0 },
	{ "remove",  3, 'r', "Remove a multicast route", "eth0 192.168.2.42 225.1.2.3", 0 },
	{ "join",    2, 'j', "Join multicast group on an interface", "eth0 225.1.2.3", 0 },
	{ "leave",   2, 'l', "Leave joined multicast group",         "eth0 225.1.2.3", 0 },
	{ NULL, 0, 0, NULL, NULL, 0 }
};

static int heading = 1;
static char *prognm = PACKAGE_NAME;


/*
 * Build IPC message to send to the daemon using @cmd and @count
 * number of arguments from @argv.
 */
static struct ipc_msg *msg_create(uint16_t cmd, char *argv[], size_t count)
{
	char *ptr;
	size_t i, len = 0, sz;
	struct ipc_msg *msg;

	for (i = 0; i < count; i++)
		len += strlen(argv[i]) + 1;

	sz = sizeof(struct ipc_msg) + len + 1;
	if (sz > MX_CMDPKT_SZ) {
		errno = EMSGSIZE;
		return NULL;
	}

	msg = calloc(1, sz);
	if (!msg)
		return NULL;

	msg->len   = sz;
	msg->cmd   = cmd;
	msg->count = count;

	ptr = (char *)msg->argv;
	for (i = 0; i < count; i++) {
		len = strlen(argv[i]) + 1;
		ptr = memcpy(ptr, argv[i], len) + len;
	}
	*ptr = '\0';	/* '\0' behind last string */

	return msg;
}

static void table_heading(char *argv[], size_t count, int detail)
{
	const char *g = "GROUP (S,G)", *i = "INBOUND", *pad = "";
	const char *r = "ROUTE (S,G)", *o = "OUTBOUND", *p = "PACKETS", *b = "BYTES";

	if (!heading)
		return;

	if (count && argv[0][0] == 'g')
		printf("\e[7m%-34s %-16s %27s\e[0m\n", g, i, pad);
	else if (detail)
		printf("\e[7m%-34s %-16s %7s %8s  %-9s\e[0m\n", r, i, p, b, o);
	else
		printf("\e[7m%-34s %-16s %-27s\e[0m\n", r, i, o);
}

/*
 * Connects to the IPC socket of the server
 */
static int ipc_connect(void)
{
	int sd;
	struct sockaddr_un sa;
	socklen_t len;

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd < 0)
		return -1;

#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sa.sun_len = 0;	/* <- correct length is set by the OS */
#endif
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, SOCKET_PATH);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(SOCKET_PATH);
	if (connect(sd, (struct sockaddr *)&sa, len) < 0) {
		int err = errno;

		close(sd);
		errno = err;

		return -1;
	}

	return sd;
}

static int ipc_command(uint16_t cmd, char *argv[], size_t count)
{
	int sd;
	int result = 0;
	int retry_count = 30;
	ssize_t len;
	struct ipc_msg *msg;
	char buf[MX_CMDPKT_SZ + 1];

	msg = msg_create(cmd, argv, count);
	if (!msg) {
		warn("Failed constructing IPC command");
		return 1;
	}

	while ((sd = ipc_connect()) < 0) {
		switch (errno) {
		case EACCES:
			warnx("Need root privileges to connect to daemon");
			break;

		case ENOENT:
		case ECONNREFUSED:
			if (--retry_count) {
				usleep(100000);
				continue;
			}

			warnx("Daemon not running");
			break;

		default:
			warn("Failed connecting to daemon");
			break;
		}

		free(msg);
		return 1;
	}

	/* Send command */
	if (write(sd, msg, msg->len) != (ssize_t)msg->len) {
	error:
		warn("Communication with daemon failed");
		close(sd);
		free(msg);

		return 1;
	}

	/* Wait here for reply */
	len = read(sd, buf, sizeof(buf) - 1);
	if (len < 0)
		goto error;

	if (len != 1 || *buf != '\0') {
		int detail = 0;

		/* Make sure buffer is NULL terminated */
		buf[len] = 0;

		switch (cmd) {
		case 'S':
			detail = 1;
		case 's':
			table_heading(argv, count, detail);
			do {
				fputs(buf, stdout);
				len = read(sd, buf, sizeof(buf) - 1);
				if (len >= 0)
					buf[len] = 0;
			} while (len > 0);
			break;

		default:
			warnx("%s", buf);
			result = 1;
			break;
		}
	}

	close(sd);
	free(msg);

	return result;
}

static int verify_cmd(int cmd, int detail)
{
	int i;

	if (!detail)
		return cmd;

	for (i = 0; args[i].val; i++) {
		if (args[i].val != cmd)
			continue;

		if (!args[i].has_detail)
			return 0;

		return cmd - 0x20;
	}

	return 0;
}

static int usage(int code)
{
	int i;

	printf("Usage:\n  %s CMD [ARGS]\n\n", prognm);

	printf("Options:\n");
	for (i = 0; args[i].val; i++) {
		if (!args[i].help)
			continue;

		if (args[i].name)
			continue;

		printf("  -%c            %s\n", args[i].val, args[i].help);
	}

	printf("\nCommands:\n");
	for (i = 0; args[i].val; i++) {
		if (!args[i].help)
			continue;

		if (!args[i].name)
			continue;

		printf("  %-7s %s  %s\n", args[i].name,
		       args[i].min_args ? "ARGS" : "    ", args[i].help);
	}

	printf("\nArguments:\n"
	       "         <----------- INBOUND ------------>  <--- OUTBOUND ---->\n"
	       "  add    IFNAME [SOURCE-IP] MULTICAST-GROUP  IFNAME [IFNAME ...]\n"
	       "  remove IFNAME [SOURCE-IP] MULTICAST-GROUP\n"
	       "\n"
	       "  join   IFNAME [SOURCE-IP] MULTICAST-GROUP\n"
	       "  leave  IFNAME [SOURCE-IP] MULTICAST-GROUP\n"
	       "\n"
	       "  show   [groups|routes]\n"
	       "\n"
	       "Bug report address: %s\n"
	       "Project homepage:   %s\n\n", PACKAGE_BUGREPORT, PACKAGE_URL);

	return code;
}

static char *progname(const char *arg0)
{
	char *nm;

	nm = strrchr(arg0, '/');
	if (nm)
		nm++;
	else
		nm = (char *)arg0;

	return nm;
}

int main(int argc, char *argv[])
{
	int help = 0, detail = 0;
	int i, pos = 1;
	uint16_t cmd = 0;

	prognm = progname(argv[0]);
	if (argc < 2)
		return usage(1);

	while (pos < argc && !cmd) {
		char *arg = argv[pos];

		for (i = 0; args[i].val; i++) {
			int       c = args[i].val;
			char    *nm = args[i].name;
			size_t  len;

			if (nm)
				len = MIN(MIN(strlen(nm), strlen(arg)), 2);
			else
				len = strlen(arg);

			while (*arg == '-') {
				arg++;
				len--;
			}

			if (len <= 0)
				break;

			if (nm) {
				if (strncmp(arg, nm, len))
					continue;
			} else {
				if (arg[0] != c)
					continue;
			}

			switch (c) {
			case 'd':	/* detail */
				detail++;
				pos++;
				break;

			case 'h':	/* help */
				help++;
				break;

			case 't':	/* no table heading */
				heading = 0;
				pos++;
				break;

			case 'v':	/* version */
				fprintf(stderr, "%s v%s\n", PACKAGE_NAME, PACKAGE_VERSION);
				return 0;

			default:
				if (argc - ++pos < args[i].min_args) {
					warnx("Not enough arguments to command %s", nm);
					cmd = c;
					goto help;
				}
				cmd = c;
				break;
			}
			break;
		}
	}

	if (help) {
		if (!cmd)
			return usage(0);
	help:
		while (!args[i].help)
			i--;

		printf("Help:\n"
		       "  %s\n"
		       "Example:\n"
		       "  %s %s %s\n", args[i].help,
		       prognm, args[i].name, args[i].example);
		return 0;
	}

	cmd = verify_cmd(cmd, detail);
	if (!cmd)
		return usage(1);

	return ipc_command(cmd, &argv[pos], argc - pos);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
