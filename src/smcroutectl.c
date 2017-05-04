/* Client for smcrouted, not needed if only using smcroute.conf
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
} args[] = {
	{ "help",    0, 'h', "Show help text", NULL },
	{ "version", 0, 'v', "Show program version", NULL },
	{ "flush" ,  0, 'F', "Flush all dynamically set (*,G) multicast routes", NULL },
	{ "kill",    0, 'k', "Kill running daemon", NULL },
	{ "restart", 0, 'H', "Tell daemon to restart and reload its .conf file, like SIGHUP", NULL },
	{ "show",    0, 's', "Show passive (*,G) and active kernel routes", NULL },
	{ "add",     3, 'a', "Add a multicast route",    "eth0 192.168.2.42 225.1.2.3 eth1 eth2" },
	{ "del",     3, 'r', "Remove a multicast route", "eth0 192.168.2.42 225.1.2.3" },
	{ "remove",  3, 'r', NULL, NULL }, /* Alias for 'del' */
	{ "join",    2, 'j', "Join multicast group on an interface", "eth0 225.1.2.3" },
	{ "leave",   2, 'l', "Leave joined multicast group",         "eth0 225.1.2.3" },
	{ NULL, 0, 0, NULL, NULL }
};

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
			warn("Need root privileges to connect to daemon");
			result = 1;
			goto error;

		case ENOENT:
		case ECONNREFUSED:
			if (--retry_count) {
				usleep(100000);
				continue;
			}

			warn("Daemon not running");
			result = 1;
			goto error;

		default:
			warn("Failed connecting to daemon");
			result = 1;
			goto error;
		}
	}

	/* Send command */
	if (write(sd, msg, msg->len) != (ssize_t)msg->len)
		goto comms_err;

	/* Wait here for reply */
	len = read(sd, buf, sizeof(buf) - 1);
	if (len < 0) {
	comms_err:
		warn("Communication with daemon failed");
		result = 1;
		goto error;
	} else {
		buf[len] = 0;
	}

	if (len != 1 || *buf != '\0') {
		switch (cmd) {
		case 's':
			do {
				fputs(buf, stdout);
				len = read(sd, buf, sizeof(buf) - 1);
				buf[len] = 0;
			} while (len > 0);
			break;

		default:
			warnx("%s", buf);
			result = 1;
			break;
		}
	}

error:
	close(sd);
	free(msg);

	return result;
}

static int usage(int code)
{
	int i;

	printf("Usage:\n  %s CMD [ARGS]\n\n", prognm);
	printf("Commands:\n");
	for (i = 0; args[i].name; i++) {
		if (!args[i].help)
			continue;

		printf("  %-7s %s  %s\n", args[i].name,
		       args[i].min_args ? "ARGS" : "    ", args[i].help);
	}
	printf("\nArguments:\n"
	       "         <----------- INBOUND ------------>  <--- OUTBOUND ---->\n"
	       "  add    IFNAME [SOURCE-IP] MULTICAST-GROUP  IFNAME [IFNAME ...]\n"
	       "  del    IFNAME [SOURCE-IP] MULTICAST-GROUP\n"
	       "\n"
	       "  join   IFNAME [SOURCE-IP] MULTICAST-GROUP\n"
	       "  leave  IFNAME [SOURCE-IP] MULTICAST-GROUP\n"
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
	int i, help = 0, pos = 1;
	uint16_t cmd = 0;

	prognm = progname(argv[0]);
	if (argc < 2)
		return usage(1);

	for (i = 0; !cmd && pos < argc; i++) {
		int       c = args[i].val;
		char    *nm = args[i].name;
		char   *arg = argv[pos];
		size_t  len;

		if (!nm)
			break;

		len = MIN(MIN(strlen(nm), strlen(arg)), 2);
		while (*arg == '-') {
			arg++;
			len--;
		}

		if (len <= 0)
			continue;

		if (strncmp(arg, nm, len))
			continue;

		switch (c) {
		case 'h':	/* help */
			help++;
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
