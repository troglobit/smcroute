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
#include <poll.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#ifdef HAVE_TERMIOS_H
# include <termios.h>
#endif
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
	char *arg;
	char *help;
	char *example;		/* optional */
	int   has_detail;
} args[] = {
	{ NULL,      0, 'd', NULL,   "Detailed output in show command", NULL, 0 },
	{ NULL,      1, 'I', "NAME", "Identity of routing daemon instance, default: " PACKAGE, "foo", 0 },
	{ NULL,      0, 't', NULL,   "Skip table heading in show command", NULL, 0 },
	{ "help",    0, 'h', NULL,   "Show help text", NULL, 0 },
	{ "version", 0, 'v', NULL,   "Show program version", NULL, 0 },
	{ "flush" ,  0, 'F', NULL,   "Flush all dynamically set (*,G) multicast routes", NULL, 0 },
	{ "kill",    0, 'k', NULL,   "Kill running daemon", NULL, 0 },
	{ "restart", 0, 'H', NULL,   "Tell daemon to restart and reload its .conf file, like SIGHUP", NULL, 0 },
	{ "show",    0, 's', NULL,   "Show passive (*,G) and active routes, as well as joined groups", NULL, 1 },
	{ "add",     3, 'a', NULL,   "Add a multicast route",    "eth0 192.168.2.42 225.1.2.3 eth1 eth2", 0 },
	{ "remove",  2, 'r', NULL,   "Remove a multicast route", "eth0 192.168.2.42 225.1.2.3", 0 },
	{ "del",     2, 'r', NULL,   NULL, NULL, 0 }, /* Alias */
	{ "join",    2, 'j', NULL,   "Join multicast group on an interface", "eth0 225.1.2.3", 0 },
	{ "leave",   2, 'l', NULL,   "Leave joined multicast group",         "eth0 225.1.2.3", 0 },
	{ NULL, 0, 0, NULL, NULL, NULL, 0 }
};

static int heading = 1;
static char *ident = PACKAGE;
static char *prognm = NULL;


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

#define ESC "\033"
static int get_width(void)
{
	int ret = 74;
#ifdef HAVE_TERMIOS_H
	char buf[42];
	struct termios tc, saved;
	struct pollfd fd = { STDIN_FILENO, POLLIN, 0 };

	memset(buf, 0, sizeof(buf));
	tcgetattr(STDERR_FILENO, &tc);
	saved = tc;
	tc.c_cflag |= (CLOCAL | CREAD);
	tc.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	tcsetattr(STDERR_FILENO, TCSANOW, &tc);
	fprintf(stderr, ESC "7" ESC "[r" ESC "[999;999H" ESC "[6n");

	if (poll(&fd, 1, 300) > 0) {
		int row, col;

		if (scanf(ESC "[%d;%dR", &row, &col) == 2)
			ret = col;
	}

	fprintf(stderr, ESC "8");
	tcsetattr(STDERR_FILENO, TCSANOW, &saved);
#endif
	return ret;
}

static void table_heading(char *argv[], size_t count, int detail)
{
	int len;
	char line[90];
	const char *g = "GROUP (S,G)", *i = "INBOUND";
	const char *r = "ROUTE (S,G)", *o = "OUTBOUND", *p = "PACKETS", *b = "BYTES";

	/* Skip heading also if user redirects output to a file */
	if (!heading || !isatty(STDOUT_FILENO))
		return;

	if (count && argv[0][0] == 'g')
		snprintf(line, sizeof(line), "\e[7m%-34s %-16s", g, i);
	else if (detail)
		snprintf(line, sizeof(line), "\e[7m%-34s %-16s %10s %10s %-8s", r, i, p, b, o);
	else
		snprintf(line, sizeof(line), "\e[7m%-34s %-16s %-8s", r, i, o);

	len = get_width() - (int)strlen(line) + 4;
	fprintf(stderr, "%s%*s\n\e[0m", line, len < 0 ? 0 : len, "");
}

/*
 * Connects to the IPC socket of the server
 */
static int ipc_connect(void)
{
	struct sockaddr_un sa;
	socklen_t len;
	int sd;

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd < 0)
		return -1;

#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sa.sun_len = 0;	/* <- correct length is set by the OS */
#endif
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s/run/%s.sock", LOCALSTATEDIR, ident);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(sa.sun_path);
	if (connect(sd, (struct sockaddr *)&sa, len) < 0) {
		int err = errno;

		if (ENOENT == errno)
			warnx("Cannot find IPC socket %s", sa.sun_path);

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
			warnx("Daemon may be running with another -I NAME");
			break;

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

static int usage(int code)
{
	int i;

	printf("Usage:\n  %s [OPTIONS] CMD [ARGS]\n\n", prognm);

	printf("Options:\n");
	for (i = 0; args[i].val; i++) {
		if (!args[i].help)
			continue;

		if (args[i].name)
			continue;

		printf("  -%c %-10s %s\n", args[i].val, args[i].arg ? args[i].arg : "", args[i].help);
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
	       "Bug report address: %s\n", PACKAGE_BUGREPORT);
#ifdef PACKAGE_URL
	printf("Project homepage:   %s\n", PACKAGE_URL);
#endif

	return code;
}

static int version(void)
{
	puts(PACKAGE_VERSION);
	return 0;
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
	int c, i, pos = 1, status = 0;
	struct arg *cmd = NULL;

	prognm = progname(argv[0]);
	while ((c = getopt(argc, argv, "dhI:tv")) != EOF) {
		switch (c) {
		case 'd':
			detail++;
			break;

		case 'h':
			help++;
			break;

		case 'I':
			ident = optarg;
			break;

		case 't':
			heading = 0;
			break;

		case 'v':
			return version();

		default:
			errx(0, "Unknown option -'%c'\n", c);
		}
	}


	pos = optind;
	while (pos < argc && !cmd) {
		char *arg = argv[pos];

		for (i = 0; args[i].val; i++) {
			int       c = args[i].val;
			char    *nm = args[i].name;
			size_t  len;

			if (!nm)
				continue;

			len = MIN(strlen(nm), strlen(arg));
			if (strncmp(arg, nm, len))
				continue;

			switch (c) {
			case 'h':
				help++;
				break;

			case 'v':
				return version();

			default:
				cmd = &args[i];
				if (argc - (pos + 1) < args[i].min_args) {
					warnx("Not enough arguments to command %s", nm);
					status = 1;
					goto help;
				}
				break;
			}

			break;	/* Next arg */
		}
		pos++;
	}

	if (help) {
		if (!cmd)
			return usage(0);
	help:
		while (!cmd->help)
			cmd--;
		printf("Help:\n"
		       "  %s\n\n"
		       "Example:\n"
		       "  %s %s %s\n\n", cmd->help,
		       prognm, cmd->name, cmd->example ? cmd->example : "");
		return status;
	}

	if (!cmd)
		return usage(1);

	c = cmd->val;
	if (cmd->has_detail)
		c -= 0x20;

	return ipc_command(c, &argv[pos], argc - pos);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
