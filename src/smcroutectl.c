/* Client for smcrouted, not needed if only using smcroute.conf
 *
 * Copyright (C) 2011-2021  Joachim Wiberg <troglobit@gmail.com>
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

static const char version_info[] = PACKAGE_NAME " v" PACKAGE_VERSION;

static char *ident = PACKAGE;
static char *sock_file = NULL;
static char *prognm = NULL;
static int   heading = 1;
static int   plain = 0;

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
	{ NULL,      0, 'p', NULL,   "Use plain table headings, no ctrl chars", NULL, 0 },
	{ NULL,      1, 'S', "FILE", "UNIX domain socket for daemon, default: " RUNSTATEDIR "/" PACKAGE ".sock", "/tmp/foo.sock", 0 },
	{ NULL,      0, 't', NULL,   "Skip table heading in show command", NULL, 0 },
	{ "help",    0, 'h', NULL,   "Show help text", NULL, 0 },
	{ "version", 0, 'v', NULL,   "Show program version", NULL, 0 },
	{ "flush" ,  0, 'F', NULL,   "Flush all dynamically set (*,G) multicast routes", NULL, 0 },
	{ "kill",    0, 'k', NULL,   "Kill running daemon", NULL, 0 },
	{ "reload",  0, 'H', NULL,   "Reload .conf file, like SIGHUP", NULL, 0 },
	{ "restart", 0, 'H', NULL,   NULL, NULL, 0 }, /* Alias, compat with older versions */
	{ "show",    0, 's', NULL,   "Show status of routes, joined groups, interfaces, etc.", NULL, 1 },
	{ "add",     3, 'a', NULL,   "Add a multicast route",    "eth0 192.168.2.42 225.1.2.3 eth1 eth2", 0 },
	{ "remove",  2, 'r', NULL,   "Remove a multicast route", "eth0 192.168.2.42 225.1.2.3", 0 },
	{ "del",     2, 'r', NULL,   NULL, NULL, 0 }, /* Alias */
	{ "join",    2, 'j', NULL,   "Join multicast group on an interface", "eth0 225.1.2.3", 0 },
	{ "leave",   2, 'l', NULL,   "Leave joined multicast group",         "eth0 225.1.2.3", 0 },
	{ NULL, 0, 0, NULL, NULL, NULL, 0 }
};


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

static void table_heading(char cmd, int detail)
{
	const char *r = "ROUTE (S,G)", *o = "OUTBOUND", *p = "PACKETS", *b = "BYTES";
	const char *g = "GROUP (S,G)", *i = "INBOUND";
	char line[120];

	if (!heading)
		return;

	/* Skip heading also if user redirects output to a file */
	if (!plain && !isatty(STDOUT_FILENO))
		return;

	if (detail)
		cmd -= 0x20;

	switch (cmd) {
	case 'G':
	case 'g':
		snprintf(line, sizeof(line), "%-46s %-16s", g, i);
		break;

	case 'R':
		snprintf(line, sizeof(line), "%-46s %-16s %10s %10s  %-8s", r, i, p, b, o);
		break;

	case 'r':
		snprintf(line, sizeof(line), "%-46s %-16s %-8s", r, i, o);
		break;

	case 'i':
	case 'I':
		snprintf(line, sizeof(line), "PHYINT           IFINDEX  VIF  MIF");
		break;

	default:
		return;
	}

	if (!plain) {
		int len;

		len = get_width() - (int)strlen(line);
		fprintf(stderr, "\e[7m%s%*s\n\e[0m", line, len < 0 ? 0 : len, "");
	} else {
		size_t j, len;

		fprintf(stderr, "%s\n", line);
		len = strlen(line);
		for (j = 0; j < len; j++)
			fputc('=', stderr);
		fputc('\n', stderr);
	}
}

/*
 * Connects to the IPC socket of the server
 */
static int ipc_connect(char *path)
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
	if (!path)
		snprintf(sa.sun_path, sizeof(sa.sun_path), "%s/%s.sock", RUNSTATEDIR, ident);
	else
		snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);

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

	while ((sd = ipc_connect(sock_file)) < 0) {
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
		char *fallback[] = { "route" };
		int detail = 0;

		if (!argv || !argv[0])
			argv = fallback;

		/* Make sure buffer is NULL terminated */
		buf[len] = 0;

		switch (cmd) {
		case 'S':
			detail = 1;
			/* fallthrough */
		case 's':
			table_heading(argv[0][0], detail);
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
	       "         <--------- INBOUND ---------->  <--- OUTBOUND ---->\n"
	       "  add    IFNAME [SOURCE-IP] GROUP[/LEN]  IFNAME [IFNAME ...]\n"
	       "  remove IFNAME [SOURCE-IP] GROUP[/LEN]\n"
	       "\n"
	       "  join   IFNAME [SOURCE-IP[/LEN]] GROUP[/LEN]\n"
	       "  leave  IFNAME [SOURCE-IP[/LEN]] GROUP[/LEN]\n"
	       "\n"
	       "  show   interfaces    Show configured multicast interfaces\n"
	       "  show   groups        Show joined multicast groups\n"
	       "  show   routes        Show (*,G) and (S,G) multicast routes, default\n"
	       "\n"
	       "NOTE: IFNAME is either an interface name or wildcard.  E.g., `eth+` matches\n"
	       "      eth0, eth15, etc.  Wildcards are available for inbound interfaces.\n"
	       "\n");

	return code;
}

static int version(void)
{
	puts(version_info);
	printf("\n"
	       "Bug report address: %s\n", PACKAGE_BUGREPORT);
#ifdef PACKAGE_URL
	printf("Project homepage:   %s\n", PACKAGE_URL);
#endif
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
	while ((c = getopt(argc, argv, "dhI:pS:tv")) != EOF) {
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

		case 'p':
			plain = 1;
			break;

		case 'S':
			sock_file = optarg;
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
			char    *nm = args[i].name;
			size_t  len;

			if (!nm)
				continue;

			len = MIN(strlen(nm), strlen(arg));
			if (strncmp(arg, nm, len))
				continue;

			c = args[i].val;
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
		return ipc_command(detail ? 'S' : 's', NULL, 0);

	c = cmd->val;
	if (detail && cmd->has_detail)
		c -= 0x20;

	return ipc_command(c, &argv[pos], argc - pos);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
