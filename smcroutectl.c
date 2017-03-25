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
#include <stdio.h>
#include "mclab.h"

char *prognm   = PACKAGE_NAME;
static const char version_info[] =
	PACKAGE_NAME " version " PACKAGE_VERSION
#ifdef BUILD
        " build " BUILD
#endif
	;

/**
 * cmd_build - Create IPC command to send to daemon
 * @cmd:   Command, one of 'a', 'r', 'j' or 'l'
 * @argv:  Vector of arguments for @cmd
 * @count: Number of arguments in @argv
 *
 * Builds an command packet with the command @cmd and @count number of
 * arguments from @argv.
 *
 * Returns:
 * Pointer to a dynamically allocated command packet, or %NULL on failure
 * to allocate enought memory.
 */
void *cmd_build(char cmd, const char *argv[], int count)
{
	int i;
	char *ptr;
	size_t arg_len = 0, packet_len;
	struct cmd *packet;

	/* Summarize length of all arguments/commands */
	for (i = 0; i < count; i++)
		arg_len += strlen(argv[i]) + 1;

	/* resulting packet size */
	packet_len = sizeof(struct cmd) + arg_len + 1;
	if (packet_len > MX_CMDPKT_SZ) {
		errno = EMSGSIZE;
		return NULL;
	}

	/* build packet */
	packet = malloc(packet_len);
	if (!packet)
		return NULL;

	packet->len   = packet_len;
	packet->cmd   = cmd;
	packet->count = count;

	/* copy args */
	ptr = (char *)(packet->argv);
	for (i = 0; i < count; i++) {
		arg_len = strlen(argv[i]) + 1;
		memcpy(ptr, argv[i], arg_len);
		ptr += arg_len;
	}
	*ptr = '\0';	/* '\0' behind last string */

	return packet;
}

/*
 * Counts the number of arguments belonging to an option. Option is any argument
 * begining with a '-'.
 *
 * returns: - the number of arguments (without the option itself),
 *          - 0, if we start already from the end of the argument vector
 *          - -1, if we start not from an option
 */
static int num_option_arguments(const char *argv[])
{
	const char **ptr;

	/* end of vector */
	if (argv == NULL || *argv == NULL)
		return 0;

	/* starting on wrong position */
	if (**argv != '-')
		return -1;

	for (ptr = argv + 1; *ptr && **ptr != '-'; ptr++)
		;

	return ptr - argv;
}

static int send_commands(int cmdnum, struct cmd *cmdv[])
{
	int i, result = 0;
	int retry_count = 30;

	if (!cmdnum)
		return 0;

	while (ipc_client_init() && !result) {
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

	for (i = 0; i < cmdnum; i++) {
		int slen, rlen;
		uint8 buf[MX_CMDPKT_SZ + 1];
		struct cmd *command = cmdv[i];

		/* Send command */
		fprintf(stderr, "Sending command(s) ... ");
		slen = ipc_send(command, command->len);

		/* Wait here for reply */
		rlen = ipc_receive(buf, MX_CMDPKT_SZ);
		if (slen < 0 || rlen < 0) {
			warn("Communication with daemon failed");
			result = 1;
			break;
		}

		if (rlen != 1 || *buf != '\0') {
			buf[MX_CMDPKT_SZ] = 0;
			fprintf(stderr, "Daemon error: %s\n", buf);
			result = 1;
			break;
		}
		puts("OK!");
	}

error:
	for (i = 0; i < cmdnum; i++)
		free(cmdv[i]);

	return result;
}

static int usage(int code)
{
	printf("\nUsage:\n"
	       "  %s [Fhkv] [-a|-r ROUTE] [-j|-l GROUP] [-x|-y SSM GROUP]\n"
	       "\n"
	       "  -F       Flush dynamic (*,G) multicast routes now\n"
	       "  -h       This help text\n"
	       "  -k       Kill a running daemon\n"
	       "  -v       Show program version\n"
	       "\n"
	       "  -a ARGS  Add a multicast route\n"
	       "  -r ARGS  Remove a multicast route\n"
	       "\n"
	       "  -j ARGS  Join a multicast group\n"
	       "  -l ARGS  Leave a multicast group\n"
	       "\n"
	       "  -x ARGS  Join a multicast group (Source Specific Multicast, SSM)\n"
	       "  -y ARGS  Leave a multicast group (Source Specific Multicast, SSM)\n"
	       "\n"
	       "     <------------- INBOUND -------------->  <----- OUTBOUND ------>\n"
	       "  -a <IFNAME> <SOURCE-IP> <MULTICAST-GROUP>  <IFNAME> [<IFNAME> ...]\n"
	       "  -r <IFNAME> <SOURCE-IP> <MULTICAST-GROUP>\n"
	       "\n"
	       "  -j <IFNAME> <MULTICAST-GROUP>\n"
	       "  -l <IFNAME> <MULTICAST-GROUP>\n"
	       "\n"
	       "  -x <IFNAME> <SOURCE-IP> <MULTICAST-GROUP>\n"
	       "  -y <IFNAME> <SOURCE-IP> <MULTICAST-GROUP>\n\n"
	       "Bug report address: %s\n"
	       "Project homepage: %s\n\n", prognm, PACKAGE_BUGREPORT, PACKAGE_URL);

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


/**
 * main - Main program
 *
 * Parses command line options and enters either daemon or client mode.
 *
 * In daemon mode, acquires multicast routing sockets, opens IPC socket
 * and goes in receive-execute command loop.
 *
 * In client mode, creates commands from command line and sends them to
 * the daemon.
 */
int main(int argc, const char *argv[])
{
	int num_opts;
	unsigned int i, cmdnum = 0;
	struct cmd *cmdv[16];

	prognm = progname(argv[0]);
	if (argc <= 1)
		return usage(1);

	/* Parse command line options */
	for (num_opts = 1; (num_opts = num_option_arguments(argv += num_opts));) {
		const char *arg;

		if (num_opts < 0)	/* error */
			return usage(1);

		/* handle option */
		arg = argv[0];
		switch (arg[1]) {
		case 'a':	/* add route */
			if (num_opts < 5)
				return usage(1);
			break;

		case 'r':	/* remove route */
			if (num_opts < 4)
				return usage(1);
			break;

		case 'j':	/* join */
		case 'l':	/* leave */
			if (num_opts != 3)
				return usage(1);
			break;

		case 'x':	/* join (ssm) */
		case 'y':	/* leave (ssm) */
			if (num_opts != 4)
				return usage(1);
			break;

		case 'k':	/* kill daemon */
			if (num_opts != 1)
				return usage(1);
			break;

		case 'F':
			if (num_opts != 1)
				return usage(1);
			break;

		case 'h':	/* help */
			return usage(0);

		case 'v':	/* version */
			fprintf(stderr, "%s\n", version_info);
			return 0;

		default:	/* unknown option */
			return usage(1);
		}

		/* Check and build command argument list. */
		if (cmdnum >= NELEMS(cmdv)) {
			fprintf(stderr, "Too many command options\n");
			return usage(1);
		}

		cmdv[cmdnum] = cmd_build(arg[1], argv + 1, num_opts - 1);
		if (!cmdv[cmdnum]) {
			perror("Failed parsing command");
			for (i = 0; i < cmdnum; i++)
				free(cmdv[i]);
			return 1;
		}
		cmdnum++;
	}

	return send_commands(cmdnum, cmdv);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
