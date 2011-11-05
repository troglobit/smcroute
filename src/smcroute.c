/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006-2008 Julien BLACHE <jb@jblache.org>
**  Copyright (C) 2006-2009 Julien BLACHE <jb@jblache.org>
**  Copyright (C) 2009      Todd Hayton <todd.hayton@gmail.com>
**  Copyright (C) 2009-2011 Micha Lenk <micha@debian.org>
**  Copyright (C) 2011      Joachim Nilsson <troglobit@gmail.com>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
**
**  $Id: smcroute.c 86 2011-08-08 17:09:45Z micha $	
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <signal.h>
#include <unistd.h>

#include "mclab.h"

#include "config.h"
#include "build.h"

static const char version_info[] =
	"smcroute, Version " PACKAGE_VERSION ", Build" BUILD "\n"
	"Copyright (c) 2001-2005  Carsten Schill <carsten@cschill.de>\n"
	"Copyright (c) 2006-2009  Julien Blache <jb@jblache.org>,\n"
	"                   2009  Todd Hayton <todd.hayton@gmail.com>, and\n"
	"              2009-2011  Micha Lenk <micha@debian.org>\n"
	"                   2011  Joachim Nilsson <troglobit@gmail.com>\n"
	"Distributed under the GNU GENERAL PUBLIC LICENSE, Version 2\n"
	"\n";

static const char usage_info[] =
	"Usage: smcroute [OPTIONS]... [ARGS]...\n"
	"\n"
	"  -d       Start smcroute daemon.\n"
	"  -n       Run daemon in foreground, i.e., do not fork.\n"
	"  -f FILE  Use FILE as daemon configuration. Default: " SMCROUTE_SYSTEM_CONF "\n"
	"  -k       Stop (kill) a running daemon.\n"
	"\n"
	"  -h       Display this help text.\n"
	"  -D       Debug logging.\n"
	"  -v       Display version information and enable verbose logging.\n"
	"\n"
	"  -a ARGS  Add a multicast route, full syntax below.\n"
	"  -r ARGS  Remove a multicast route, full syntax below.\n"
	"\n"
	"  -j ARGS  Join a multicast group on an interface, useful for testing.\n"
	"  -l ARGS  Leave a multicast group on an interface, useful for testing.\n"
	"\n"
	"     <------------- INBOUND -------------->  <----- OUTBOUND ------>\n"
	"  -a <IFNAME> <SOURCE-IP> <MULTICAST-GROUP>  <IFNAME> [<IFNAME> ...]\n"
	"  -r <IFNAME> <SOURCE-IP> <MULTICAST-GROUP>\n"
	"\n"
	"  -j <IFNAME> <MULTICAST-GROUP>\n"
	"  -l <IFNAME> <MULTICAST-GROUP>\n";

static int sighandled = 0;
#define	GOT_SIGINT	0x01
#define	GOT_SIGHUP	0x02

int do_debug_logging = 0;

/*
 * Signal handler.  Take note of the fact that the signal arrived
 * so that the main loop can take care of it.
 */
static void handler(int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGTERM:
	sighandled |= GOT_SIGINT;
	break;

    case SIGHUP:
	sighandled |= GOT_SIGHUP;
	break;
    }
}

static void signal_init(void)
{
	struct sigaction sa;

	sa.sa_handler = handler;
	sa.sa_flags = 0;	/* Interrupt system calls */
	sigemptyset(&sa.sa_mask);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
}

/*
** Counts the number of arguments belonging to an option. Option is any argument
** begining with a '-'. 
** 
** returns: - the number of arguments (without the option itself), 
**          - 0, if we start already from the end of the argument vector
**          - -1, if we start not from an option
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

/* Parse .conf file and setup routes */
static void read_conf_file(const char *conf_file)
{
	if (access(conf_file, R_OK)) {
		smclog(LOG_WARNING, errno, "Failed loading %s", conf_file);
	} else {
		if (parse_conf_file(conf_file))
			smclog(LOG_WARNING, errno, "Failed reading %s", conf_file);
	}
}

/* Cleans up, i.e. releases allocated resources. Called via atexit() */
static void clean(void)
{
	smclog(LOG_DEBUG, 0, "clean handler called");
	mroute4_disable();
	mroute6_disable();
	ipc_exit();
}

static void restart(void)
{
	smclog(LOG_DEBUG, 0, "Restart handler called");
	mroute4_disable();
	mroute6_disable();
	/* No need to close the IPC, only at cleanup. */

	/* Update list of interfaces and create new virtual interface mappings in kernel. */
	iface_init();
	mroute4_enable();
	mroute6_enable();
}

static int daemonize(void)
{
	int pid;

	smclog(LOG_NOTICE, 0, "Forking daemon process.");

	pid = fork();
	if (!pid) {
		/* Detach deamon from terminal */
		if (close(0) < 0 || close(1) < 0 || close(2) < 0
		    || open("/dev/null", 0) != 0 || dup2(0, 1) < 0
		    || dup2(0, 2) < 0 || setpgrp() < 0)
			smclog(LOG_ERR, errno, "Failed to detach deamon");
	}

	return pid;
}

static void server_loop(int sd, const char *conf_file)
{
	int result;
	uint8 buf[MX_CMDPKT_SZ];
	fd_set fds;
#ifdef HAVE_IPV6_MULTICAST_ROUTING
	int max_fd_num = MAX(sd, MAX(mroute4_socket, mroute6_socket));
#else
	int max_fd_num = MAX(sd, mroute4_socket);
#endif
	const char *str;
	struct cmd *packet;
	struct mroute mroute;

	smclog(LOG_NOTICE, 0, "Attempting to load %s", conf_file);
	read_conf_file (conf_file);

	/* Ready for input, tell clients that by creating the pidfile */
	if (pidfile(NULL))
		smclog(LOG_WARNING, errno, "Failed creating pidfile");

	/* Watch the MRouter and the IPC socket to the smcroute client */
	while (1) {
		if (sighandled) {
			if (sighandled & GOT_SIGINT) {
				sighandled &= ~GOT_SIGINT;
				break;
			}
			if (sighandled & GOT_SIGHUP) {
				sighandled &= ~GOT_SIGHUP;
				restart();
				smclog(LOG_NOTICE, 0, "Got SIGHUP, reloading %s ...", conf_file);
				read_conf_file (conf_file);
			}
		}

		FD_ZERO(&fds);
		FD_SET(sd, &fds);
		FD_SET(mroute4_socket, &fds);
#ifdef HAVE_IPV6_MULTICAST_ROUTING
		if (-1 != mroute6_socket)
			FD_SET(mroute6_socket, &fds);
#endif

		/* wait for input */
		result = select(max_fd_num + 1, &fds, NULL, NULL, NULL);
		if (result <= 0) {
			/* Log all errors, except when signalled, ignore failures. */
			if (EINTR != errno)
				smclog(LOG_WARNING, errno, "select() failure");
			continue;
		}

		/* Receive and drop IGMP stuff. This is either IGMP packets
		 * or upcall messages sent up from the kernel.
		 */
		if (FD_ISSET(mroute4_socket, &fds)) {
			char tmp[128];

			result = read(mroute4_socket, tmp, sizeof(tmp));
			smclog(LOG_DEBUG, 0, "%d byte IGMP signaling dropped", result);
		}

		/* Receive and drop ICMPv6 stuff. This is either MLD packets
		 * or upcall messages sent up from the kernel.
		 */
#ifdef HAVE_IPV6_MULTICAST_ROUTING
		if (-1 != mroute6_socket && FD_ISSET(mroute6_socket, &fds)) {
			char tmp[128];

			result = read(mroute6_socket, tmp, sizeof(tmp));
			smclog(LOG_DEBUG, 0, "%d byte MLD signaling dropped", result);
		}
#endif

		/* loop back to select if there is no smcroute command */
		if (!FD_ISSET(sd, &fds))
			continue;

		/* receive the command from the smcroute client */
		packet = ipc_server_read(buf, sizeof(buf));
		switch (packet->cmd) {
		case 'a':
		case 'r':
			if ((str = cmd_convert_to_mroute(&mroute, packet))) {
				smclog(LOG_WARNING, 0, str);
				ipc_send(log_last_message, strlen(log_last_message) + 1);
				break;
			}

			if (mroute.version == 4) {
				if ((packet->cmd == 'a' && mroute4_add(&mroute.u.mroute4))
				    || (packet->cmd == 'r' && mroute4_del(&mroute.u.mroute4))) {
					ipc_send(log_last_message, strlen(log_last_message) + 1);
					break;
				}
			} else {
#ifndef HAVE_IPV6_MULTICAST_ROUTING
				smclog(LOG_WARNING, 0, "Not built with IPv6 routing support.");
#else
				if ((packet->cmd == 'a' && mroute6_add(&mroute.u.mroute6))
				    || (packet->cmd == 'r' && mroute6_del(&mroute.u.mroute6))) {
					ipc_send(log_last_message, strlen(log_last_message) + 1);
					break;
				}
#endif				/* HAVE_IPV6_MULTICAST_ROUTING */
			}

			ipc_send("", 1);
			break;

		case 'j':	/* j <InputIntf> <McGroupAdr> */
		case 'l':	/* l <InputIntf> <McGroupAdr> */
		{
			int result = -1;
			const char *ifname = (const char *)(packet + 1);
			const char *groupstr = ifname + strlen(ifname) + 1;

			if (strchr(groupstr, ':') == NULL) {
				struct in_addr group;

				/* check multicast address */
				if (!*groupstr
				    || !inet_aton(groupstr, &group)
				    || !IN_MULTICAST(ntohl(group.s_addr))) {
					smclog(LOG_WARNING, 0, "invalid multicast group address: '%s'", groupstr);
					ipc_send(log_last_message, strlen(log_last_message) + 1);
					break;
				}

				/* join or leave */
				if (packet->cmd == 'j')
					result = mcgroup4_join(ifname, group);
				else
					result = mcgroup4_leave(ifname, group);
			} else {	/* IPv6 */
#ifndef HAVE_IPV6_MULTICAST_HOST
				smclog(LOG_WARNING, 0, "Not built with IPv6 support.");
#else
				struct in6_addr group;

				/* check multicast address */
				if (!*groupstr
				    || (inet_pton(AF_INET6, groupstr, &group) <= 0)
				    || !IN6_IS_ADDR_MULTICAST(&group)) {
					smclog(LOG_WARNING, 0, "invalid multicast group address: '%s'", groupstr);
					ipc_send(log_last_message, strlen(log_last_message) + 1);
					break;
				}

				/* join or leave */
				if (packet->cmd == 'j')
					result = mcgroup6_join(ifname, group);
				else
					result = mcgroup6_leave(ifname, group);
#endif				/* HAVE_IPV6_MULTICAST_HOST */
			}

			/* failed */
			if (result) {
				ipc_send(log_last_message, strlen(log_last_message) + 1);
				break;
			}

			ipc_send("", 1);
			break;
		}

		case 'k':
			ipc_send("", 1);
			exit(0);
		}
	}
}

/* Init everything before forking, so we can fail and return an
 * error code in the parent and the initscript will fail */
static void start_server(int background, const char *conf_file)
{
	int sd, pid = 0;
	unsigned short initialized_api_count;

	/* Build list of multicast-capable physical interfaces that 
	 * are currently assigned an IP address. */
	iface_init();

	initialized_api_count = 0;
	if (mroute4_enable() == 0)
		initialized_api_count++;

	if (mroute6_enable() == 0)
		initialized_api_count++;

	/* At least one API (IPv4 or IPv6) must have initialized successfully
	 * otherwise we abort the server initialization. */
	if (initialized_api_count == 0) {
		smclog(LOG_INIT, ENOPROTOOPT, "Kernel does not support multicast routing");
		exit(1);
	}

	sd = ipc_server_init();
	if (sd < 0) {
		clean();
		exit(2);
	}

	if (background)
		pid = daemonize();

	if (!pid) {
		smclog(LOG_NOTICE, 0, "Entering smcroute daemon main loop.");
		atexit(clean);
		signal_init();
		server_loop(sd, conf_file);
	}
}

static int usage(void)
{
	fputs(version_info, stderr);
	fputs(usage_info, stderr);

	return 1;
}

/*
** main program
** - Parses command line options
**   - daemon mode: enters daemon status and goes in receive-execute command loop 
**   - client mode: creates commands from command line and sends them to the daemon
*/
int main(int argc, const char *argv[])
{
	int num_opts, result = 0;
	int start_daemon = 0;
	int background = 1;
	uint8 buf[MX_CMDPKT_SZ];
	const char *arg, *conf_file = SMCROUTE_SYSTEM_CONF;
	unsigned int cmdnum = 0;
	struct cmd *cmdv[16];

	/* init syslog */
	openlog(argv[0], LOG_PID, LOG_DAEMON);

	if (argc <= 1)
		return usage();

	/* Parse command line options */
	for (num_opts = 1; (num_opts = num_option_arguments(argv += num_opts));) {
		if (num_opts < 0)	/* error */
			return usage();

		/* handle option */
		arg = argv[0];
		switch (arg[1]) {
		case 'a':	/* add route */
			if (num_opts < 5) {
				fprintf(stderr, "Not enough arguments for 'add' command\n");
				return usage();
			}
			break;

		case 'r':	/* remove route */
			if (num_opts < 4) {
				fprintf(stderr, "Wrong number of  arguments for 'remove' command\n");
				return usage();
			}
			break;

		case 'j':	/* join */
		case 'l':	/* leave */
			if (num_opts != 3) {
				fprintf(stderr, "Wrong number of arguments for %s command\n", arg[1] == 'j' ? "'join'" : "'leave'");
				return usage();
			}
			break;

		case 'k':	/* kill daemon */
			if (num_opts != 1) {
				fprintf(stderr, "No arguments allowed for 'k' option\n");
				return usage();
			}
			break;

		case 'h':	/* help */
			return usage();

		case 'v':	/* verbose */
			fputs(version_info, stderr);
			log_stderr = LOG_DEBUG;
			continue;

		case 'd':	/* daemon */
			start_daemon = 1;
			continue;

		case 'n':	/* run daemon in foreground, i.e., do not fork */
			background = 0;
			continue;

		case 'f':
			if (num_opts != 2) {
				fprintf(stderr, "Missing configuration file arguments for 'f' option\n");
				return usage();
			}
			conf_file = argv[1];
			continue;

		case 'D':
			do_debug_logging = 1;
			continue;

		default:	/* unknown option */
			fprintf(stderr, "unknown option: %s\n", *argv);
			return usage();
		}

		/* Check and build command argument list. */
		if (cmdnum >= ARRAY_ELEMENTS(cmdv)) {
			fprintf(stderr, "Too many command options\n");
			return usage();
		}

		cmdv[cmdnum++] = cmd_build(arg[1], argv + 1, num_opts - 1);
	}

	if (start_daemon) {	/* only daemon parent enters */
		start_server(background, conf_file);
		if (!background)
			exit (0); /* Exit if non-backgrounded daemon exits this way. */
	}

	/* Client or daemon parent only, the daemon never reaches this point */

	/* send commands */
	if (cmdnum) {
		unsigned int i;
		int code, retry_count = 30;

		openlog(argv[0], LOG_PID, LOG_USER);

	retry:
		/* connect to daemon */
		code = ipc_client_init();
		if (code) {
			switch (code) {
			case EACCES:
				smclog(LOG_ERR, EACCES, "need super-user rights to connect to daemon");
				break;

			case ENOENT:
			case ECONNREFUSED:
				/* When starting daemon, give it 30 times a 1/10 second to get ready */
				if (start_daemon && --retry_count) {
					usleep(100000);
					goto retry;
				}
				smclog(LOG_ERR, code, "daemon not running ?");
				break;

			default:
				smclog(LOG_ERR, code, "Failed connecting to daemon");
				break;
			}
		}

		for (i = 0; i < cmdnum; i++) {
			int slen = 0, rlen = 0;
			struct cmd *command = cmdv[i];

			slen = ipc_send(command, command->len);
			rlen = ipc_receive(buf, sizeof(buf));
			if (slen < 0 || rlen < 0)
				smclog(LOG_ERR, errno, "read/write to daemon failed");

			smclog(LOG_DEBUG, 0, "rlen: %d", rlen);

			if (rlen != 1 || *buf != '\0') {
				fprintf(stderr, "daemon error: %s\n", buf);
				result = 1;
			}

			free(command);
		}
	}

	return result;
}

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
