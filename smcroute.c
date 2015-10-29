/* Daemon and client main routines
 *
 * Copyright (C) 2001-2005  Carsten Schill <carsten@cschill.de>
 * Copyright (C) 2006-2009  Julien BLACHE <jb@jblache.org>
 * Copyright (C) 2009       Todd Hayton <todd.hayton@gmail.com>
 * Copyright (C) 2009-2011  Micha Lenk <micha@debian.org>
 * Copyright (C) 2011-2013  Joachim Nilsson <troglobit@gmail.com>
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
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <signal.h>
#include <unistd.h>

#include "mclab.h"

#define SMCROUTE_SYSTEM_CONF "/etc/smcroute.conf"

int do_debug_logging = 0;
const char *script_exec = NULL;

static int         running   = 1;
static const char *conf_file = SMCROUTE_SYSTEM_CONF;

extern char *__progname;
static const char version_info[] =
	"SMCRoute version " PACKAGE_VERSION
#ifdef BUILD
        " build " BUILD
#endif
        "\n";

static const char usage_info[] =
	"Usage: smcroute [OPTIONS]... [ARGS]...\n"
	"\n"
	"  -d       Start daemon\n"
	"  -n       Run daemon in foreground\n"
	"  -f FILE  File to use instead of default " SMCROUTE_SYSTEM_CONF "\n"
	"  -s SCRIPT  Script to call on startup/reload when all routes have\n"
	"             been installed. Or when a source-less (ANY) route has\n"
	"             been installed.\n"
	"  -k       Kill a running daemon\n"
	"\n"
	"  -h       This help text\n"
	"  -D       Debug logging\n"
	"  -v       Show version and enable verbose logging\n"
	"\n"
	"  -a ARGS  Add a multicast route\n"
	"  -r ARGS  Remove a multicast route\n"
	"\n"
	"  -j ARGS  Join a multicast group\n"
	"  -l ARGS  Leave a multicast group\n"
	"\n"
	"     <------------- INBOUND -------------->  <----- OUTBOUND ------>\n"
	"  -a <IFNAME> <SOURCE-IP> <MULTICAST-GROUP>  <IFNAME> [<IFNAME> ...]\n"
	"  -r <IFNAME> <SOURCE-IP> <MULTICAST-GROUP>\n"
	"\n"
	"  -j <IFNAME> <MULTICAST-GROUP>\n"
	"  -l <IFNAME> <MULTICAST-GROUP>\n";

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

/* Parse .conf file and setup routes */
static void read_conf_file(const char *conf_file)
{
	if (access(conf_file, R_OK)) {
		smclog(LOG_WARNING, errno, "Failed loading %s", conf_file);
		return;
	}

	if (parse_conf_file(conf_file))
		smclog(LOG_WARNING, errno, "Failed reading %s", conf_file);
}

/* Cleans up, i.e. releases allocated resources. Called via atexit() */
static void clean(void)
{
	mroute4_disable();
	mroute6_disable();
	mcgroup4_disable();
	mcgroup6_disable();
	ipc_exit();
	smclog(LOG_NOTICE, 0, "Exiting.");
}

static void restart(void)
{
	mroute4_disable();
	mroute6_disable();
	mcgroup4_disable();
	mcgroup6_disable();
	/* No need to close the IPC, only at cleanup. */

	/* Update list of interfaces and create new virtual interface mappings in kernel. */
	iface_init();
	mroute4_enable();
	mroute6_enable();
}

static int daemonize(void)
{
	int pid;

	pid = fork();
	if (pid < 0)
		smclog(LOG_ERR, errno, "Cannot start in background");
	if (!pid) {
		/* Detach deamon from terminal */
		if (close(0) < 0 || close(1) < 0 || close(2) < 0
		    || open("/dev/null", 0) != 0 || dup2(0, 1) < 0
		    || dup2(0, 2) < 0 || setpgid(0, 0) < 0)
			smclog(LOG_ERR, errno, "Failed detaching deamon");
	}

	return pid;
}

/* Check for kernel IGMPMSG_NOCACHE for (*,G) hits. I.e., source-less routes. */
static int read_mroute4_socket(void)
{
	int result;
	char tmp[128];
	struct ip *ip;
	struct igmpmsg *igmpctl;

	memset(tmp, 0, sizeof(tmp));
	result = read(mroute4_socket, tmp, sizeof(tmp));

	/* packets sent up from kernel to daemon have ip->ip_p = 0 */
	ip = (struct ip *)tmp;
	igmpctl = (struct igmpmsg *)tmp;

	/* Check for IGMPMSG_NOCACHE to do (*,G) based routing. */
	if (ip->ip_p == 0 && igmpctl->im_msgtype == IGMPMSG_NOCACHE) {
		struct iface *iface;
		mroute4_t mroute;

		mroute.group.s_addr  = igmpctl->im_dst.s_addr;
		mroute.sender.s_addr = igmpctl->im_src.s_addr;
		mroute.inbound       = igmpctl->im_vif;

		iface = iface_find_by_vif(mroute.inbound);
		if (!iface) {
			/* TODO: Add support for dynamically re-enumerating VIFs at runtime! */
			smclog(LOG_WARNING, 0, "No VIF for possibly dynamic inbound iface %s, cannot add mroute dynamically.", mroute.inbound);
			return 1;
		}

		/* Find any matching route for this group on that iif. */
		result = mroute4_dyn_add(&mroute);
		if (!result && script_exec) {
			mroute_t mrt;

			mrt.version = 4;
			mrt.u.mroute4 = mroute;
			run_script(&mrt);
		}
	}

	return result;
}

/* Receive and drop ICMPv6 stuff. This is either MLD packets or upcall messages sent up from the kernel. */
static int read_mroute6_socket(void)
{
	char tmp[128];

	if (mroute6_socket < 0)
		return -1;

	return read(mroute6_socket, tmp, sizeof(tmp));
}

/* Receive command from the smcroute client */
static int read_ipc_command(void)
{
	const char *str;
	struct cmd *packet;
	struct mroute mroute;
	uint8 buf[MX_CMDPKT_SZ];

	memset(buf, 0, sizeof(buf));
	packet = ipc_server_read(buf, sizeof(buf));
	if (!packet) {
		/* Skip logging client disconnects */
		if (errno != ECONNRESET)
			smclog(LOG_WARNING, errno, "Failed receving IPC message from client");
		return 1;
	}

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
			smclog(LOG_WARNING, 0, "IPv6 multicast routing support disabled.");
#else
			if ((packet->cmd == 'a' && mroute6_add(&mroute.u.mroute6))
			    || (packet->cmd == 'r' && mroute6_del(&mroute.u.mroute6))) {
				ipc_send(log_last_message, strlen(log_last_message) + 1);
				break;
			}
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
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
				smclog(LOG_WARNING, 0, "Invalid multicast group: %s", groupstr);
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
			smclog(LOG_WARNING, 0, "IPv6 multicast support disabled.");
#else
			struct in6_addr group;

			/* check multicast address */
			if (!*groupstr
			    || (inet_pton(AF_INET6, groupstr, &group) <= 0)
			    || !IN6_IS_ADDR_MULTICAST(&group)) {
				smclog(LOG_WARNING, 0, "Invalid multicast group: %s", groupstr);
				ipc_send(log_last_message, strlen(log_last_message) + 1);
				break;
			}

			/* join or leave */
			if (packet->cmd == 'j')
				result = mcgroup6_join(ifname, group);
			else
				result = mcgroup6_leave(ifname, group);
#endif /* HAVE_IPV6_MULTICAST_HOST */
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

	return 0;
}

/*
 * Signal handler.  Take note of the fact that the signal arrived
 * so that the main loop can take care of it.
 */
static void handler(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		running = 0;
		break;

	case SIGHUP:
		smclog(LOG_NOTICE, 0, "Got SIGHUP, reloading %s ...", conf_file);
		restart();
		read_conf_file(conf_file);
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

static void server_loop(int sd)
{
	fd_set fds;
#ifdef HAVE_IPV6_MULTICAST_ROUTING
	int max_fd_num = MAX(sd, MAX(mroute4_socket, mroute6_socket));
#else
	int max_fd_num = MAX(sd, mroute4_socket);
#endif

	/* Watch the MRouter and the IPC socket to the smcroute client */
	while (running) {
		int result;

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

		if (FD_ISSET(mroute4_socket, &fds))
			read_mroute4_socket();

#ifdef HAVE_IPV6_MULTICAST_ROUTING
		if (-1 != mroute6_socket && FD_ISSET(mroute6_socket, &fds))
			read_mroute6_socket();
#endif

		/* loop back to select if there is no smcroute command */
		if (FD_ISSET(sd, &fds))
			read_ipc_command();
	}
}

/* Init everything before forking, so we can fail and return an
 * error code in the parent and the initscript will fail */
static void start_server(int background)
{
	int sd, api = 0, busy = 0;

	if (background && daemonize())
		return;

	smclog(LOG_NOTICE, 0, "%s", version_info);

	/* Build list of multicast-capable physical interfaces that
	 * are currently assigned an IP address. */
	iface_init();

	if (mroute4_enable()) {
		if (errno == EADDRINUSE)
			busy++;
	} else {
		api++;
	}

	if (mroute6_enable()) {
		if (errno == EADDRINUSE)
			busy++;
	} else {
		api++;
	}

	/* At least one API (IPv4 or IPv6) must have initialized successfully
	 * otherwise we abort the server initialization. */
	if (!api) {
		if (busy)
			smclog(LOG_INIT, 0, "Another multicast routing application is already running.");
		else
			smclog(LOG_INIT, 0, "Kernel does not support multicast routing.");
		exit(1);
	}

	sd = ipc_server_init();
	if (sd < 0)
		smclog(LOG_WARNING, errno, "Failed setting up IPC socket, client communication disabled");

	atexit(clean);
	signal_init();
	read_conf_file(conf_file);

	/* Everything setup, notify any clients by creating the pidfile */
	if (pidfile(NULL))
		smclog(LOG_WARNING, errno, "Failed creating pidfile");

	server_loop(sd);
}

static int usage(void)
{
	fputs(version_info, stderr);
	fputs(usage_info, stderr);

	return 1;
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
	int i, num_opts, result = 0;
	int start_daemon = 0;
	int background = 1;
	unsigned int cmdnum = 0;
	struct cmd *cmdv[16];

	/* init syslog */
	openlog(__progname, LOG_PID, LOG_DAEMON);

	if (argc <= 1)
		return usage();

	/* Parse command line options */
	for (num_opts = 1; (num_opts = num_option_arguments(argv += num_opts));) {
		const char *arg;

		if (num_opts < 0)	/* error */
			return usage();

		/* handle option */
		arg = argv[0];
		switch (arg[1]) {
		case 'a':	/* add route */
			if (num_opts < 5)
				return usage();
			break;

		case 'r':	/* remove route */
			if (num_opts < 4)
				return usage();
			break;

		case 'j':	/* join */
		case 'l':	/* leave */
			if (num_opts != 3)
				return usage();
			break;

		case 'k':	/* kill daemon */
			if (num_opts != 1)
				return usage();
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
			if (num_opts != 2)
				return usage();
			conf_file = argv[1];
			continue;

		case 's':
			if (num_opts != 2)
				return usage();
			script_exec = argv[1];
			continue;

		case 'D':
			do_debug_logging = 1;
			continue;

		default:	/* unknown option */
			return usage();
		}

		/* Check and build command argument list. */
		if (cmdnum >= ARRAY_ELEMENTS(cmdv)) {
			fprintf(stderr, "Too many command options\n");
			return usage();
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

	if (start_daemon) {	/* only daemon parent enters */
		if (geteuid() != 0) {
			smclog(LOG_ERR, 0, "Need root privileges to start %s", __progname);
			return 1;
		}

		if (script_exec && access(script_exec, X_OK)) {
			fprintf(stderr, "%s is not an executable, disabling script.", script_exec);
			script_exec = NULL;
		}

		start_server(background);
		if (!background)
			return 0;
	}

	/* Client or daemon parent only, the daemon never reaches this point */

	/* send commands */
	if (cmdnum) {
		int retry_count = 30;

		openlog(argv[0], LOG_PID, LOG_USER);

		/* connect to daemon */
		while (ipc_client_init() && !result) {
			switch (errno) {
			case EACCES:
				smclog(LOG_ERR, EACCES, "Need root privileges to connect to daemon");
				result = 1;
				break;

			case ENOENT:
			case ECONNREFUSED:
				/* When starting daemon, give it 30 times a 1/10 second to get ready */
				if (start_daemon && --retry_count) {
					usleep(100000);
					continue;
				}

				smclog(LOG_WARNING, errno, "Daemon not running");
				result = 1;
				break;

			default:
				smclog(LOG_WARNING, errno, "Failed connecting to daemon");
				result = 1;
				break;
			}
		}

		for (i = 0; !result && i < cmdnum; i++) {
			int slen, rlen;
			uint8 buf[MX_CMDPKT_SZ + 1];
			struct cmd *command = cmdv[i];

			/* Send command */
			slen = ipc_send(command, command->len);

			/* Wait here for reply */
			rlen = ipc_receive(buf, MX_CMDPKT_SZ);
			if (slen < 0 || rlen < 0) {
				smclog(LOG_WARNING, errno, "Communication with daemon failed");
				result = 1;
			}

			if (rlen != 1 || *buf != '\0') {
				buf[MX_CMDPKT_SZ] = 0;
				fprintf(stderr, "Daemon error: %s\n", buf);
				result = 1;
			}
		}

		for (i = 0; i < cmdnum; i++)
			free(cmdv[i]);
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
