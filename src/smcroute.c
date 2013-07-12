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
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <ev.h>

#include <signal.h>
#include <unistd.h>

#include "mclab.h"

#include "config.h"
#include "build.h"


int do_debug_logging = 0;
const char *conf_file = SMCROUTE_SYSTEM_CONF;

static struct ev_io ipc_watcher;
static struct ev_io mroute4_watcher;
#ifdef HAVE_IPV6_MULTICAST_ROUTING
static struct ev_io mroute6_watcher;
#endif

extern char *__progname;
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

static void server_ipc_cb(struct ev_loop *loop, struct ev_io *w, int revents __attribute__ ((unused)))
{
	uint8 buf[MX_CMDPKT_SZ];
	const char *str;
	struct cmd *packet;
	struct mroute mroute;

	ev_io_stop(loop, w);

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
#endif			/* HAVE_IPV6_MULTICAST_HOST */
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

	ev_io_start(loop, w);
}

/* Check for kernel IGMPMSG_NOCACHE for (*,G) hits. I.e., source-less routes. */
static void server_mroute4_cb(struct ev_loop *loop, struct ev_io *w, int revents __attribute__ ((unused)))
{
	int result;
	char tmp[128];
	struct ip *ip;
	struct igmpmsg *igmpctl;

	ev_io_stop(loop, w);

	memset(tmp, 0, sizeof(tmp));
	result = read(mroute4_socket, tmp, sizeof(tmp));

	/* packets sent up from kernel to daemon have ip->ip_p = 0 */
	ip = (struct ip *)tmp;
	igmpctl = (struct igmpmsg *)tmp;

	/* Check for IGMPMSG_NOCACHE to do (*,G) based routing. */
	if (ip->ip_p == 0 && igmpctl->im_msgtype == IGMPMSG_NOCACHE) {
		char sbuf[16], gbuf[16];
		struct iface *iface;
		mroute4_t mroute;

		mroute.group.s_addr  = igmpctl->im_dst.s_addr;
		mroute.sender.s_addr = igmpctl->im_src.s_addr;
		mroute.inbound       = igmpctl->im_vif;
		iface = iface_find_by_vif(mroute.inbound);

		/* Find any matching route for this group on that iif. */
		smclog(LOG_DEBUG, 0, "Cache miss for group %s from %s on interface %s(%d) ifindex:%d",
		       inet_ntop (AF_INET, &mroute.group, gbuf, sizeof(gbuf)),
		       inet_ntop (AF_INET, &mroute.sender, sbuf, sizeof(sbuf)),
		       iface ? iface->name : "unknown", mroute.inbound,
		       iface ? iface->ifindex : -1);
		mroute4_dyn_add(&mroute);
	} else {
		smclog(LOG_DEBUG, 0, "%d byte IGMP signaling dropped", result);
	}

	ev_io_start(loop, w);
}

/* Receive and drop ICMPv6 stuff. This is either MLD packets or upcall messages sent up from the kernel. */
static void server_mroute6_cb(struct ev_loop *loop, struct ev_io *w, int revents __attribute__ ((unused)))
{
	int result;

	ev_io_stop(loop, w);

	if (-1 != mroute6_socket) {
		char tmp[128];

		result = read(mroute6_socket, tmp, sizeof(tmp));
		smclog(LOG_DEBUG, 0, "%d byte MLD signaling dropped", result);
	}

	ev_io_start(loop, w);
}

static void unregister_routing_watchers(struct ev_loop *loop)
{
	ev_io_stop(loop, &mroute4_watcher);
	ev_io_stop(loop, &mroute6_watcher);
}

static void register_routing_watchers(struct ev_loop *loop)
{
	if (mroute4_socket < 0)
		smclog(LOG_WARNING, 0, "No IPv4 multicast routing socket.");
	else {
		ev_io_init(&mroute4_watcher, server_mroute4_cb, mroute4_socket, EV_READ);
		ev_io_start(loop, &mroute4_watcher);
	}

#ifdef HAVE_IPV6_MULTICAST_ROUTING
	if (mroute6_socket < 0)
		smclog(LOG_WARNING, 0, "No IPv6 multicast routing socket.");
	else {
		ev_io_init(&mroute6_watcher, server_mroute6_cb, mroute6_socket, EV_READ);
		ev_io_start(loop, &mroute6_watcher);
	}
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
}

/* Watch the MRouter and the IPC socket to the smcroute client */
static void server_loop_init(struct ev_loop *loop, int sd)
{
	smclog(LOG_NOTICE, 0, "Attempting to load %s", conf_file);
	read_conf_file(conf_file);

	/* Ready for input, tell clients that by creating the pidfile */
	if (pidfile(NULL))
		smclog(LOG_WARNING, errno, "Failed creating pidfile");

	if (sd < 0)
		smclog(LOG_WARNING, errno, "No IPC socket setup, client communication disabled.");
	else {
		ev_io_init(&ipc_watcher, server_ipc_cb, sd, EV_READ);
		ev_io_start(loop, &ipc_watcher);
	}

	register_routing_watchers(loop);
}

static void sigterm_cb(struct ev_loop *loop, ev_signal *w __attribute__ ((unused)), int revents __attribute__ ((unused)))
{
	ev_break(loop, EVBREAK_ALL);
}

static void sighup_cb(struct ev_loop *loop, ev_signal *w __attribute__ ((unused)), int revents __attribute__ ((unused)))
{
	smclog(LOG_NOTICE, 0, "Got SIGHUP, reloading %s ...", conf_file);

	unregister_routing_watchers(loop);
	restart();
	read_conf_file(conf_file);
	register_routing_watchers(loop);
}

static void signal_init(struct ev_loop *loop)
{
	static ev_signal sighup_watcher;
	static ev_signal sigterm_watcher;
	static ev_signal sigint_watcher;

	ev_signal_init(&sighup_watcher, sighup_cb, SIGHUP);
	ev_signal_start(loop, &sighup_watcher);

	ev_signal_init(&sigterm_watcher, sigterm_cb, SIGTERM);
	ev_signal_start(loop, &sigterm_watcher);

	ev_signal_init(&sigint_watcher, sigterm_cb, SIGINT);
	ev_signal_start(loop, &sigint_watcher);
}

/* Init everything before forking, so we can fail and return an
 * error code in the parent and the initscript will fail */
static void start_server(int background)
{
	struct ev_loop *loop;
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
	else
		smclog(LOG_NOTICE, 0, "Starting daemon in foreground.");

	if (!pid) {
		smclog(LOG_NOTICE, 0, "Entering smcroute daemon main loop.");
		atexit(clean);

		loop = ev_default_loop(0);

		signal_init(loop);
		server_loop_init(loop, sd);

		ev_run(loop, 0);
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
	const char *arg;
	unsigned int cmdnum = 0;
	struct cmd *cmdv[16];

	/* init syslog */
	openlog(__progname, LOG_PID, LOG_DAEMON);

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
			fprintf(stderr, "Unknown option: %s\n", *argv);
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
		if (geteuid() != 0) {
			smclog(LOG_ERR, 0, "Must have super-user permissions to start %s.", __progname);
			exit(1);
		}
		start_server(background);
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
				smclog(LOG_ERR, EACCES, "Need super-user permissions to connect to daemon");
				break;

			case ENOENT:
			case ECONNREFUSED:
				/* When starting daemon, give it 30 times a 1/10 second to get ready */
				if (start_daemon && --retry_count) {
					usleep(100000);
					goto retry;
				}
				smclog(LOG_ERR, code, "Daemon not running");
				break;

			default:
				smclog(LOG_ERR, code, "Failed connecting to daemon");
				break;
			}
		}

		for (i = 0; i < cmdnum; i++) {
			int slen = 0, rlen = 0;
			struct cmd *command = cmdv[i];

			smclog(LOG_DEBUG, 0, "Sending command %c len:%zu count:%d", command->cmd, command->len, command->count);
			slen = ipc_send(command, command->len);
			rlen = ipc_receive(buf, sizeof(buf));
			if (slen < 0 || rlen < 0)
				smclog(LOG_ERR, errno, "Read/Write to daemon failed");

			smclog(LOG_DEBUG, 0, "rlen: %d", rlen);

			if (rlen != 1 || *buf != '\0') {
				fprintf(stderr, "Daemon error: %s\n", buf);
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
