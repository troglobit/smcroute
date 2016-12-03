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

#ifdef HAVE_LIBCAP
#include <sys/prctl.h>
#include <sys/capability.h>
#include <pwd.h>
#include <grp.h>
#endif

#include <signal.h>
#include <unistd.h>

#include "mclab.h"

#define SMCROUTE_SYSTEM_CONF "/etc/smcroute.conf"

int running    = 1;
int background = 1;
int do_vifs    = 1;
int do_daemon  = 0;
int do_syslog  = 0;

uid_t uid      = 0;
gid_t gid      = 0;

const        char *script_exec  = NULL;
static const char *conf_file    = SMCROUTE_SYSTEM_CONF;
extern       char *__progname;
static const char version_info[] =
	"SMCRoute version " PACKAGE_VERSION
#ifdef BUILD
        " build " BUILD
#endif
	;

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
		if (errno == ENOENT)
			smclog(LOG_NOTICE, "Configuration file %s does not exist", conf_file);
		else
			smclog(LOG_WARNING, "Unexpected error when accessing %s: %s", conf_file, strerror(errno));

		smclog(LOG_NOTICE, "Continuing anyway, waiting for client to connect.");
		return;
	}

	if (parse_conf_file(conf_file))
		smclog(LOG_WARNING, "Failed parsing %s: %s", conf_file, strerror(errno));
}

/* Cleans up, i.e. releases allocated resources. Called via atexit() */
static void clean(void)
{
	mroute4_disable();
	mroute6_disable();
	mcgroup4_disable();
	mcgroup6_disable();
	ipc_exit();
	iface_exit();
	smclog(LOG_NOTICE, "Exiting.");
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

/* Check for kernel IGMPMSG_NOCACHE for (*,G) hits. I.e., source-less routes. */
static void read_mroute4_socket(void)
{
	int result;
	char tmp[128];
	struct ip *ip;
	struct igmpmsg *igmpctl;

	memset(tmp, 0, sizeof(tmp));
	result = read(mroute4_socket, tmp, sizeof(tmp));
	if (result < 0) {
		smclog(LOG_WARNING, "Failed reading IGMP message from kernel: %s", strerror(errno));
		return;
	}

	/* packets sent up from kernel to daemon have ip->ip_p = 0 */
	ip = (struct ip *)tmp;
	igmpctl = (struct igmpmsg *)tmp;

	/* Check for IGMPMSG_NOCACHE to do (*,G) based routing. */
	if (ip->ip_p == 0 && igmpctl->im_msgtype == IGMPMSG_NOCACHE) {
		struct iface *iface;
		mroute4_t mroute;
		char origin[INET_ADDRSTRLEN], group[INET_ADDRSTRLEN];

		mroute.group.s_addr  = igmpctl->im_dst.s_addr;
		mroute.sender.s_addr = igmpctl->im_src.s_addr;
		mroute.inbound       = igmpctl->im_vif;

		inet_ntop(AF_INET, &mroute.group,  group,  INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &mroute.sender, origin, INET_ADDRSTRLEN);
		smclog(LOG_DEBUG, "New multicast data from %s to group %s on VIF %d", origin, group, mroute.inbound);

		iface = iface_find_by_vif(mroute.inbound);
		if (!iface) {
			/* TODO: Add support for dynamically re-enumerating VIFs at runtime! */
			smclog(LOG_WARNING, "No matching interface for VIF %d, cannot add mroute.", mroute.inbound);
			return;
		}

		/* Find any matching route for this group on that iif. */
		result = mroute4_dyn_add(&mroute);
		if (result) {
			/* This is a common error, the router receives streams it is not
			 * set up to route -- we ignore these by default, but if the user
			 * sets a more permissive log level we help out by showing what
			 * is going on. */
			if (ENOENT == errno)
				smclog(LOG_INFO, "Multicast from %s, group %s, VIF %d does not match any (*,G) rule",
				       origin, group, mroute.inbound);
			return;
		}

		if (script_exec) {
			int status;
			mroute_t mrt;

			mrt.version = 4;
			mrt.u.mroute4 = mroute;
			status = run_script(&mrt);
			if (status) {
				if (status < 0)
					smclog(LOG_WARNING, "Failed starting external script %s: %s", script_exec, strerror(errno));
				else
					smclog(LOG_WARNING, "External script %s returned error code: %d", script_exec, status);
			}
		}
	}
}

/* Receive and drop ICMPv6 stuff. This is either MLD packets or upcall messages sent up from the kernel. */
static void read_mroute6_socket(void)
{
	int result;
	char tmp[128];

	if (mroute6_socket < 0)
		return;

	result = read(mroute6_socket, tmp, sizeof(tmp));
	if (result < 0)
		smclog(LOG_INFO, "Failed clearing MLD message from kernel: %s", strerror(errno));
}

/* Receive command from the smcroute client */
static void read_ipc_command(void)
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
			smclog(LOG_WARNING, "Failed receving IPC message from client: %s", strerror(errno));
		return;
	}

	switch (packet->cmd) {
	case 'a':
	case 'r':
		if ((str = cmd_convert_to_mroute(&mroute, packet))) {
			smclog(LOG_WARNING, "%s", str);
			ipc_send(log_message, strlen(log_message) + 1);
			break;
		}

		if (mroute.version == 4) {
			if ((packet->cmd == 'a' && mroute4_add(&mroute.u.mroute4))
			    || (packet->cmd == 'r' && mroute4_del(&mroute.u.mroute4))) {
				ipc_send(log_message, strlen(log_message) + 1);
				break;
			}
		} else {
#ifndef HAVE_IPV6_MULTICAST_ROUTING
			smclog(LOG_WARNING, "IPv6 multicast routing support disabled.");
#else
			if ((packet->cmd == 'a' && mroute6_add(&mroute.u.mroute6))
			    || (packet->cmd == 'r' && mroute6_del(&mroute.u.mroute6))) {
				ipc_send(log_message, strlen(log_message) + 1);
				break;
			}
#endif /* HAVE_IPV6_MULTICAST_ROUTING */
		}

		ipc_send("", 1);
		break;

	case 'x':	/* x <InputIntf> <SourceAdr> <McGroupAdr> */
	case 'y':	/* y <InputIntf> <SourceAdr> <McGroupAdr> */
	{
		int result = -1;
		const char *ifname = (const char *)(packet + 1);
		const char *sourceadr = ifname + strlen(ifname) + 1;
		const char *groupstr = sourceadr + strlen(sourceadr) + 1;

		if (strchr(groupstr, ':') == NULL && strchr(sourceadr, ':') == NULL) {
			struct in_addr source;

			/* check source address */
			if (!*sourceadr
			    || !inet_aton(sourceadr, &source)) {
				smclog(LOG_WARNING, "Invalid IPv4 multicast source: %s", sourceadr);
				ipc_send(log_message, strlen(log_message) + 1);
				break;
			}

			struct in_addr group;

			/* check multicast address */
			if (!*groupstr
			    || !inet_aton(groupstr, &group)
			    || !IN_MULTICAST(ntohl(group.s_addr))) {
				smclog(LOG_WARNING, "Invalid IPv4 multicast group: %s", groupstr);
				ipc_send(log_message, strlen(log_message) + 1);
				break;
			}

			/* join or leave */
			if (packet->cmd == 'x')
				result = mcgroup4_join_ssm(ifname, source, group);
			else
				result = mcgroup4_leave_ssm(ifname, source, group);
		} else {
			smclog(LOG_WARNING, "IPv6 is not supported for Source Specific Multicast.");
		}

		/* failed */
		if (result) {
			ipc_send(log_message, strlen(log_message) + 1);
			break;
		}

		ipc_send("", 1);
		break;
	}

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
				smclog(LOG_WARNING, "Invalid IPv4 multicast group: %s", groupstr);
				ipc_send(log_message, strlen(log_message) + 1);
				break;
			}

			/* join or leave */
			if (packet->cmd == 'j')
				result = mcgroup4_join(ifname, group);
			else
				result = mcgroup4_leave(ifname, group);
		} else {	/* IPv6 */
#ifndef HAVE_IPV6_MULTICAST_HOST
			smclog(LOG_WARNING, "IPv6 multicast support disabled.");
#else
			struct in6_addr group;

			/* check multicast address */
			if (!*groupstr
			    || (inet_pton(AF_INET6, groupstr, &group) <= 0)
			    || !IN6_IS_ADDR_MULTICAST(&group)) {
				smclog(LOG_WARNING, "Invalid multicast group: %s", groupstr);
				ipc_send(log_message, strlen(log_message) + 1);
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
			ipc_send(log_message, strlen(log_message) + 1);
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
		smclog(LOG_NOTICE, "Got SIGHUP, reloading %s ...", conf_file);
		restart();
		read_conf_file(conf_file);

		/* Acknowledge client SIGHUP by touching the pidfile */
		pidfile(NULL);
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

static int server_loop(int sd)
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
				smclog(LOG_WARNING, "Failed call to select() in server_loop(): %s", strerror(errno));
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

	return 0;
}

#ifdef HAVE_LIBCAP
static int whoami(const char *user, const char *group)
{
	struct passwd *pw;
	struct group  *gr;

	if (!user)
		return -1;

	/* Get target UID and target GID */
	pw = getpwnam(user);
	if (!pw) {
		smclog(LOG_INIT, "User '%s' not found!", user);
		return -1;
	}

	uid = pw->pw_uid;
	gid = pw->pw_gid;
	if (group) {
		gr = getgrnam(group);
		if (!gr) {
			smclog(LOG_INIT, "Group '%s' not found!", group);
			return -1;
		}
		gid = gr->gr_gid;
	}

	return 0;
}

static int setcaps(cap_value_t cv)
{
	int result;
	cap_t caps = cap_get_proc();
	cap_value_t cap_list = cv;

	cap_clear(caps);

	cap_set_flag(caps, CAP_PERMITTED, 1, &cap_list, CAP_SET);
	cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap_list, CAP_SET);
	result = cap_set_proc(caps);

	cap_free(caps);

	return result;
}

/*
 * Drop root privileges except capability CAP_NET_ADMIN. This capability
 * enables the thread (among other networking related things) to add and
 * remove multicast routes
 */
static int drop_root(void)
{
	/* Allow this process to preserve permitted capabilities */
	if (prctl(PR_SET_KEEPCAPS, 1) == -1) {
		smclog(LOG_ERR, "Cannot preserve capabilities: %s", strerror(errno));
		return -1;
	}

	/* Set supplementary groups, GID and UID */
	if (initgroups(user, gid) == -1) {
		smclog(LOG_ERR, "Failed setting supplementary groups: %s", strerror(errno));
		return -1;
	}

	if (setgid(gid) == -1) {
		smclog(LOG_ERR, "Failed setting group ID %d: %s", gid, strerror(errno));
		return -1;
	}

	if (setuid(uid) == -1) {
		smclog(LOG_ERR, "Failed setting user ID %d: %s", uid, strerror(errno));
		return -1;
	}

	/* Clear all capabilities except CAP_NET_ADMIN */
	if (setcaps(CAP_NET_ADMIN)) {
		smclog(LOG_ERR, "Failed setting `CAP_NET_ADMIN`: %s", strerror(errno));
		return -1;
	}

	/* Try to regain root UID, should not work at this point. */
	if (setuid(0) == 0)
		return -1;

	return 0;
}
#endif /* HAVE_LIBCAP */

/* Init everything before forking, so we can fail and return an
 * error code in the parent and the initscript will fail */
static int start_server(void)
{
	int sd, api = 2, busy = 0;

	/* Hello world! */
	smclog(LOG_NOTICE, "%s", version_info);

	/* Build list of multicast-capable physical interfaces that
	 * are currently assigned an IP address. */
	iface_init();

	if (mroute4_enable()) {
		if (errno == EADDRINUSE)
			busy++;
		api--;
	}

	if (mroute6_enable()) {
		if (errno == EADDRINUSE)
			busy++;
		api--;
	}

	/* At least one API (IPv4 or IPv6) must have initialized successfully
	 * otherwise we abort the server initialization. */
	if (!api) {
		if (busy)
			smclog(LOG_INIT, "Another multicast routing application is already running.");
		else
			smclog(LOG_INIT, "Kernel does not support multicast routing.");
		exit(1);
	}

	sd = ipc_server_init();
	if (sd < 0)
		smclog(LOG_WARNING, "Failed setting up IPC socket, client communication disabled: %s", strerror(errno));

	atexit(clean);
	signal_init();
	read_conf_file(conf_file);

	/* Everything setup, notify any clients by creating the pidfile */
	if (pidfile(NULL))
		smclog(LOG_WARNING, "Failed creating pidfile: %s", strerror(errno));

#ifdef HAVE_LIBCAP
	/* Drop root privileges before entering the server loop */
	if (uid != 0) {
		if (drop_root() == -1)
			smclog(LOG_INIT, "Could not drop root privileges, continuing as root.");
		else
			smclog(LOG_INIT, "Root privileges dropped: Current UID %u, GID %u.", getuid(), getgid());
	}
#endif

	return server_loop(sd);
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
			smclog(LOG_ERR, "Need root privileges to connect to daemon: %s", strerror(errno));
			result = 1;
			goto error;

		case ENOENT:
		case ECONNREFUSED:
			if (--retry_count) {
				usleep(100000);
				continue;
			}

			smclog(LOG_WARNING, "Daemon not running: %s", strerror(errno));
			result = 1;
			goto error;

		default:
			smclog(LOG_WARNING, "Failed connecting to daemon: %s", strerror(errno));
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
			smclog(LOG_WARNING, "Communication with daemon failed: %s", strerror(errno));
			result = 1;
			break;
		}

		if (rlen != 1 || *buf != '\0') {
			buf[MX_CMDPKT_SZ] = 0;
			fprintf(stderr, "Daemon error: %s\n", buf);
			result = 1;
			break;
		}
		fprintf(stderr, "OK!\n");
	}

error:
	for (i = 0; i < cmdnum; i++)
		free(cmdv[i]);

	return result;
}

static int usage(int code)
{
	printf("\nUsage:\n"
	       "  %s [dnkhv] [-f FILE] [-e CMD] [-L LVL] [-a|-r ROUTE] [-j|-l GROUP] [-x|-y SSM GROUP]\n"
	       "\n"
	       "Daemon:\n"
	       "  -d              Start daemon\n"
	       "  -e CMD          Script or command to call on startup/reload when all routes\n"
	       "                  have been installed. Or when a source-less (ANY) route has\n"
	       "                  been installed.\n"
	       "  -f FILE         File to use instead of default " SMCROUTE_SYSTEM_CONF "\n"
	       "  -L LVL          Set log level: none, err, info, notice*, debug\n"
	       "  -n              Run daemon in foreground, useful when run from finit\n"
	       "  -N              No VIFs/MIFs created by default, use `phyint IFNAME enable`\n"
	       "  -s              Use syslog, default unless running in foreground, -n\n"
#ifdef HAVE_LIBCAP
	       "  -p USER[:GROUP] After initialization set UID and GID to USER and GROUP\n"
#endif
	       "\n"
	       "Client:\n"
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
	       "  -x ARGS  Join a multicast group (Source Specific Multicast version)\n"
	       "  -y ARGS  Leave a multicast group (Source Specific Multicast version)\n"
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
	       "Project homepage: %s\n\n", __progname, PACKAGE_BUGREPORT, PACKAGE_URL);

	return code;
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
	int i, num_opts;
	unsigned int cmdnum = 0;
	struct cmd *cmdv[16];

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

		case 'h':	/* help */
			return usage(0);

		case 'v':	/* version */
			fprintf(stderr, "%s\n", version_info);
			return 0;

		case 'd':	/* daemon */
			do_daemon = 1;
			continue;

		case 'n':	/* run daemon in foreground, i.e., do not fork */
			background = 0;
			continue;

		case 'N':
			do_vifs = 0;
			continue;

		case 's':	/* Force syslog even though in foreground */
			do_syslog = 1;
			continue;

		case 'f':
			if (num_opts != 2)
				return usage(1);
			conf_file = argv[1];
			continue;

		case 'e':
			if (num_opts != 2)
				return usage(1);
			script_exec = argv[1];
			continue;

		case 'L':
			if (num_opts != 2)
				return usage(1);
			log_level = loglvl(argv[1]);
			continue;

#ifdef HAVE_LIBCAP
		case 'p':
			if (num_opts != 2)
				return usage(1);
			if (whoami(strtok(argv[1], ":"), strtok(NULL, ":"))) {
				perror("Invalid user:group argument");
				return 1;
			}
			continue;
#endif

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

	if (do_daemon) {
		if (geteuid() != 0) {
			smclog(LOG_ERR, "Need root privileges to start %s", __progname);
			return 1;
		}

		if (script_exec && access(script_exec, X_OK)) {
			smclog(LOG_ERR, "%s is not an executable, exiting.", script_exec);
			return 1;
		}

		if (background) {
			do_syslog = 1;
			if (daemon(0, 0) < 0) {
				smclog(LOG_ERR, "Failed daemonizing: %s", strerror(errno));
				return 1;
			}
		}

		if (do_syslog) {
			openlog(__progname, LOG_PID, LOG_DAEMON);
			setlogmask(LOG_UPTO(log_level));
		}

		return start_server();
	}

	return send_commands(cmdnum, cmdv);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
