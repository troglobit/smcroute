/* Static multicast routing daemon
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
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>		/* gettimeofday() */

#ifdef HAVE_LIBCAP
# ifdef HAVE_SYS_PRCTL_H
#  include <sys/prctl.h>
# endif
# include <sys/capability.h>
# include <pwd.h>
# include <grp.h>
#endif

#include "ipc.h"
#include "log.h"
#include "msg.h"
#include "conf.h"
#include "ifvc.h"
#include "util.h"
#include "timer.h"
#include "script.h"
#include "socket.h"
#include "mroute.h"
#include "mcgroup.h"

int running    = 1;
int background = 1;
int do_vifs    = 1;
int do_syslog  = 1;
int cache_tmo  = 0;
int startup_delay = 0;

uid_t uid      = 0;
gid_t gid      = 0;

char *script   = NULL;
char *prognm   = PACKAGE_NAME;

#ifdef HAVE_LIBCAP
static const char *username;
#endif

static const char version_info[] = PACKAGE_NAME " v" PACKAGE_VERSION;


/* Cleans up, i.e. releases allocated resources. Called via atexit() */
static void clean(void)
{
	mroute4_disable();
	mroute6_disable();
	mcgroup4_disable();
	mcgroup6_disable();
#ifdef ENABLE_CLIENT
	ipc_exit();
#endif
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
	mroute4_enable(do_vifs);
	mroute6_enable(do_vifs);
}

void reload(int signo)
{
#ifdef ENABLE_DOTCONF
	smclog(LOG_NOTICE, "Got %s, reloading %s ...",
	       signo ? "SIGHUP" : "client restart command", conf_file);
#else
	smclog(LOG_NOTICE, "Got %s, restarting ...",
	       signo ? "SIGHUP" : "client restart command");
#endif
	restart();
	read_conf_file(conf_file, do_vifs);

	/* Acknowledge client SIGHUP/reload by touching the pidfile */
	pidfile(NULL, uid, gid);
}

/*
 * Signal handler.  Take note of the fact that the signal arrived
 * so that the main loop can take care of it.
 */
static void handler(int signo)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		running = 0;
		break;

	case SIGHUP:
		reload(signo);
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

static void cache_flush(void *arg)
{
	(void)arg;

	smclog(LOG_NOTICE, "Cache timeout, flushing unused (*,G) routes!");
	mroute4_dyn_expire(cache_tmo);
}

static int server_loop(void)
{
	script_init(script);

	if (cache_tmo)
		timer_add(cache_tmo, cache_flush, NULL);

	while (running)
		socket_poll(NULL);

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

	/* Valid user */
	username = user;

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
static int drop_root(const char *user)
{
#ifdef HAVE_SYS_PRCTL_H
	/* Allow this process to preserve permitted capabilities */
	if (prctl(PR_SET_KEEPCAPS, 1) == -1) {
		smclog(LOG_ERR, "Cannot preserve capabilities: %s", strerror(errno));
		return -1;
	}
#endif
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
	int sd = 0, api = 2, busy = 0;

	/* Hello world! */
	smclog(LOG_NOTICE, "%s", version_info);

	if (startup_delay > 0) {
		smclog(LOG_INFO, "Startup delay requested, waiting %d sec before continuing.", startup_delay);
		sleep(startup_delay);
	}

	/* Build list of multicast-capable physical interfaces that
	 * are currently assigned an IP address. */
	iface_init();

	if (mroute4_enable(do_vifs)) {
		if (errno == EADDRINUSE)
			busy++;
		api--;
	}

	if (mroute6_enable(do_vifs)) {
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

#ifdef ENABLE_CLIENT
	sd = ipc_init();
	if (sd < 0)
		smclog(LOG_WARNING, "Failed setting up IPC socket, client communication disabled: %s", strerror(errno));
#endif

	atexit(clean);
	signal_init();
	timer_init();

	read_conf_file(conf_file, do_vifs);

	/* Everything setup, notify any clients by creating the pidfile */
	if (pidfile(NULL, uid, gid))
		smclog(LOG_WARNING, "Failed create/chown pidfile: %s", strerror(errno));

#ifdef HAVE_LIBCAP
	/* Drop root privileges before entering the server loop */
	if (username) {
		if (drop_root(username) == -1)
			smclog(LOG_INIT, "Could not drop root privileges, continuing as root.");
		else
			smclog(LOG_INIT, "Root privileges dropped: Current UID %u, GID %u.", getuid(), getgid());
	}
#endif

	return server_loop();
}


static int usage(int code)
{
	printf("Usage: %s [hnNsv] [-c SEC] "
#ifdef ENABLE_DOTCONF
	       "[-f FILE] "
#endif
	       "[-e CMD] [-L LVL] [-t SEC]\n"
	       "\n"
	       "  -c SEC          Flush dynamic (*,G) multicast routes every SEC seconds\n"
	       "  -e CMD          Script or command to call on startup/reload when all routes\n"
	       "                  have been installed. Or when a source-less (ANY) route has\n"
	       "                  been installed.\n"
#ifdef ENABLE_DOTCONF
	       "  -f FILE         File to use instead of default " SMCROUTE_SYSTEM_CONF "\n"
#endif
	       "  -h              This help text\n"
	       "  -L LVL          Set log level: none, err, info, notice*, debug\n"
	       "  -n              Run daemon in foreground, useful when run from finit\n"
	       "  -N              No VIFs/MIFs created by default, use `phyint IFNAME enable`\n"
#ifdef HAVE_LIBCAP
	       "  -p USER[:GROUP] After initialization set UID and GID to USER and GROUP\n"
#endif
	       "  -s              Use syslog, default unless running in foreground, -n\n"
	       "  -t SEC          Startup delay, useful for delaying interface probe at boot\n"
	       "  -v              Show program version\n"
	       "\n"
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
int main(int argc, char *argv[])
{
	int c;
	int log_opts = LOG_CONS | LOG_PID;
#ifdef HAVE_LIBCAP
	char *ptr;
#endif

	prognm = progname(argv[0]);
	while ((c = getopt(argc, argv, "c:de:f:hL:nNp:st:v")) != EOF) {
		switch (c) {
		case 'c':	/* cache timeout */
			cache_tmo = atoi(optarg);
			break;

		case 'd':	/* compat, ignore */
			break;

		case 'e':
			script = optarg;
			break;

		case 'f':
#ifdef ENABLE_DOTCONF
			conf_file = optarg;
#else
			warnx("Built without .conf file support.");
#endif
			break;

		case 'h':	/* help */
			return usage(0);

		case 'L':
			log_level = loglvl(optarg);
			break;

		case 'n':	/* run daemon in foreground, i.e., do not fork */
			background = 0;
			do_syslog--;
			break;

		case 'N':
			do_vifs = 0;
			break;

		case 'p':
#ifndef HAVE_LIBCAP
			warnx("Drop privs support not available.");
			break;
#else
			ptr = strdup(optarg);
			if (!ptr)
				err(1, "Failed parsing user:group argument");

			if (whoami(strtok(ptr, ":"), strtok(NULL, ":")))
				err(1, "Invalid user:group argument");

			free(ptr);
			break;
#endif

		case 's':	/* Force syslog even though in foreground */
			do_syslog++;
			break;

		case 't':
			startup_delay = atoi(optarg);
			break;

		case 'v':	/* version */
			fprintf(stderr, "%s\n", version_info);
			return 0;

		default:	/* unknown option */
			return usage(1);
		}
	}

	if (!background && do_syslog < 1)
		log_opts |= LOG_PERROR;

	openlog(prognm, log_opts, LOG_DAEMON);
	setlogmask(LOG_UPTO(log_level));

	if (geteuid() != 0) {
		smclog(LOG_ERR, "Need root privileges to start %s", prognm);
		return 1;
	}

	if (background) {
		if (daemon(0, 0) < 0) {
			smclog(LOG_ERR, "Failed daemonizing: %s", strerror(errno));
			return 1;
		}
	}

	return start_server();
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
