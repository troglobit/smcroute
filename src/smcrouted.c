/* Static multicast routing daemon
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
#include <getopt.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>		/* gettimeofday() */
#include <sys/un.h>

#include "cap.h"
#include "ipc.h"
#include "log.h"
#include "msg.h"
#include "conf.h"
#include "ifvc.h"
#include "util.h"
#include "timer.h"
#include "script.h"
#include "socket.h"
#include "mrdisc.h"
#include "mroute.h"
#include "mcgroup.h"

int running    = 1;
int background = 1;
int do_vifs    = 1;
int do_syslog  = 1;
int cache_tmo  = 60;
int interval   = MRDISC_INTERVAL_DEFAULT;
int startup_delay = 0;
int table_id   = 0;

char *script    = NULL;
char *ident     = PACKAGE;
char *prognm    = NULL;
char *pid_file  = NULL;
char *conf_file = NULL;

static uid_t uid = 0;
static gid_t gid = 0;

static const char version_info[] = PACKAGE_NAME " v" PACKAGE_VERSION;


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
	mroute4_enable(do_vifs, table_id, cache_tmo);
	mroute6_enable(do_vifs, table_id);
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
	conf_read(conf_file, do_vifs);

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

static int server_loop(void)
{
	script_init(script);
	mrdisc_init(interval);

	while (running)
		socket_poll(NULL);

	return 0;
}

/* Init everything before forking, so we can fail and return an
 * error code in the parent and the initscript will fail */
static int start_server(void)
{
	int api = 2, busy = 0;

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

	/* Hello world! */
	smclog(LOG_NOTICE, "%s", version_info);

	if (startup_delay > 0) {
		smclog(LOG_INFO, "Startup delay requested, waiting %d sec before continuing.", startup_delay);
		sleep(startup_delay);
	}

	/*
	 * Build list of multicast-capable physical interfaces
	 */
	iface_init();

	/*
	 * Timer API needs to be initilized before mroute4_enable()
	 */
	timer_init();

	if (mroute4_enable(do_vifs, table_id, cache_tmo)) {
		if (errno == EADDRINUSE)
			busy++;
		api--;
	}

	if (mroute6_enable(do_vifs, table_id)) {
		if (errno == EADDRINUSE)
			busy++;
		api--;
	}

	/* At least one API (IPv4 or IPv6) must have initialized successfully
	 * otherwise we abort the server initialization. */
	if (!api) {
		if (busy)
			smclog(LOG_ERR, "Another multicast routing application is already running.");
		else
			smclog(LOG_ERR, "Kernel does not support multicast routing.");
		exit(1);
	}

	atexit(clean);
	signal_init();
	ipc_init();

	conf_read(conf_file, do_vifs);

	/* Everything setup, notify any clients by creating the pidfile */
	if (pidfile(pid_file, uid, gid))
		smclog(LOG_WARNING, "Failed create/chown pidfile: %s", strerror(errno));

	/* Drop root privileges before entering the server loop */
	cap_drop_root(uid, gid);

	return server_loop();
}

static int compose_paths(void)
{
	/* Default .conf file path: "/etc" + '/' + "smcroute" + ".conf" */
	if (!conf_file) {
		size_t len = strlen(SYSCONFDIR) + strlen(ident) + 7;

		conf_file = malloc(len);
		if (!conf_file) {
			smclog(LOG_ERR, "Failed allocating memory, exiting: %s", strerror(errno));
			exit(1);
		}

		snprintf(conf_file, len, "%s/%s.conf", SYSCONFDIR, ident);
	}

	/* Default is to let pidfile() API construct PID file from ident */
	if (!pid_file)
		pid_file = ident;

	return 0;
}

static int usage(int code)
{
        char pidfn[80];

	compose_paths();
	if (pid_file[0] != '/')
		snprintf(pidfn, sizeof(pidfn), "%s/run/%s.pid", LOCALSTATEDIR, pid_file);
	else
		snprintf(pidfn, sizeof(pidfn), "%s", pid_file);

	printf("Usage: %s [hnNsv] [-c SEC] [-d SEC] [-e CMD] "
#ifdef ENABLE_DOTCONF
	       "[-f FILE] "
#endif
	       "[-l LVL] "
#ifdef ENABLE_MRDISC
	       "[-m SEC] "
#endif
	       "[-P FILE] "
	       "[-t ID] "
	       "\n\n"
	       "  -c SEC          Flush dynamic (*,G) multicast routes every SEC seconds,\n"
	       "                  default 60 sec.  Useful when source/interface changes\n"
	       "  -d SEC          Startup delay, useful for delaying interface probe at boot\n"
	       "  -e CMD          Script or command to call on startup/reload when all routes\n"
	       "                  have been installed, or when a (*,G) is installed\n"
#ifdef ENABLE_DOTCONF
	       "  -f FILE         Set configuration file, default uses ident NAME: %s\n"
#endif
	       "  -h              This help text\n"
	       "  -I NAME         Identity for config, PID file, and syslog, default: %s\n"
	       "  -l LVL          Set log level: none, err, notice*, info, debug\n"
#ifdef ENABLE_MRDISC
	       "  -m SEC          Multicast router discovery, 4-180, default: 20 sec\n"
#endif
	       "  -n              Run daemon in foreground, when started by systemd or finit\n"
#ifdef ENABLE_DOTCONF
	       "  -N              No multicast VIFs/MIFs created by default.  Use with\n"
	       "                  smcroute.conf `phyint enable` directive\n"
#endif
#ifdef ENABLE_LIBCAP
	       "  -p USER[:GROUP] After initialization set UID and GID to USER and GROUP\n"
#endif
	       "  -P FILE         Set daemon PID file name, with optional path.\n"
	       "                  Default uses ident NAME: %s\n"
	       "  -s              Use syslog, default unless running in foreground, -n\n"
	       "  -t ID           Set multicast routing table ID, default: 0\n"
	       "  -v              Show program version\n"
	       "\n"
	       "Bug report address: %s\n", prognm, conf_file,
#ifdef ENABLE_DOTCONF
	       ident,
#endif
	       pidfn, PACKAGE_BUGREPORT);
#ifdef PACKAGE_URL
	printf("Project homepage:   %s\n", PACKAGE_URL);
#endif

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

	prognm = progname(argv[0]);
	while ((c = getopt(argc, argv, "c:d:e:f:hI:l:m:nNp:P:st:v")) != EOF) {
		switch (c) {
		case 'c':	/* cache timeout */
			cache_tmo = atoi(optarg);
			break;

		case 'd':
			startup_delay = atoi(optarg);
			break;

		case 'e':
			script = optarg;
			break;

		case 'f':
#ifndef ENABLE_DOTCONF
			warnx("Built without .conf file support.");
#else
			conf_file = optarg;
#endif
			break;

		case 'h':	/* help */
			return usage(0);

		case 'I':
			ident = optarg;
			break;

		case 'l':
			log_level = loglvl(optarg);
			break;

		case 'm':
#ifndef ENABLE_MRDISC
			warnx("Built without mrdisc support.");
#else
			interval = atoi(optarg);
			if (interval < 4 || interval > 180)
				errx(1, "Invalid mrdisc announcement interval, 4-180.");
#endif
			break;

		case 'n':	/* run daemon in foreground, i.e., do not fork */
			background = 0;
			do_syslog--;
			break;

		case 'N':
#ifndef ENABLE_DOTCONF
			errx(1, "Built without .conf file, no way to enable individual interfaces.");
#else
			do_vifs = 0;
#endif
			break;

		case 'p':
			cap_set_user(optarg, &uid, &gid);
			break;

		case 'P':
			pid_file = optarg;
			break;

		case 's':	/* Force syslog even though in foreground */
			do_syslog++;
			break;

		case 't':
#ifndef __linux__
			errx(1, "Different multicast routing tables only available on Linux.");
#else
			table_id = atoi(optarg);
			if (table_id < 0)
				return usage(1);
#endif
			break;

		case 'v':	/* version */
			fprintf(stderr, "%s\n", version_info);
			return 0;

		default:	/* unknown option */
			return usage(1);
		}
	}

	compose_paths();

	if (!background && do_syslog < 1)
		log_opts |= LOG_PERROR;

	openlog(ident, log_opts, LOG_DAEMON);
	setlogmask(LOG_UPTO(log_level));

	return start_server();
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
