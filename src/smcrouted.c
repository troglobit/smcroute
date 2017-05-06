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
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>		/* gettimeofday() */

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

char *script   = NULL;
char *prognm   = PACKAGE_NAME;

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

static void cache_flush(void *arg)
{
	(void)arg;

	smclog(LOG_NOTICE, "Cache timeout, flushing unused (*,G) routes!");
	mroute4_dyn_expire(cache_tmo);
}

static int server_loop(void)
{
	script_init(script);
	mrdisc_init(interval);

	if (cache_tmo)
		timer_add(cache_tmo, cache_flush, NULL);

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

	atexit(clean);
	signal_init();
	timer_init();
	ipc_init();

	conf_read(conf_file, do_vifs);

	/* Everything setup, notify any clients by creating the pidfile */
	if (pidfile(NULL, uid, gid))
		smclog(LOG_WARNING, "Failed create/chown pidfile: %s", strerror(errno));

	/* Drop root privileges before entering the server loop */
	cap_drop_root(uid, gid);

	return server_loop();
}


static int usage(int code)
{
	printf("Usage: %s [hnNsv] [-c SEC] "
#ifdef ENABLE_DOTCONF
	       "[-f FILE] "
#endif
	       "[-e CMD] [-l LVL] "
#ifdef ENABLE_MRDISC
	       "[-m SEC] "
#endif
	       "[-t SEC]\n"
	       "\n"
	       "  -c SEC          Flush dynamic (*,G) multicast routes every SEC seconds\n"
	       "  -e CMD          Script or command to call on startup/reload when all routes\n"
	       "                  have been installed. Or when a source-less (ANY) route has\n"
	       "                  been installed.\n"
#ifdef ENABLE_DOTCONF
	       "  -f FILE         File to use instead of default " SMCROUTE_SYSTEM_CONF "\n"
#endif
	       "  -h              This help text\n"
	       "  -l LVL          Set log level: none, err, notice*, info, debug\n"
#ifdef ENABLE_MRDISC
	       "  -m SEC          Multicast router discovery, 4-180, default: 20 sec"
#endif
	       "  -n              Run daemon in foreground, useful when run from finit\n"
#ifdef ENABLE_DOTCONF
	       "  -N              No multicast VIFs/MIFs created by default.  Use with\n"
	       "                  smcroute.conf `phyint enable` directive\n"
#endif
#ifdef HAVE_LIBCAP
	       "  -p USER[:GROUP] After initialization set UID and GID to USER and GROUP\n"
#endif
	       "  -s              Use syslog, default unless running in foreground, -n\n"
	       "  -t SEC          Startup delay, useful for delaying interface probe at boot\n"
	       "  -v              Show program version\n"
	       "\n"
	       "Bug report address: %s\n"
	       "Project homepage: %s\n", prognm, PACKAGE_BUGREPORT, PACKAGE_URL);

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
	while ((c = getopt(argc, argv, "c:de:f:hl:m:nNp:st:v")) != EOF) {
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
#ifndef ENABLE_DOTCONF
			warnx("Built without .conf file support.");
#else
			conf_file = optarg;
#endif
			break;

		case 'h':	/* help */
			return usage(0);

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

	return start_server();
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
