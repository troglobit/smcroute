/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001-2005 Carsten Schill <carsten@cschill.de>
**  Copyright (C) 2006 Julien BLACHE <jb@jblache.org>
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
**  $Id: syslog.c 87 2011-08-08 17:18:21Z micha $	
**
**  This module contains the interface functions for syslog
**
*/

#include "mclab.h"

int  log_stderr = LOG_WARNING;
int  log_last_severity;
int  log_last_error;
char log_last_message[128];

/*
** Writes the message 'fmt' with the parameters '...' to syslog.
** 'severity' is used for the syslog entry. For an 'code' value 
** other then 0, the correponding error string is appended to the
** message.
**
** For a 'severity' more important then 'LOG_WARNING' the message is 
** also logged to 'stderr' and the program is finished with a call to 
** 'exit()'.
**
** If the 'severity' is more important then 'log_stderr' the message
** is logged to 'stderr'.
**          
*/
void smclog(int severity, int code, const char *fmt, ...)
{
	int arg_len;
	va_list args;
	const char severity_list[][5] = {
		"EMER", "ALER", "CRIT", "ERRO",
		"Warn", "Note", "Info", "Debu"
	};
	const char *severity_string;
	const char *error_string = (code <= 0) ? NULL : (const char *)strerror(code);

	/* LOG_INIT is a gross hack to work around smcroute's bad architecture
	 * During daemon init, we do not want to trigger the exit() call at the end
	 * of the function to be able to return an exit code from the parent before
	 * we daemonize, without the parent triggering the atexit() handlers in the
	 * normal case (which would remove the socket...)
	 * That gross, ugly hack or a complete rewrite, for now the hack will do. */
	if (severity < 0 || severity >= (int)ARRAY_ELEMENTS(severity_list)) {
		if (severity == LOG_INIT)
			severity_string = "INIT";
		else
			severity_string = "!unknown serverity!";
	} else {
		severity_string = severity_list[severity];
	}

	/* Skip logging for severities 'DEBUG' if do_debug_logging is false */
	if (severity == LOG_DEBUG && !do_debug_logging)
		return;

	va_start(args, fmt);
	arg_len  = snprintf(log_last_message, sizeof(log_last_message), "%s: ", severity_string);
	arg_len += vsnprintf(log_last_message + arg_len, sizeof(log_last_message) - arg_len, fmt, args);
	if (error_string)
		snprintf(log_last_message + arg_len, sizeof(log_last_message) - arg_len, ". Error %d: %s", code, error_string);
	va_end(args);

	/* update our global Last... variables */
	log_last_severity = severity;
	log_last_error = code;

	/* control logging to stderr */
	if (severity < LOG_WARNING || severity < log_stderr || severity == LOG_INIT)
		fprintf(stderr, "%s\n", log_last_message);

	/* always to syslog */
	syslog((severity == LOG_INIT) ? LOG_ERR : severity, "%s", log_last_message);

	/* LOG_INIT doesn't trigger that */
	if (severity <= LOG_ERR)
		exit(-1);
}

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
