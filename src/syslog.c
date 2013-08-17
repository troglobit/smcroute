/* System logging API
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

#include "mclab.h"

int  log_stderr = LOG_WARNING;
int  log_last_severity;
int  log_last_error;
char log_last_message[128];

/**
 * smclog - Log message to syslog and stderr
 * @severity: Standard syslog() severity levels or %LOG_INIT
 * @code:     Error code, @errno, or zero if unused
 * @fmt:      Standard printf() formatted message to log
 * 
 * Logs a standard printf() formatted message to syslog and stderr when
 * @severity is greater than the @log_stderr threshold.  When @code is
 * set it is appended to the log, along with the error message.
 *
 * When @severity is %LOG_ERR or worse this function will call exit().
 */
void smclog(int severity, int code, const char *fmt, ...)
{
	int len;
	va_list args;
	const char *err = (code <= 0) ? NULL : (const char *)strerror(code);

	/* Skip logging for severities 'DEBUG' if do_debug_logging is false */
	if (severity == LOG_DEBUG && !do_debug_logging)
		return;

	va_start(args, fmt);
	len += vsnprintf(log_last_message + len, sizeof(log_last_message) - len, fmt, args);
	if (err)
		snprintf(log_last_message + len, sizeof(log_last_message) - len, ". Error %d: %s", code, err);
	va_end(args);

	/* update our global Last... variables */
	log_last_severity = severity;
	log_last_error = code;

	/* control logging to stderr */
	if (severity < log_stderr || severity == LOG_INIT)
		fprintf(stderr, "%s\n", log_last_message);

	/* always to syslog */
	syslog((severity == LOG_INIT) ? LOG_ERR : severity, "%s", log_last_message);

	/* LOG_INIT doesn't trigger that */
	if (severity <= LOG_ERR)
		exit(255);
}

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
