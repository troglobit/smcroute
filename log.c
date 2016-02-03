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

#define SYSLOG_NAMES
#include "mclab.h"

int  log_level = LOG_NOTICE;
char log_message[128];

/**
 * smclog - Log message to syslog or stderr
 * @severity: Standard syslog() severity levels
 * @fmt:      Standard printf() formatted message to log
 *
 * Logs a standard printf() formatted message to syslog and stderr when
 * @severity is greater than the @log_level threshold.  When @code is
 * set it is appended to the log, along with the error message.
 *
 * When @severity is %LOG_ERR or worse this function will call exit().
 */
void smclog(int severity, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(log_message, sizeof(log_message), fmt, args);
	va_end(args);

	if (do_syslog) {
		syslog(severity, "%s", log_message);
		return;
	}

	if (severity < log_level || severity == LOG_INIT)
		fprintf(stderr, "%s\n", log_message);
}

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
