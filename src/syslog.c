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

int Log2Stderr = LOG_WARNING;

int LogLastServerity;
int LogLastErrno;
char LogLastMsg[128];

extern int do_debug_logging;

void smclog(int Serverity, int Errno, const char *FmtSt, ...)
/*
** Writes the message 'FmtSt' with the parameters '...' to syslog.
** 'Serverity' is used for the syslog entry. For an 'Errno' value 
** other then 0, the correponding error string is appended to the
** message.
**
** For a 'Serverity' more important then 'LOG_WARNING' the message is 
** also logged to 'stderr' and the program is finished with a call to 
** 'exit()'.
**
** If the 'Serverity' is more important then 'Log2Stderr' the message
** is logged to 'stderr'.
**          
*/
{
	const char ServVc[][5] = { "EMER", "ALER", "CRIT", "ERRO",
		"Warn", "Note", "Info", "Debu"
	};

	const char *ServPt;

	const char *ErrSt = (Errno <= 0) ? NULL : (const char *)strerror(Errno);

	// LOG_INIT is a gross hack to work around smcroute's bad architecture
	// During daemon init, we do not want to trigger the exit() call at the end
	// of the function to be able to return an exit code from the parent before
	// we daemonize, without the parent triggering the atexit() handlers in the
	// normal case (which would remove the socket...)
	// That gross, ugly hack or a complete rewrite, for now the hack will do.
	if (Serverity < 0 || Serverity >= (int)VCMC(ServVc)) {
		if (Serverity == LOG_INIT)
			ServPt = "INIT";
		else
			ServPt = "!unknown serverity!";
	} else
		ServPt = ServVc[Serverity];

	// Skip logging for severities 'DEBUG' if do_debug_logging is false
	if (Serverity == LOG_DEBUG && !do_debug_logging)
		return;

	{
		va_list ArgPt;
		unsigned Ln;

		va_start(ArgPt, FmtSt);
		Ln = snprintf(LogLastMsg, sizeof(LogLastMsg), "%s: ", ServPt);
		Ln +=
		    vsnprintf(LogLastMsg + Ln, sizeof(LogLastMsg) - Ln, FmtSt,
			      ArgPt);
		if (ErrSt)
			snprintf(LogLastMsg + Ln, sizeof(LogLastMsg) - Ln,
				 "; Errno(%d): %s", Errno, ErrSt);

		va_end(ArgPt);
	}

	// update our global Last... variables
	LogLastServerity = Serverity;
	LogLastErrno = Errno;

	// control logging to stderr
	if (Serverity < LOG_WARNING || Serverity < Log2Stderr
	    || Serverity == LOG_INIT)
		fprintf(stderr, "%s\n", LogLastMsg);

	// always to syslog
	syslog((Serverity == LOG_INIT) ? LOG_ERR : Serverity, "%s", LogLastMsg);

	// LOG_INIT doesn't trigger that
	if (Serverity <= LOG_ERR)
		exit(-1);
}

/**
 * Local Variables:
 *  version-control: t
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
