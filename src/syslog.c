/*
**  smcroute - static multicast routing control 
**  Copyright (C) 2001 Carsten Schill <carsten@cschill.de>
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
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**
**  $Id: syslog.c,v 1.2 2001/08/02 11:25:17 cschill Exp $	
**
**  This module contains the interface functions for syslog
**
*/

#include "mclab.h"

int Log2Stderr = LOG_WARNING;

int  LogLastServerity;
int  LogLastErrno;
char LogLastMsg[ 128 ];

void log( int Serverity, int Errno, const char *FmtSt, ... )
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
  const char ServVc[][ 5 ] = { "EMER", "ALER", "CRIT", "ERRO", 
			       "Warn", "Note", "Info", "Debu" };

  const char *ServPt = Serverity < 0 || Serverity >= VCMC( ServVc ) ? 
                       "!unknown serverity!" : ServVc[ Serverity ];
 
  const char *ErrSt = (Errno <= 0) ? NULL : (const char *)strerror( Errno ); 

  {
    va_list ArgPt;
    unsigned Ln;

    va_start( ArgPt, FmtSt );
    Ln  = snprintf( LogLastMsg, sizeof( LogLastMsg ), "%s: ", ServPt );
    Ln += vsnprintf( LogLastMsg + Ln, sizeof( LogLastMsg ) - Ln, FmtSt, ArgPt );
    if( ErrSt )
      snprintf( LogLastMsg + Ln, sizeof( LogLastMsg ) - Ln, "; Errno(%d): %s", Errno, ErrSt );
       
    va_end( ArgPt );
  }


  // update our global Last... variables
  LogLastServerity = Serverity;
  LogLastErrno = Errno;

  // control logging to stderr
  if( Serverity < LOG_WARNING || Serverity < Log2Stderr )
    fprintf( stderr, "%s\n", LogLastMsg );

  // always to syslog
  syslog( Serverity, "%s", LogLastMsg );

  if( Serverity <= LOG_ERR )
    exit( -1 );
}














