#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(SMCRoute, 2.1.0, https://github.com/troglobit/smcroute/issues, smcroute, http://troglobit.com/smcroute.html)
AM_INIT_AUTOMAKE([1.11 foreign no-dist-gzip dist-xz])
AM_SILENT_RULES()

AC_CONFIG_SRCDIR([mclab.h])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])

# Older versions of autoconf (<2.58) do not have AC_CONFIG_MACRO_DIR()
m4_include([m4/misc.m4])
m4_include([m4/mroute.m4])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# The pidfile() code needs asprintf(), which relies on -D_GNU_SOURCE
AC_GNU_SOURCE

# Check if user even wants IPv6 support
AC_ARG_ENABLE([ipv6],[AS_HELP_STRING([--disable-ipv6],
	[disable IPv6 support, default: enabled])
	],[
	[ac_enable_ipv6="$enableval"],
	[ac_enable_ipv6="yes"]
])

# Check if user wants to have build number encoded in binary
AC_ARG_ENABLE([build-id],[AS_HELP_STRING([--enable-build-id@<:@=ID@:>@],
	[enable build ID in 'smcroute -v', default: disabled])
	],[
	AS_IF([test "x$enableval" = "xyes" ], [build_id=`date +%y%m%d`], [build_id=$enableval])
	AC_DEFINE_UNQUOTED([BUILD], "$build_id", [Build number, abbreviated date.])
])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h		\
                  sys/ioctl.h sys/socket.h sys/types.h syslog.h unistd.h	\
                  net/route.h sys/param.h ifaddrs.h linux/sockios.h], [], [],[
	#ifdef HAVE_SYS_SOCKET_H
	# include <sys/socket.h>
	#endif
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([atexit dup2 memset select socket strchr strerror strrchr asprintf])

# Check for sun_len in struct sockaddr_un
AC_CHECK_SUN_LEN()

# Check for IPv4 support
AC_CHECK_MROUTE()

# If IPv6 is enabled we must probe the system some more
if test "x$ac_enable_ipv6" = "xyes"; then
   AC_CHECK_MROUTE6()
fi

AC_OUTPUT
