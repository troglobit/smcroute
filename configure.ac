#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(SMCRoute, 2.3.0-rc1, https://github.com/troglobit/smcroute/issues, smcroute, http://troglobit.com/smcroute.html)
AM_INIT_AUTOMAKE([1.11 foreign no-dist-gzip dist-xz])
AM_SILENT_RULES()

AC_CONFIG_SRCDIR([src/smcrouted.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile src/Makefile smcroute.service])

# Older versions of autoconf (<2.58) do not have AC_CONFIG_MACRO_DIR()
m4_include([m4/misc.m4])
m4_include([m4/mroute.m4])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Required to check for libsystemd-dev
PKG_PROG_PKG_CONFIG

# The pidfile() code needs asprintf(), which relies on -D_GNU_SOURCE
AC_GNU_SOURCE

# Check user options
AC_ARG_ENABLE([mrdisc],
	AS_HELP_STRING([--enable-mrdisc], [enable IPv4 multicast router discovery, default: disabled]))
AC_ARG_ENABLE([ipv6],
	AS_HELP_STRING([--disable-ipv6], [disable IPv6 support, default: enabled]))
AC_ARG_WITH([client],
	AS_HELP_STRING([--without-client], [do not build smcroutectl and IPC API]))
AC_ARG_WITH([config],
	AS_HELP_STRING([--without-config], [disable /etc/smcroute.conf support]))
AC_ARG_WITH([libcap],
	AS_HELP_STRING([--without-libcap], [do not use libcap, disables -p USER:GROUP]))
AC_ARG_WITH([systemd],
     [AS_HELP_STRING([--with-systemd=DIR], [Directory for systemd service files])],,
     [with_systemd=auto])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h		\
                  sys/ioctl.h sys/prctl.h sys/socket.h sys/types.h syslog.h	\
                  unistd.h net/route.h sys/param.h sys/stat.h sys/time.h	\
		  ifaddrs.h linux/sockios.h], [], [],[
	#ifdef HAVE_SYS_SOCKET_H
	# include <sys/socket.h>
	#endif
])

# Build w/ mrdisc support?
AS_IF([test "x$enable_mrdisc" = "xyes"],
    AC_DEFINE([ENABLE_MRDISC], 1, [Enable IPv4 multicast router discovery protocol]))
AM_CONDITIONAL([USE_MRDISC], [test "x$enable_mrdisc" = "xyes"])

# Build w/o smcroutectl and IPC API?
AS_IF([test "x$with_client" != "xno"],
    AC_DEFINE([ENABLE_CLIENT], 1, [Enable smcroutectl and the daemon IPC API]))
AM_CONDITIONAL([HAVE_CLIENT], [test "x$with_client" != "xno"])

# Build w/o smcroute.conf support?
AS_IF([test "x$with_config" != "xno"],
    AC_DEFINE([ENABLE_DOTCONF], 1, [Enable /etc/smcroute.conf support]))
AM_CONDITIONAL([USE_DOTCONF], [test "x$with_config" != "xno"])

# Sanity check ...
AS_IF([test "x$with_client" = "xno" -a "x$with_config" = "xno"],
    AC_MSG_ERROR([Cannot disable both smcroutectl and /etc/smcroute.conf support.]))

# Separate check for libcap
AS_IF([test "x$with_libcap" != "xno"], [
	AC_CHECK_HEADER([sys/capability.h], [], [
		AC_MSG_NOTICE([As a safety measure, SMCRoute v2.2 and later use libcap to drop root])
		AC_MSG_NOTICE([privileges after startup.  Install libcap and missing headers from])
		AC_MSG_NOTICE([libcap-dev, or similar, to build.])
		AC_MSG_NOTICE([On CentOS/RHEL 6 this is broken, users are recommended to disable it.])
		AC_MSG_ERROR([cannot continue, try --without-libcap to disable this feature.])
	])])

# Check where to install the systemd .service file
AS_IF([test "x$with_systemd" = "xyes" -o "x$with_systemd" = "xauto"], [
     def_systemd=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
     AS_IF([test "x$def_systemd" = "x"],
         [AS_IF([test "x$with_systemd" = "xyes"],
	     [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
	     with_systemd=no], [with_systemd="$def_systemd"])]
)
AS_IF([test "x$with_systemd" != "xno"],
     [AC_SUBST([systemddir], [$with_systemd])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemd" != "xno"])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([atexit dup2 memset select socket strchr strerror strrchr asprintf utimensat clock_gettime])

# Check for sun_len in struct sockaddr_un
AC_CHECK_SUN_LEN()

# Check for IPv4 support
AC_CHECK_MROUTE()

# If IPv6 is enabled we must probe the system some more
AS_IF([test "x$enable_ipv6" != "xno"],
        AC_CHECK_MROUTE6())

# Support for dropping root privileges is enabled by default
AS_IF([test "x$with_libcap" != "xno"],
	AC_DEFINE([HAVE_LIBCAP], [], [Define to enable support for libcap.]))
AM_CONDITIONAL(USE_LIBCAP, [test "x$with_libcap" != "xno"])

# Mac OS does not (yet) support SOCK_CLOEXEC
AC_CACHE_CHECK([for SOCK_CLOEXEC support], [ac_cv_sock_cloexec],
	[AC_TRY_RUN([
#include <sys/types.h>
#include <sys/socket.h>

int main()
{
    return socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0) == -1;
}], [ac_cv_sock_cloexec=yes], [ac_cv_sock_cloexec=no], [ac_cv_sock_cloexec=no])])

AS_IF([test "$ac_cv_sock_cloexec" = "yes" ],
   AC_DEFINE([HAVE_SOCK_CLOEXEC], 1, [Define if the SOCK_CLOEXEC flag is supported]))

# Expand $sbindir early, into $SBINDIR, for systemd unit file
# NOTE: This does *not* take prefix/exec_prefix override at "make
#       install" into account, unfortunately.
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'
SBINDIR=`eval echo $sbindir`
SBINDIR=`eval echo $SBINDIR`
AC_SUBST(SBINDIR)

AC_OUTPUT
