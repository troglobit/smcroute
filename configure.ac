#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(smcroute, 2.0.0, https://github.com/troglobit/smcroute/issues)
AM_INIT_AUTOMAKE([1.11 foreign no-dist-gzip dist-xz])
AM_SILENT_RULES()

AC_CONFIG_SRCDIR([mclab.h])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# The pidfile() code needs asprintf(), which relies on -D_GNU_SOURCE
AC_GNU_SOURCE

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h \
                  sys/ioctl.h sys/socket.h sys/types.h syslog.h unistd.h \
                  net/route.h sys/param.h ifaddrs.h], [], [],
[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
])

AC_CHECK_HEADERS([linux/mroute.h], [], [], 
[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#define _LINUX_IN_H             /* For Linux <= 2.6.25 */
#include <linux/types.h>
])

AC_CHECK_HEADERS([linux/mroute6.h], [], [], 
[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
])

AC_CHECK_HEADERS([linux/sockios.h])

AC_CHECK_HEADERS([netinet/ip_mroute.h], [], [],
[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
])
AC_CHECK_HEADERS([netinet6/ip6_mroute.h], [], [],
[
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
])

AC_MSG_CHECKING(for IPv6 multicast host support)
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
[[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]],
[[
  struct ipv6_mreq mreq;
]])],
  [AC_DEFINE(HAVE_IPV6_MULTICAST_HOST, 1, [Define to 1 if your OS supports acting as an IPv6 multicast host])
   AC_MSG_RESULT(yes)],
  [AC_MSG_RESULT(no)]) 

AC_MSG_CHECKING(for IPv6 multicast routing support)
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
[[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_LINUX_MROUTE6_H
#include <linux/mroute6.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_NETINET6_IP6_MROUTE_H
#include <netinet6/ip6_mroute.h>
#endif
]],
[[
  int dummy = MRT6_INIT;
]])],
  [AC_DEFINE(HAVE_IPV6_MULTICAST_ROUTING, 1, [Define to 1 if your OS supports IPv6 multicast routing])
   AC_MSG_RESULT(yes)],
  [AC_MSG_RESULT(no)]) 


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_UINT32_T

AC_MSG_CHECKING(for sun_len member in struct sockaddr_un)
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
[[
#include <sys/un.h>
]],
[[
  struct sockaddr_un dummy;
  dummy.sun_len = 0;
]])],
  [AC_DEFINE(HAVE_SOCKADDR_UN_SUN_LEN, 1, [Define to 1 if the struct sockaddr_un has a member sun_len on your OS])
   AC_MSG_RESULT(yes)],
  [AC_MSG_RESULT(no)])

AC_MSG_CHECKING(for vifc_threshold member in struct mif6ctl)
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
[[
#ifdef HAVE_LINUX_MROUTE6_H
#include <linux/mroute6.h>
#endif
#ifdef HAVE_NETINET6_IP6_MROUTE_H
#include <netinet6/ip6_mroute.h>
#endif
]],
[[
  struct mif6ctl dummy;
  dummy.vifc_threshold = 1;
]])],
  [AC_DEFINE(HAVE_MIF6CTL_VIFC_THRESHOLD, 1, [Define to 1 if the struct mif6ctl has a member vifc_threshold on your OS])
   AC_MSG_RESULT(yes)],
  [AC_MSG_RESULT(no)])

AC_MSG_CHECKING(for vifc_rate_limit member in struct mif6ctl)
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
[[
#ifdef HAVE_LINUX_MROUTE6_H
#include <linux/mroute6.h>
#endif
#ifdef HAVE_NETINET6_IP6_MROUTE_H
#include <netinet6/ip6_mroute.h>
#endif
]],
[[
  struct mif6ctl dummy;
  dummy.vifc_rate_limit = 1;
]])],
  [AC_DEFINE(HAVE_MIF6CTL_VIFC_RATE_LIMIT, 1, [Define to 1 if the struct mif6ctl has a member vifc_rate_limit on your OS])
   AC_MSG_RESULT(yes)],
  [AC_MSG_RESULT(no)])

# Add build number to config.h.in
AC_ARG_ENABLE([build-id],
  [AS_HELP_STRING([--enable-build-id@<:@=ID@:>@],
              [show build id in output of 'smcroute -v'])],
  [AS_IF([test "x$enableval" = "xyes" ],
    [build_id=`date +%y%m%d`],
    [build_id=$enableval])
   AC_DEFINE_UNQUOTED([BUILD], "$build_id", [Build number, abbreviated date.])])


# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([atexit dup2 memset select socket strchr strerror strrchr asprintf])

AC_OUTPUT
