#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(smcroute, 1.98.3, troglobit@gmail.com)
AC_CONFIG_SRCDIR([src/mclab.h])
AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile])

# Checks for programs.
AC_PROG_CC

# The pidfile() code needs asprintf(), which relies on -D_GNU_SOURCE
AC_GNU_SOURCE

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h \
                  sys/ioctl.h sys/socket.h syslog.h unistd.h \
                  net/route.h sys/param.h ifaddrs.h])

AC_CHECK_HEADERS([linux/mroute.h], [], [], 
[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
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

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETPGRP
AC_CHECK_FUNCS([atexit dup2 memset select socket strchr strerror strrchr asprintf])

AC_OUTPUT
