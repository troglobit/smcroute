#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(smcroute, 0.94, todd.hayton@gmail.com)
AC_CONFIG_SRCDIR([mclab.h])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h syslog.h unistd.h])

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

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETPGRP
AC_CHECK_FUNCS([atexit dup2 memset select socket strchr strerror strrchr])

AC_OUTPUT
